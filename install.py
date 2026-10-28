#!/usr/bin/env python3
# Copyright 2026 Anten Skrabec
# SPDX-License-Identifier: Apache-2.0

"""Managed, exact-entrypoint SELinux installation for native RimWorld."""

import argparse
import errno
import fcntl
import hashlib
import json
import os
import re
import shlex
import shutil
import stat
import struct
import subprocess
import sys
import tempfile
import uuid
from contextlib import contextmanager, nullcontext
from pathlib import Path


class InstallerError(Exception):
    """An unsafe, unsupported, or failed operation that must not be hidden."""


def vdf_tokens(text):
    # Steam metadata is untrusted; bound memory and recursion before parsing it.
    if len(text) > 1024 * 1024:
        raise InstallerError("Steam metadata exceeds the 1 MiB limit")
    pattern = re.compile(r'\s+|//[^\n]*|"(?:\\.|[^"\\])*"|[{}]|[^\s{}"]+')
    position = 0
    text = text.lstrip("\ufeff")
    escapes = {'"': '"', "\\": "\\", "n": "\n", "r": "\r", "t": "\t"}

    def decode_escape(match):
        if match[1] not in escapes:
            raise InstallerError("Unsupported Steam metadata escape; use --game")
        return escapes[match[1]]

    while position < len(text):
        match = pattern.match(text, position)
        if not match:
            raise InstallerError("Malformed or unterminated Steam metadata string")
        raw = match.group()
        position = match.end()
        if raw.isspace() or raw.startswith("//"):
            continue
        if raw in ("{", "}"):
            yield ("brace", raw)
        elif raw.startswith('"'):
            yield ("value", re.sub(r"\\(.)", decode_escape, raw[1:-1]))
        else:
            if raw.startswith(("#", "[")):
                raise InstallerError("Unsupported KeyValues directive or conditional")
            yield ("value", raw)


def parse_vdf(text):
    tokens = iter(vdf_tokens(text))

    def read_object(depth, nested):
        if depth > 32:
            raise InstallerError("Steam metadata nesting exceeds the limit")
        result = {}
        for kind, value in tokens:
            if (kind, value) == ("brace", "}") and nested:
                return result
            if kind != "value":
                raise InstallerError("Unexpected brace in Steam metadata")
            key = value.casefold()
            if key in result:
                raise InstallerError(f"Duplicate Steam metadata key: {key!r}")
            next_token = next(tokens, None)
            if next_token == ("brace", "{"):
                result[key] = read_object(depth + 1, True)
            elif next_token and next_token[0] == "value":
                result[key] = next_token[1]
            else:
                raise InstallerError("Missing Steam metadata value")
        if nested:
            raise InstallerError("Unclosed Steam metadata object")
        return result

    return read_object(0, False)


def read_vdf(path):
    try:
        with path.open("rb") as stream:
            data = stream.read(1024 * 1024 + 1)
        if len(data) > 1024 * 1024:
            raise InstallerError("Steam metadata exceeds the 1 MiB byte limit")
        return parse_vdf(data.decode("utf-8-sig"))
    except (OSError, UnicodeError) as exc:
        raise InstallerError(
            f"Cannot read Steam metadata {str(path)!r}: {exc}"
        ) from exc


def validate_game(path):
    try:
        path = Path(path).expanduser().resolve(strict=True)
        mode = path.stat().st_mode
        if (
            path.name != "RimWorld"
            or not stat.S_ISREG(mode)
            or not os.access(path, os.X_OK)
        ):
            raise InstallerError("Select the regular executable named RimWorld")
        with path.open("rb") as stream:
            header = stream.read(64)
        valid = (
            len(header) == 64
            and header[:6] == b"\x7fELF\x02\x01"
            and struct.unpack_from("<H", header, 16)[0] in (2, 3)
            and struct.unpack_from("<H", header, 18)[0] == 62
        )
        if not valid:
            raise InstallerError(
                "RimWorld must be a native x86-64 ELF, not a script or DLL"
            )
        return path
    except OSError as exc:
        raise InstallerError(f"Cannot validate game {str(path)!r}: {exc}") from exc


def library_paths(root):
    libraries = {root}
    for relative in ("steamapps/libraryfolders.vdf", "config/libraryfolders.vdf"):
        metadata = root / relative
        if not metadata.exists():
            continue
        folders = read_vdf(metadata).get("libraryfolders")
        if not isinstance(folders, dict):
            raise InstallerError(f"Missing libraryfolders object in {str(metadata)!r}")
        for key, entry in folders.items():
            if not key.isdecimal():
                continue
            value = entry.get("path") if isinstance(entry, dict) else entry
            if not isinstance(value, str) or not Path(value).is_absolute():
                raise InstallerError("Steam library path must be an absolute string")
            libraries.add(Path(value).resolve())
    return libraries


def discover_games(home=None, xdg_data_home=None):
    home = Path(home) if home is not None else Path.home()
    roots = [home / ".local/share/Steam", home / ".steam/steam", home / ".steam/root"]
    if xdg_data_home is not None:
        roots.append(Path(xdg_data_home) / "Steam")
    libraries = set()
    for root in {p.resolve() for p in roots if p.is_dir()}:
        libraries.update(library_paths(root))
    games = set()
    for library in sorted(libraries):
        manifest = library / "steamapps/appmanifest_294100.acf"
        if not manifest.exists():
            continue
        app = read_vdf(manifest).get("appstate")
        if not isinstance(app, dict) or app.get("appid") != "294100":
            raise InstallerError(
                f"Manifest does not identify RimWorld: {str(manifest)!r}"
            )
        directory = app.get("installdir")
        if (
            not isinstance(directory, str)
            or directory in ("", ".", "..")
            or "/" in directory
            or "\\" in directory
        ):
            raise InstallerError(
                "Unsafe Steam installdir; use --game for an explicit target"
            )
        common = (library / "steamapps/common").resolve()
        candidate = common / directory / "RimWorld"
        game = validate_game(candidate)
        if not game.is_relative_to(common):
            raise InstallerError("Discovered game escapes steamapps/common; use --game")
        for sidecar in ("RimWorld.dll", "RimWorld.runtimeconfig.json"):
            if not (game.parent / sidecar).is_file():
                raise InstallerError(
                    f"Discovered apphost is missing {sidecar}; use --game"
                )
        games.add(game)
    return sorted(games)


def fcontext_regex(path):
    # Literal hex escapes survive both PCRE and file-context whitespace parsing.
    safe = b"/_-abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
    return "".join(chr(b) if b in safe else rf"\x{b:02x}" for b in os.fsencode(path))


ROOT_UID = 0
STATE_DIR = Path("/var/lib/rimworld-selinux")
STAGES = {
    "prepared",
    "module_pending",
    "module_installed",
    "mapping_pending",
    "mapping_installed",
    "label_pending",
    "installed",
    "removing",
    "unmapping_pending",
    "restore_pending",
    "unmodule_pending",
}
RESOURCE_NAMES = ("module", "mapping", "label")
RESOURCE_TRANSITIONS = {
    "unattempted": {"pending", "released"},
    "pending": {"owned", "released"},
    "owned": {"released"},
    "released": set(),
}


def parse_modules(text):
    result = []
    for line in text.splitlines():
        parts = line.split()
        if not parts:
            continue
        if len(parts) < 3 or not parts[0].isdecimal():
            raise InstallerError("Unrecognized semodule full-list output")
        if parts[1] != "rimworld_jit":
            continue
        digest = re.search(r"(?:sha256:)?\b([0-9a-fA-F]{64})\b", line)
        if not digest:
            raise InstallerError("Cannot verify installed module checksum")
        result.append(
            {
                "priority": int(parts[0]),
                "checksum": digest[1].lower(),
                "enabled": "disabled" not in parts[3:],
            }
        )
    return result


def parse_mappings(text):
    result = []
    options = {
        "-f": "ftype",
        "-t": "type",
        "-s": "seuser",
        "-r": "range",
        "-e": "equiv",
    }
    for line in text.splitlines():
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        try:
            tokens = shlex.split(line)
        except ValueError as exc:
            raise InstallerError("Malformed fcontext export") from exc
        if tokens == ["fcontext", "-D"]:
            continue
        if len(tokens) < 3 or tokens[:2] != ["fcontext", "-a"]:
            raise InstallerError("Unrecognized fcontext export directive")
        row = {"ftype": "a", "seuser": "system_u", "range": "s0"}
        cursor = 2
        while cursor < len(tokens) - 1:
            key = tokens[cursor]
            if key not in options or cursor + 1 >= len(tokens) - 1:
                raise InstallerError("Unrecognized fcontext export option")
            row[options[key]] = tokens[cursor + 1]
            cursor += 2
        row["regex"] = tokens[-1]
        if "equiv" in row:
            result.append({"regex": row["regex"], "equiv": row["equiv"]})
        elif "type" in row:
            result.append(row)
        else:
            raise InstallerError("Missing type in fcontext export")
    return result


def entrypoint_label(original):
    if not isinstance(original, str) or len(original) > 4096:
        raise InstallerError("Invalid original SELinux label")
    parts = original.split(":", 3)
    if (
        len(parts) != 4
        or any(not p for p in parts)
        or any(c.isspace() or ord(c) < 32 for c in original)
        or parts[2] == "rimworld_jit_exec_t"
    ):
        raise InstallerError("Unsafe or already-special original SELinux label")
    parts[2] = "rimworld_jit_exec_t"
    return ":".join(parts)


def validate_record(record):
    keys = {
        "schema",
        "stage",
        "game",
        "identity",
        "original_label",
        "applied_label",
        "regex",
        "checksum",
        "package_sha256",
        "resources",
    }
    try:
        if (
            not isinstance(record, dict)
            or set(record) != keys
            or type(record["schema"]) is not int
            or record["schema"] != 2
        ):
            raise ValueError("unknown schema or fields")
        if record["stage"] not in STAGES:
            raise ValueError("unknown operation stage")
        resources = record["resources"]
        if (
            not isinstance(resources, dict)
            or set(resources) != set(RESOURCE_NAMES)
            or any(state not in RESOURCE_TRANSITIONS for state in resources.values())
        ):
            raise ValueError("invalid resource acquisition/release facts")
        if record["stage"] == "installed" and any(
            state != "owned" for state in resources.values()
        ):
            raise ValueError("completed installation does not own all resources")
        game = Path(record["game"])
        if (
            not game.is_absolute()
            or game.name != "RimWorld"
            or str(game) != record["game"]
        ):
            raise ValueError("invalid game path")
        if "\x00" in str(game) or record["regex"] != fcontext_regex(game):
            raise ValueError("invalid exact-path mapping")
        identity = record["identity"]
        if (
            not isinstance(identity, list)
            or len(identity) != 2
            or any(type(n) is not int or n < 0 for n in identity)
        ):
            raise ValueError("invalid executable identity")
        if record["applied_label"] != entrypoint_label(record["original_label"]):
            raise ValueError("invalid label recovery data")
        for key in ("checksum", "package_sha256"):
            if not isinstance(record[key], str) or not re.fullmatch(
                "[0-9a-f]{64}", record[key]
            ):
                raise ValueError("invalid checksum")
    except (KeyError, TypeError, ValueError, InstallerError) as exc:
        raise InstallerError(f"Unsafe/corrupt ownership journal: {exc}") from exc
    return record


class Journal:
    def __init__(self, directory=STATE_DIR):
        self.directory = Path(directory)

    @staticmethod
    def check(info, directory=False):
        predicate = stat.S_ISDIR if directory else stat.S_ISREG
        mode = 0o700 if directory else 0o600
        if (
            not predicate(info.st_mode)
            or info.st_uid != ROOT_UID
            or stat.S_IMODE(info.st_mode) != mode
        ):
            raise InstallerError(
                "Journal path must be private, owned, and not a symlink"
            )

    def sync_directory(self, directory=None):
        directory = self.directory if directory is None else directory
        fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)

    @contextmanager
    def locked(self, create=False):
        if create:
            try:
                self.directory.mkdir(mode=0o700)
            except FileExistsError:
                pass
        self.check(self.directory.lstat(), directory=True)
        if create:
            # An earlier attempt may have died after mkdir but before its parent was synced.
            self.sync_directory(self.directory.parent)
        flags = os.O_RDWR | os.O_NOFOLLOW | (os.O_CREAT if create else 0)
        fd = os.open(self.directory / "lock", flags, 0o600)
        try:
            self.check(os.fstat(fd))
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError as exc:
                raise InstallerError("Another installer operation is active") from exc
            yield fd
        finally:
            os.close(fd)

    def read(self):
        try:
            info = self.directory.lstat()
        except FileNotFoundError:
            return None
        self.check(info, directory=True)
        try:
            fd = os.open(self.directory / "state.json", os.O_RDONLY | os.O_NOFOLLOW)
        except FileNotFoundError:
            return None
        try:
            self.check(os.fstat(fd))
            with os.fdopen(fd, "rb", closefd=False) as stream:
                data = stream.read(65537)
            if len(data) > 65536:
                raise InstallerError("Oversized ownership journal")
            return validate_record(json.loads(data))
        except (ValueError, UnicodeError) as exc:
            raise InstallerError("Corrupt ownership journal") from exc
        finally:
            os.close(fd)

    def write(self, record):
        validate_record(record)
        self.check(self.directory.lstat(), directory=True)
        path = self.directory / ("state-" + uuid.uuid4().hex + ".tmp")
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        try:
            with os.fdopen(fd, "w", closefd=False) as stream:
                json.dump(record, stream, sort_keys=True)
                stream.flush()
                os.fsync(fd)
            os.replace(path, self.directory / "state.json")
            self.sync_directory()
        finally:
            os.close(fd)
            if path.exists():
                path.unlink()

    def clear(self):
        self.read()
        (self.directory / "state.json").unlink()
        self.sync_directory()


def owned_mapping(record):
    return {
        "regex": record["regex"],
        "ftype": "f",
        "type": "rimworld_jit_exec_t",
        "seuser": "system_u",
        "range": "s0",
    }


@contextmanager
def game_descriptor(record, allow_missing=False):
    path = Path(record["game"])
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    except FileNotFoundError:
        if not allow_missing:
            raise InstallerError("Recorded game executable is missing") from None
        yield None
        return
    except OSError as exc:
        raise InstallerError(
            f"Cannot open recorded executable without following links: {exc}"
        ) from exc
    try:
        identity = os.fstat(fd)
        if (
            not stat.S_ISREG(identity.st_mode)
            or [identity.st_dev, identity.st_ino] != record["identity"]
        ):
            raise InstallerError(
                "Game executable was replaced; refusing automatic adoption"
            )
        if path.resolve() != path:
            raise InstallerError("Game path now resolves through a different target")
        yield fd
        visible = path.lstat()
        if [visible.st_dev, visible.st_ino] != record["identity"]:
            raise InstallerError("Game executable changed during the operation")
    finally:
        os.close(fd)


class Installer:
    def __init__(self, journal, system):
        self.journal, self.system = journal, system

    def stopped(self, game):
        if self.system.running(game):
            raise InstallerError("RimWorld is running; exit it normally before changes")

    def snapshot(self, record, fd, removing=False):
        modules = self.system.modules()
        expected = {"priority": 400, "checksum": record["checksum"], "enabled": True}
        if modules and modules != [expected]:
            raise InstallerError(
                "Module ownership/checksum drift; no overwrite or removal"
            )
        mappings = self.system.mappings()
        matching = [
            r
            for r in mappings
            if r.get("regex") == record["regex"] and r.get("ftype") == "f"
        ]
        if matching and matching != [owned_mapping(record)]:
            raise InstallerError("Exact-path mapping drift; no overwrite or removal")
        foreign = [
            r
            for r in mappings
            if r.get("type") == "rimworld_jit_exec_t" and r not in matching
        ]
        if foreign:
            raise InstallerError(
                "Another mapping depends on this module; refusing removal"
            )
        label = self.system.get_label(fd) if fd is not None else None
        if label is not None and label not in (
            record["original_label"],
            record["applied_label"],
        ):
            raise InstallerError("Executable label drift; refusing to overwrite it")
        for resource, present in (
            ("module", bool(modules)),
            ("mapping", bool(matching)),
            ("label", label == record["applied_label"]),
        ):
            if present and record["resources"][resource] in ("unattempted", "released"):
                raise InstallerError(
                    f"Unmanaged {resource} appeared without an acquisition right; refusing adoption"
                )
        if not modules and (matching or label == record["applied_label"]):
            raise InstallerError("Module disappeared while its mapping/label remains")
        if record["stage"] == "installed":
            if (
                not modules
                or not matching
                or (fd is not None and label != record["applied_label"])
            ):
                raise InstallerError("Completed installation has drifted")
            if fd is None and not removing:
                raise InstallerError("Installed executable is missing")
            if (
                fd is not None
                and self.system.expected_type(record["game"]) != "rimworld_jit_exec_t"
            ):
                raise InstallerError("Effective executable mapping has drifted")
        return bool(modules), bool(matching), label

    def stage(self, record, stage, **resources):
        for name, state in resources.items():
            previous = record["resources"].get(name)
            if previous not in RESOURCE_TRANSITIONS or (
                state != previous and state not in RESOURCE_TRANSITIONS[previous]
            ):
                raise InstallerError(
                    f"Invalid resource transition for {name}: {previous} -> {state}"
                )
        # Phase changes cannot reacquire something never attempted or already released.
        record["resources"].update(resources)
        record["stage"] = stage
        self.journal.write(record)

    def status(self):
        record = self.journal.read()
        if record is None:
            unmanaged = (
                self.system.modules()
                or self.system.existing_types()
                or any(
                    row.get("type") == "rimworld_jit_exec_t"
                    for row in self.system.mappings()
                )
            )
            return "unmanaged" if unmanaged else "absent"
        with game_descriptor(record, allow_missing=True) as fd:
            self.snapshot(record, fd)
        return "installed" if record["stage"] == "installed" else "incomplete"

    def install(self, game, package):
        self.system.preflight()
        self.stopped(game)
        previous = self.journal.read()
        checksum = self.system.checksum(package)
        if previous is not None:
            if previous["game"] != str(game) or previous["checksum"] != checksum:
                raise InstallerError(
                    "Owned installation differs; remove it explicitly before changing it"
                )
            if self.status() != "installed":
                raise InstallerError(
                    "Incomplete installation; run remove to recover first"
                )
            return "already installed (verified)"
        if self.system.modules() or self.system.existing_types():
            raise InstallerError(
                "Unmanaged existing policy; automatic adoption is forbidden"
            )
        confirmed = str(game)
        game = validate_game(game)
        if str(game) != confirmed:
            raise InstallerError(
                "Confirmed canonical game path changed; refusing to retarget"
            )
        info = game.stat()
        record = {
            "schema": 2,
            "stage": "prepared",
            "resources": {name: "unattempted" for name in RESOURCE_NAMES},
            "game": str(game),
            "identity": [info.st_dev, info.st_ino],
            "regex": fcontext_regex(game),
            "checksum": checksum,
            "package_sha256": hashlib.sha256(package.read_bytes()).hexdigest(),
        }
        with game_descriptor(record) as fd:
            record["original_label"] = self.system.get_label(fd)
            record["applied_label"] = entrypoint_label(record["original_label"])
            mappings = self.system.mappings()
            if any(
                r.get("type") == "rimworld_jit_exec_t"
                or (r.get("regex") == record["regex"] and r.get("ftype") in ("a", "f"))
                for r in mappings
            ):
                raise InstallerError(
                    "Pre-existing mapping conflicts with this installation"
                )
            self.journal.write(record)
            try:
                self.apply(record, package, fd)
            except (InstallerError, OSError) as error:
                try:
                    self.remove()
                except (InstallerError, OSError) as cleanup:
                    raise InstallerError(
                        f"{error}; recovery retained: {cleanup}. Use status --sudo."
                    ) from error
                raise InstallerError(
                    f"{error}; verified owned changes were rolled back"
                ) from error
        return "installed (verified)"

    def apply(self, record, package, fd):
        self.snapshot(record, fd)
        self.stage(record, "module_pending", module="pending")
        self.system.install_module(package)
        if not self.snapshot(record, fd)[0]:
            raise InstallerError(
                "Module command returned without installing the intended module"
            )
        self.stage(record, "module_installed", module="owned")
        self.stopped(record["game"])
        self.snapshot(record, fd)
        self.stage(record, "mapping_pending", mapping="pending")
        self.system.add_mapping(record["regex"])
        if (
            not self.snapshot(record, fd)[1]
            or self.system.expected_type(record["game"]) != "rimworld_jit_exec_t"
        ):
            raise InstallerError(
                "Exact-path mapping is ineffective; check SELinux path equivalences"
            )
        self.stage(record, "mapping_installed", mapping="owned")
        self.stopped(record["game"])
        self.snapshot(record, fd)
        self.stage(record, "label_pending", label="pending")
        self.system.set_label(fd, record["applied_label"])
        if self.system.get_label(fd) != record["applied_label"]:
            raise InstallerError("Executable label did not change as intended")
        self.stage(record, "installed", label="owned")
        self.snapshot(record, fd)

    def remove(self):
        record = self.journal.read()
        if record is None:
            raise InstallerError(
                "No owned installation journal; refusing unmanaged removal"
            )
        self.stopped(record["game"])
        with game_descriptor(record, allow_missing=True) as fd:
            module, mapping, label = self.snapshot(record, fd, removing=True)
            absent = {
                "module": not module,
                "mapping": not mapping,
                "label": fd is None or label == record["original_label"],
            }
            # Commit observed absence before another phase can obscure its provenance.
            self.stage(
                record,
                "removing",
                **{name: "released" for name, missing in absent.items() if missing},
            )
            if mapping:
                self.stage(record, "unmapping_pending")
                self.system.delete_mapping(record["regex"])
                if self.snapshot(record, fd, removing=True)[1]:
                    raise InstallerError("Owned mapping still exists after deletion")
                self.stage(record, "removing", mapping="released")
            if fd is not None and label == record["applied_label"]:
                self.snapshot(record, fd, removing=True)
                self.stage(record, "restore_pending")
                self.system.set_label(fd, record["original_label"])
                if self.system.get_label(fd) != record["original_label"]:
                    raise InstallerError("Original executable label was not restored")
                self.stage(record, "removing", label="released")
            if module:
                self.stopped(record["game"])
                self.snapshot(record, fd, removing=True)
                self.stage(record, "unmodule_pending")
                self.system.remove_module()
                if self.system.modules():
                    raise InstallerError("Module still exists after removal")
                self.stage(record, "removing", module="released")
            remaining_module, remaining_mapping, restored = self.snapshot(
                record, fd, removing=True
            )
            if (
                remaining_module
                or remaining_mapping
                or (fd is not None and restored != record["original_label"])
            ):
                raise InstallerError(
                    "Cleanup is not verified; retaining the ownership journal"
                )
        self.journal.clear()
        return "removed (verified)"


SAFE_PATH = "/usr/sbin:/usr/bin:/sbin:/bin"
DEPENDENCIES = (
    "make",
    "checkmodule",
    "semodule_package",
    "semodule_unpackage",
    "semodule",
    "semanage",
    "matchpathcon",
    "seinfo",
    "getenforce",
    "getsebool",
    "sestatus",
    "sudo",
)
PACKAGE_COMMAND = (
    "sudo dnf install make selinux-policy-devel checkpolicy policycoreutils "
    "policycoreutils-python-utils setools-console python3"
)
HLL_COMPILER = "/usr/libexec/selinux/hll/pp"


class System:
    lock_fd = None

    def run(self, name, *args, binary=False, cwd=None):
        executable = shutil.which(name, path=SAFE_PATH)
        if executable is None:
            raise InstallerError(
                f"Missing {name!r}. Install prerequisites: {PACKAGE_COMMAND}"
            )
        try:
            result = subprocess.run(
                [executable, *map(str, args)],
                capture_output=True,
                cwd=cwd,
                env={"PATH": SAFE_PATH, "LC_ALL": "C", "LANG": "C"},
                # A policy writer keeps the lease if this controller dies. Do not force-kill
                # its leader on a timeout while transaction helpers might still be running.
                pass_fds=() if self.lock_fd is None else (self.lock_fd,),
                timeout=180 if self.lock_fd is None else None,
                check=False,
            )
        except subprocess.TimeoutExpired as exc:
            raise InstallerError(
                f"{name} timed out; inspect actual state before retrying"
            ) from exc
        if result.returncode:
            error = result.stderr.decode("utf-8", "backslashreplace")[:2000]
            raise InstallerError(f"{name} failed ({result.returncode}): {error!r}")
        if result.stderr:
            print(
                result.stderr.decode("utf-8", "backslashreplace"),
                file=sys.stderr,
                end="",
            )
        return (
            result.stdout
            if binary
            else result.stdout.decode("utf-8", "surrogateescape")
        )

    def modules(self):
        return parse_modules(self.run("semodule", "-lfull", "-m"))

    def mappings(self):
        return parse_mappings(self.run("semanage", "fcontext", "-E"))

    def existing_types(self):
        for name in ("rimworld_jit_t", "rimworld_jit_exec_t"):
            if re.search(r"\b" + name + r"\b", self.run("seinfo", "-t", name)):
                return True
        return False

    def checksum(self, package):
        return hashlib.sha256(self.run(HLL_COMPILER, package, binary=True)).hexdigest()

    def preflight(self):
        release = Path("/etc/os-release").read_text()
        if not re.search(r'^ID=["\']?fedora["\']?$', release, re.MULTILINE):
            raise InstallerError("Installer supports Fedora targeted policy only")
        if self.run("getenforce").strip() != "Enforcing":
            raise InstallerError(
                "SELinux must be enforcing; this tool will not change its mode"
            )
        if not re.search(r"Loaded policy name:\s+targeted\b", self.run("sestatus")):
            raise InstallerError("The loaded SELinux policy must be targeted")
        if self.run("getsebool", "selinuxuser_execheap").strip().split()[-1] != "off":
            raise InstallerError(
                "Global selinuxuser_execheap must already be off; no automatic change"
            )
        capability = Path("/sys/fs/selinux/policy_capabilities/nnp_nosuid_transition")
        if capability.read_text().strip() != "1":
            raise InstallerError(
                "Required nnp_nosuid_transition policy capability is unavailable"
            )

    def running(self, game):
        for process in Path("/proc").iterdir():
            if not process.name.isdecimal():
                continue
            try:
                # The main thread can exit before its group; a missing exe link is not absence.
                context = (process / "attr/current").read_text().strip("\x00\n")
                if context.split(":")[2:3] == ["rimworld_jit_t"]:
                    return True
                executable = os.readlink(process / "exe").removesuffix(" (deleted)")
            except OSError as exc:
                if exc.errno in (errno.ENOENT, errno.ESRCH):
                    continue
                raise InstallerError(
                    f"Cannot verify process {process.name} is unrelated: {exc}"
                ) from exc
            if Path(executable).name == "RimWorld" or executable == str(game):
                return True
        return False

    def get_label(self, fd):
        return os.getxattr(fd, "security.selinux").decode("ascii").rstrip("\x00")

    def set_label(self, fd, label):
        # The open descriptor pins the selected inode despite pathname replacement.
        os.setxattr(fd, "security.selinux", label.encode("ascii") + b"\x00")
        # Do not retire recovery evidence before the inode metadata is synchronized.
        os.fsync(fd)

    def expected_type(self, game):
        context = self.run("matchpathcon", "-n", "--", game).strip().split(":", 3)
        if len(context) != 4:
            raise InstallerError("Cannot verify the persistent executable mapping")
        return context[2]

    def install_module(self, package):
        self.run("semodule", "-X", "400", "-i", package)

    def remove_module(self):
        self.run("semodule", "-X", "400", "-r", "rimworld_jit")

    def add_mapping(self, regex):
        self.run(
            "semanage",
            "fcontext",
            "-a",
            "-f",
            "f",
            "-t",
            "rimworld_jit_exec_t",
            "--",
            regex,
        )

    def delete_mapping(self, regex):
        self.run("semanage", "fcontext", "-d", "-f", "f", "--", regex)


def missing_dependencies():
    missing = [
        name for name in DEPENDENCIES if shutil.which(name, path=SAFE_PATH) is None
    ]
    for path in ("/usr/share/selinux/devel/Makefile", HLL_COMPILER, "/usr/bin/python3"):
        if not Path(path).is_file():
            missing.append(path)
    return missing


def inspect_package(system, package, directory):
    module = directory / "inspected.mod"
    contexts = directory / "inspected.fc"
    system.run("semodule_unpackage", package, module, contexts)
    rows = [
        line
        for line in contexts.read_text().splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    ]
    if rows:
        raise InstallerError("Refusing a package with embedded file-context mappings")


@contextmanager
def build_package():
    if os.geteuid() == 0:
        raise InstallerError(
            "Run install as your normal user; compilation must not run as root"
        )
    missing = missing_dependencies()
    if missing:
        raise InstallerError(
            f"Missing prerequisites: {', '.join(missing)}. Run: {PACKAGE_COMMAND}"
        )
    source = Path(__file__).resolve().with_name("rimworld_jit.te")
    with tempfile.TemporaryDirectory(prefix="rimworld-policy-build-") as temporary:
        directory = Path(temporary)
        # Only the policy source enters the build; checkout-local contexts/Makefiles cannot leak in.
        shutil.copyfile(source, directory / "rimworld_jit.te")
        system = System()
        system.run(
            "make",
            "-f",
            "/usr/share/selinux/devel/Makefile",
            "rimworld_jit.pp",
            cwd=directory,
        )
        package = directory / "rimworld_jit.pp"
        inspect_package(system, package, directory)
        yield package


def select_game(explicit):
    if explicit:
        return validate_game(explicit)
    games = discover_games(xdg_data_home=os.environ.get("XDG_DATA_HOME"))
    if not games:
        raise InstallerError(
            "No native RimWorld 1.7 installation found; use --game PATH"
        )
    if len(games) == 1:
        return games[0]
    for number, game in enumerate(games, 1):
        print(f"{number}: {str(game)!r}")
    if not sys.stdin.isatty():
        raise InstallerError(
            "Multiple installations found; use --game PATH in noninteractive mode"
        )
    try:
        choice = input("Select installation number (blank cancels): ").strip()
        if not choice.isdecimal() or not 1 <= int(choice) <= len(games):
            raise ValueError
        return games[int(choice) - 1]
    except (EOFError, ValueError) as exc:
        raise InstallerError("No installation selected; nothing applied") from exc


def confirm(message, yes=False, terminal=False):
    if yes:
        return
    try:
        with (
            open("/dev/tty", "r", encoding="utf-8")
            if terminal
            else nullcontext(sys.stdin)
        ) as stream:
            if not stream.isatty():
                raise InstallerError(
                    "Confirmation requires a terminal or explicit --yes"
                )
            prompt = message + " [y/N]: "
            if terminal:
                # TTYs are nonseekable; separate streams avoid BufferedRandom's r+ requirement.
                with open("/dev/tty", "w", encoding="utf-8") as output:
                    output.write(prompt)
                    output.flush()
            else:
                print(prompt, end="", flush=True)
            answer = stream.readline()
            if answer.strip().casefold() not in ("y", "yes"):
                raise InstallerError("Cancelled; no requested changes applied")
    except (EOFError, OSError) as exc:
        raise InstallerError(
            "Confirmation unavailable; no requested changes applied"
        ) from exc


def print_install_plan(game, dry_run=False, digest=None):
    print(f"Game: {str(game)!r}")
    print(f"Exact regular-file mapping: {fcontext_regex(game)!r}")
    print("Module: rimworld_jit, priority 400; game domain: rimworld_jit_t")
    print(f"Private recovery journal: {str(STATE_DIR / 'state.json')!r}")
    print(
        "Preserve original label user/role/range; grant executable heap only to the game domain."
    )
    print(
        "Do not change the global boolean, enforcing mode, Steam options, or tiered JIT."
    )
    print(
        "Privileged ownership, active-game and host-policy checks: unverified until privileged preflight."
    )
    if digest is not None:
        print("Built package SHA256:", digest)
    if dry_run:
        print(
            "Dry run: no build, sudo authentication, state, policy, or label changes."
        )
    else:
        print(
            "On failure, undo only verified owned changes; retain recovery state if ownership is uncertain."
        )


def unprivileged_status():
    try:
        info = STATE_DIR.lstat()
    except FileNotFoundError:
        print(f"Installer ownership directory not found: {str(STATE_DIR)!r}.")
    else:
        Journal.check(info, directory=True)
        print(f"Private installer directory present: {str(STATE_DIR)!r}.")
        try:
            record = Journal(STATE_DIR).read()
        except PermissionError:
            print(
                "Journal contents are private; ownership cannot be inspected without privilege."
            )
        else:
            if record is None:
                print("No ownership record is visible in that directory.")
            else:
                print(
                    f"Recorded stage: {record['stage']}; executable: {record['game']!r}."
                )
    print(
        "Live module/mapping/label status: unverified. Use status --sudo for read-only verification."
    )
    print(
        "Missing or unreadable local state alone does not prove the policy is absent."
    )
    return 0


def run_privileged(action, request):
    sudo = shutil.which("sudo", path=SAFE_PATH)
    if sudo is None:
        raise InstallerError("sudo is missing; run prerequisites as documented")
    command = [
        sudo,
        "--",
        "/usr/bin/python3",
        "-I",
        str(Path(__file__).resolve()),
        "_root",
        action,
    ]
    return subprocess.run(
        command, input=json.dumps(request), text=True, check=False
    ).returncode


def snapshot_package(request, directory):
    source = Path(request["package"])
    if not source.is_absolute() or not re.fullmatch("[0-9a-f]{64}", request["sha256"]):
        raise InstallerError("Invalid build snapshot request")
    fd = os.open(source, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        info = os.fstat(fd)
        caller = int(os.environ.get("SUDO_UID", os.getuid()))
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_uid != caller
            or info.st_size > 4 * 1024 * 1024
        ):
            raise InstallerError(
                "Build package must be a bounded regular file owned by the invoking user"
            )
        with os.fdopen(fd, "rb", closefd=False) as stream:
            data = stream.read(4 * 1024 * 1024 + 1)
    finally:
        os.close(fd)
    if hashlib.sha256(data).hexdigest() != request["sha256"]:
        raise InstallerError("Build package changed after confirmation")
    target = directory / "rimworld_jit.pp"
    with target.open("xb") as stream:
        stream.write(data)
        stream.flush()
        os.fsync(stream.fileno())
    return target


def privileged_main(action, request):
    if os.geteuid() != 0:
        raise InstallerError("The internal privileged worker requires root")
    fields = {
        "install": {"game", "package", "sha256"},
        "remove": {"yes"},
        "status": set(),
    }
    if (
        action not in fields
        or not isinstance(request, dict)
        or set(request) != fields[action]
    ):
        raise InstallerError("Invalid privileged operation request")
    os.umask(0o077)
    store, system = Journal(STATE_DIR), System()
    engine = Installer(store, system)
    state_exists = STATE_DIR.exists()
    if action == "remove" and not state_exists:
        raise InstallerError(
            "No installer ownership record; refusing unmanaged removal"
        )
    locking = (
        store.locked(create=action == "install")
        if action != "status" or state_exists
        else nullcontext()
    )
    with locking as lease:
        system.lock_fd = lease
        if action == "status":
            result = engine.status()
            print(result)
            return 0 if result in ("installed", "absent") else 1
        if action == "remove":
            if type(request["yes"]) is not bool:
                raise InstallerError("Invalid confirmation flag")
            record = store.read()
            if record is None:
                raise InstallerError("No owned journal; refusing unmanaged removal")
            with game_descriptor(record, allow_missing=True) as fd:
                engine.snapshot(record, fd, removing=True)
            print(
                f"Remove owned module and mapping; restore original label on {record['game']!r}",
                flush=True,
            )
            confirm("Remove this owned installation?", request["yes"], terminal=True)
            print(engine.remove())
        else:
            game = validate_game(request["game"])
            if str(game) != request["game"]:
                raise InstallerError("Selected canonical game path changed")
            with tempfile.TemporaryDirectory(
                prefix="package-", dir=STATE_DIR
            ) as temporary:
                directory = Path(temporary)
                package = snapshot_package(request, directory)
                inspect_package(system, package, directory)
                print(engine.install(game, package))
    return 0


def parser():
    result = argparse.ArgumentParser(description=__doc__)
    commands = result.add_subparsers(dest="command", required=True)
    install = commands.add_parser(
        "install", help="discover, build and install the scoped policy"
    )
    install.add_argument(
        "--game", metavar="PATH", help="explicit native RimWorld executable"
    )
    install.add_argument(
        "--dry-run", action="store_true", help="preview without build, sudo or changes"
    )
    install.add_argument(
        "--yes",
        action="store_true",
        help="explicitly accept the displayed application plan",
    )
    status = commands.add_parser("status", help="inspect ownership and state")
    status.add_argument(
        "--sudo",
        action="store_true",
        help="authorize privileged read-only verification",
    )
    remove = commands.add_parser(
        "remove", help="remove or recover only installer-owned effects"
    )
    remove.add_argument(
        "--yes", action="store_true", help="accept the displayed owned removal plan"
    )
    return result


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    try:
        if len(argv) == 2 and argv[0] == "_root":
            if os.geteuid() != 0:
                raise InstallerError("Internal worker requires root")
            data = sys.stdin.read(65537)
            if len(data) > 65536:
                raise InstallerError("Oversized privileged request")
            return privileged_main(argv[1], json.loads(data))
        args = parser().parse_args(argv)
        if args.command == "install":
            game = select_game(args.game)
            if args.dry_run:
                print_install_plan(game, dry_run=True)
                return 0
            if os.geteuid() == 0:
                raise InstallerError(
                    "Run install as your normal user; do not sudo the build"
                )
            with build_package() as package:
                digest = hashlib.sha256(package.read_bytes()).hexdigest()
                print_install_plan(game, digest=digest)
                confirm(
                    "Apply this installation after privileged safety checks?", args.yes
                )
                request = {"game": str(game), "package": str(package), "sha256": digest}
                return run_privileged("install", request)
        if args.command == "remove":
            return run_privileged("remove", {"yes": args.yes})
        if args.sudo:
            return run_privileged("status", {})
        return unprivileged_status()
    except (InstallerError, OSError, ValueError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print(
            "Interrupted. If application started, use status --sudo then remove to inspect/recover owned changes.",
            file=sys.stderr,
        )
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
