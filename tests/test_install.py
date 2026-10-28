# Copyright 2026 Anten Skrabec
# SPDX-License-Identifier: Apache-2.0

import importlib.util
import io
import json
import os
import pty
import shutil
import socket
import subprocess
import sys
import tempfile
import unittest
from contextlib import contextmanager, redirect_stderr, redirect_stdout
from pathlib import Path
from unittest.mock import patch

SCRIPT = Path(__file__).resolve().parents[1] / "install.py"


def load_tool(case):
    case.assertTrue(SCRIPT.is_file(), "managed installer is not implemented")
    spec = importlib.util.spec_from_file_location("rimworld_install_test", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def make_game(directory, sidecars=True):
    directory.mkdir(parents=True, exist_ok=True)
    game = directory / "RimWorld"
    # A real native ELF avoids a canned magic-header fixture passing validation.
    shutil.copyfile("/usr/bin/true", game)
    game.chmod(0o755)
    if sidecars:
        (directory / "RimWorld.dll").write_bytes(b"sidecar existence fixture")
        (directory / "RimWorld.runtimeconfig.json").write_text("{}")
    return game.resolve()


def add_library(library, install_dir="RimWorld", appid="294100"):
    apps = library / "steamapps"
    apps.mkdir(parents=True, exist_ok=True)
    (apps / "appmanifest_294100.acf").write_text(
        f'"AppState" {{ "appid" "{appid}" "installdir" "{install_dir}" }}'
    )
    return make_game(apps / "common" / install_dir)


class DiscoveryTests(unittest.TestCase):
    def setUp(self):
        self.tool = load_tool(self)
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.home = Path(self.temp.name)
        self.steam = self.home / ".local/share/Steam"
        self.steam.mkdir(parents=True)

    def test_keyvalues_preserves_nested_values_and_escaped_paths(self):
        value = self.tool.parse_vdf(
            r"// header" + "\n" + r'"LibraryFolders" { "0" { "path" "a\\b\"c" } }'
        )
        self.assertEqual(value, {"libraryfolders": {"0": {"path": 'a\\b"c'}}})

    def test_keyvalues_accepts_bare_tokens_and_bom(self):
        self.assertEqual(
            self.tool.parse_vdf("\ufeffAppState { appid 294100 }"),
            {"appstate": {"appid": "294100"}},
        )

    def test_malformed_duplicate_and_trailing_tokens_are_rejected(self):
        for text in ['"a" {', '"a" "unterminated', '"a" "1" "A" "2"', "}", '"a"']:
            with self.subTest(text=text), self.assertRaises(self.tool.InstallerError):
                self.tool.parse_vdf(text)

    def test_metadata_byte_limit_is_enforced_before_decoding(self):
        path = self.home / "oversized.vdf"
        path.write_text('"metadata" "' + "é" * 300000 + '"' + " " * 600000)
        with self.assertRaises(self.tool.InstallerError):
            self.tool.read_vdf(path)

    def test_default_library_manifest_finds_native_game(self):
        game = add_library(self.steam)
        self.assertEqual(self.tool.discover_games(self.home), [game])

    def test_custom_modern_library_and_aliases_are_deduplicated(self):
        library = self.home / "Steam Library [beta]"
        game = add_library(library)
        apps = self.steam / "steamapps"
        apps.mkdir(exist_ok=True)
        (apps / "libraryfolders.vdf").write_text(
            f'"libraryfolders" {{ "0" {{ "path" "{library}" }} '
            f'"1" {{ "path" "{library}" }} }}'
        )
        (self.home / ".steam").mkdir()
        (self.home / ".steam/steam").symlink_to(self.steam)
        self.assertEqual(self.tool.discover_games(self.home), [game])

    def test_legacy_config_library_and_xdg_root_are_supported(self):
        root = self.home / "xdg/Steam"
        (root / "config").mkdir(parents=True)
        library = self.home / "other"
        game = add_library(library)
        (root / "config/libraryfolders.vdf").write_text(
            f'"LibraryFolders" {{ "1" "{library}" "TimeNextStatsReport" "0" }}'
        )
        self.assertEqual(self.tool.discover_games(self.home, self.home / "xdg"), [game])

    def test_two_distinct_installs_are_returned_not_guessed(self):
        first = add_library(self.steam)
        other = self.home / "other"
        second = add_library(other)
        (self.steam / "steamapps/libraryfolders.vdf").write_text(
            f'"libraryfolders" {{ "1" {{ "path" "{other}" }} }}'
        )
        self.assertEqual(set(self.tool.discover_games(self.home)), {first, second})

    def test_wrong_appid_and_directory_traversal_fail_closed(self):
        add_library(self.steam, appid="123")
        with self.assertRaises(self.tool.InstallerError):
            self.tool.discover_games(self.home)
        (self.steam / "steamapps/appmanifest_294100.acf").write_text(
            '"AppState" { "appid" "294100" "installdir" "../outside" }'
        )
        with self.assertRaises(self.tool.InstallerError):
            self.tool.discover_games(self.home)

    def test_discovery_requires_apphost_sidecars(self):
        game = add_library(self.steam)
        (game.parent / "RimWorld.dll").unlink()
        with self.assertRaises(self.tool.InstallerError):
            self.tool.discover_games(self.home)

    def test_explicit_game_is_canonical_executable_native_elf(self):
        game = make_game(self.home / "direct", sidecars=False)
        alias = self.home / "RimWorld"
        alias.symlink_to(game)
        self.assertEqual(self.tool.validate_game(alias), game)
        game.write_text("#!/bin/sh\nexit 0\n")
        with self.assertRaises(self.tool.InstallerError):
            self.tool.validate_game(alias)

    def test_directory_nonexecutable_and_wrong_name_are_rejected(self):
        game = make_game(self.home / "direct")
        game.chmod(0o644)
        for target in [game, game.parent]:
            with (
                self.subTest(target=target),
                self.assertRaises(self.tool.InstallerError),
            ):
                self.tool.validate_game(target)
        renamed = game.with_name("steam")
        game.rename(renamed)
        renamed.chmod(0o755)
        with self.assertRaises(self.tool.InstallerError):
            self.tool.validate_game(renamed)

    def test_literal_regex_escapes_spaces_metacharacters_and_utf8(self):
        self.assertEqual(
            self.tool.fcontext_regex("/games/Steam Library/[beta]/RimWorld"),
            r"/games/Steam\x20Library/\x5bbeta\x5d/RimWorld",
        )
        self.assertEqual(
            self.tool.fcontext_regex("/games/café/RimWorld"),
            r"/games/caf\xc3\xa9/RimWorld",
        )


class KernelDouble:
    """Replace privileged tools only; keep journal and descriptor/xattr IO real."""

    def __init__(self, tool, root, game):
        self.tool, self.game = tool, game
        self.db = root / "kernel.json"
        self.db.write_text(json.dumps({"modules": [], "mappings": []}))
        self.failures = {}
        self.active = False
        os.setxattr(
            game, "user.rimworld_label", b"unconfined_u:object_r:data_home_t:s0"
        )

    def read(self):
        return json.loads(self.db.read_text())

    def change(self, key, value, action):
        self.trip(action, "before")
        data = self.read()
        data[key] = value
        self.db.write_text(json.dumps(data))
        self.trip(action, "after")

    def trip(self, action, when):
        error = self.failures.pop((action, when), None)
        if error:
            raise error(f"injected {action} {when}")

    def modules(self):
        return self.read()["modules"]

    def mappings(self):
        return self.read()["mappings"]

    def existing_types(self):
        return False

    def preflight(self):
        if self.active:
            raise self.tool.InstallerError("game is running")

    def running(self, game):
        return self.active

    def checksum(self, package):
        return "a" * 64

    def get_label(self, fd):
        return os.getxattr(fd, "user.rimworld_label").decode()

    def set_label(self, fd, label):
        if "rimworld_jit_exec_t" in label and not self.modules():
            raise self.tool.InstallerError("entrypoint type does not exist")
        action = "label" if "rimworld_jit_exec_t" in label else "restore"
        self.trip(action, "before")
        os.setxattr(fd, "user.rimworld_label", label.encode())
        self.trip(action, "after")

    def expected_type(self, game):
        return self.read().get(
            "effective_type",
            "rimworld_jit_exec_t" if self.mappings() else "data_home_t",
        )

    def install_module(self, package):
        self.change(
            "modules",
            [{"priority": 400, "checksum": "a" * 64, "enabled": True}],
            "module",
        )

    def remove_module(self):
        if self.mappings() or (
            self.game.exists()
            and b"rimworld_jit_exec_t" in os.getxattr(self.game, "user.rimworld_label")
        ):
            raise self.tool.InstallerError("module removed before its mapping/label")
        self.change("modules", [], "unmodule")

    def add_mapping(self, regex):
        if not self.modules():
            raise self.tool.InstallerError("mapping type does not exist")
        self.change(
            "mappings",
            [
                {
                    "regex": regex,
                    "ftype": "f",
                    "type": "rimworld_jit_exec_t",
                    "seuser": "system_u",
                    "range": "s0",
                }
            ],
            "mapping",
        )

    def delete_mapping(self, regex):
        if self.mappings()[0]["regex"] != regex:
            raise self.tool.InstallerError("wrong mapping selected")
        self.change("mappings", [], "unmapping")


class LifecycleTests(unittest.TestCase):
    def setUp(self):
        self.tool = load_tool(self)
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.game = make_game(self.root / "game")
        self.package = self.root / "module.pp"
        self.package.write_bytes(b"external compiler output fixture")
        self.kernel = KernelDouble(self.tool, self.root, self.game)
        self.tool.ROOT_UID = os.geteuid()
        self.assertTrue(
            hasattr(self.tool, "Journal"), "durable ownership store is missing"
        )
        self.store = self.tool.Journal(self.root / "state")
        self.engine = self.tool.Installer(self.store, self.kernel)

    def install(self):
        with self.store.locked(create=True):
            return self.engine.install(self.game, self.package)

    def remove(self):
        with self.store.locked():
            return self.engine.remove()

    def assert_absent(self):
        self.assertEqual(self.kernel.modules(), [])
        self.assertEqual(self.kernel.mappings(), [])
        if self.game.exists():
            self.assertEqual(
                os.getxattr(self.game, "user.rimworld_label"),
                b"unconfined_u:object_r:data_home_t:s0",
            )
        self.assertIsNone(self.store.read())

    def test_install_and_remove_restore_exact_original_context(self):
        original = "unconfined_u:object_r:data_home_t:s0-s0:c0.c1023"
        os.setxattr(self.game, "user.rimworld_label", original.encode())
        self.install()
        self.assertEqual(self.engine.status(), "installed")
        self.assertEqual(
            os.getxattr(self.game, "user.rimworld_label"),
            b"unconfined_u:object_r:rimworld_jit_exec_t:s0-s0:c0.c1023",
        )
        self.remove()
        self.assertEqual(
            os.getxattr(self.game, "user.rimworld_label"), original.encode()
        )
        self.assertIsNone(self.store.read())

    def test_effective_mapping_drift_blocks_status_reinstall_and_remove(self):
        self.install()
        data = self.kernel.read()
        data["effective_type"] = "data_home_t"
        self.kernel.db.write_text(json.dumps(data))
        journal = self.store.read()
        label = os.getxattr(self.game, "user.rimworld_label")
        for operation in (self.engine.status, self.install, self.remove):
            with self.subTest(operation=operation.__name__):
                with self.assertRaises(self.tool.InstallerError):
                    operation()
                self.assertEqual(self.kernel.read(), data)
                self.assertEqual(self.store.read(), journal)
                self.assertEqual(os.getxattr(self.game, "user.rimworld_label"), label)

    def test_revalidation_rejects_a_changed_canonical_target(self):
        other = make_game(self.root / "other")
        original = os.getxattr(self.game, "user.rimworld_label")
        os.setxattr(other, "user.rimworld_label", original)
        preflight = self.kernel.preflight

        def redirect_during_preflight():
            preflight()
            self.game.parent.rename(self.root / "original")
            self.game.parent.symlink_to(other.parent, target_is_directory=True)

        self.kernel.preflight = redirect_during_preflight
        with self.assertRaises(self.tool.InstallerError):
            self.install()
        self.assert_absent()
        self.assertEqual(os.getxattr(other, "user.rimworld_label"), original)
        self.assertEqual(
            os.getxattr(self.root / "original/RimWorld", "user.rimworld_label"),
            original,
        )

    def test_reinstall_verifies_existing_state_without_duplicate_changes(self):
        self.install()
        self.kernel.failures[("module", "before")] = AssertionError
        self.install()
        self.assertEqual(len(self.kernel.modules()), 1)
        self.assertEqual(len(self.kernel.mappings()), 1)
        self.assertEqual(self.engine.status(), "installed")

    def test_status_does_not_hide_an_unmanaged_stale_mapping(self):
        data = self.kernel.read()
        data["mappings"] = [
            {
                "regex": "/other/RimWorld",
                "ftype": "f",
                "type": "rimworld_jit_exec_t",
                "seuser": "system_u",
                "range": "s0",
            }
        ]
        self.kernel.db.write_text(json.dumps(data))
        self.assertEqual(self.engine.status(), "unmanaged")

    def test_unmanaged_module_is_never_overwritten(self):
        data = self.kernel.read()
        data["modules"] = [{"priority": 300, "checksum": "b" * 64, "enabled": True}]
        self.kernel.db.write_text(json.dumps(data))
        with self.assertRaises(self.tool.InstallerError):
            self.install()
        self.assertEqual(self.kernel.modules(), data["modules"])
        self.assertIsNone(self.store.read())

    def test_active_game_prevents_all_installation_effects(self):
        self.kernel.active = True
        with self.assertRaises(self.tool.InstallerError):
            self.install()
        self.assert_absent()

    def test_failures_before_and_after_each_install_effect_are_safely_undone(self):
        for action in ["module", "mapping", "label"]:
            for when in ["before", "after"]:
                with self.subTest(action=action, when=when):
                    self.kernel.failures[(action, when)] = self.tool.InstallerError
                    with self.assertRaises(self.tool.InstallerError):
                        self.install()
                    self.assert_absent()

    def test_interruptions_leave_durable_recoverable_ownership(self):
        for action in ["module", "mapping", "label"]:
            for when in ["before", "after"]:
                with self.subTest(action=action, when=when):
                    self.kernel.failures[(action, when)] = KeyboardInterrupt
                    with self.assertRaises(KeyboardInterrupt):
                        self.install()
                    self.assertIsNotNone(self.store.read())
                    self.engine = self.tool.Installer(self.store, self.kernel)
                    self.assertEqual(self.engine.status(), "incomplete")
                    self.remove()
                    self.assert_absent()

    def test_interrupted_removal_can_resume_after_every_effect(self):
        for action in ["unmapping", "restore", "unmodule"]:
            for when in ["before", "after"]:
                with self.subTest(action=action, when=when):
                    self.install()
                    self.kernel.failures[(action, when)] = KeyboardInterrupt
                    with self.assertRaises(KeyboardInterrupt):
                        self.remove()
                    self.assertIsNotNone(self.store.read())
                    self.engine = self.tool.Installer(self.store, self.kernel)
                    self.remove()
                    self.assert_absent()

    def test_missing_executable_can_be_cleaned_up_without_relabeling_another_file(self):
        self.install()
        self.game.unlink()
        self.remove()
        self.assert_absent()

    def test_second_writer_cannot_enter_a_held_journal_lock(self):
        with (
            self.store.locked(create=True),
            self.assertRaises(self.tool.InstallerError),
            self.store.locked(),
        ):
            self.fail("second writer acquired the lock")

    def test_unknown_mapping_and_external_label_changes_block_removal(self):
        self.install()
        original = self.kernel.read()
        changed = json.loads(json.dumps(original))
        changed["mappings"][0]["type"] = "other_exec_t"
        self.kernel.db.write_text(json.dumps(changed))
        with self.assertRaises(self.tool.InstallerError):
            self.remove()
        self.assertEqual(self.kernel.mappings()[0]["type"], "other_exec_t")
        self.kernel.db.write_text(json.dumps(original))
        os.setxattr(self.game, "user.rimworld_label", b"system_u:object_r:bin_t:s0")
        with self.assertRaises(self.tool.InstallerError):
            self.remove()
        self.assertEqual(
            os.getxattr(self.game, "user.rimworld_label"), b"system_u:object_r:bin_t:s0"
        )
        self.assertEqual(len(self.kernel.modules()), 1)

    def test_corrupt_label_recovery_data_is_a_controlled_error(self):
        self.install()
        record = self.store.read()
        record["original_label"] = None
        (self.store.directory / "state.json").write_text(json.dumps(record))
        with self.assertRaises(self.tool.InstallerError):
            self.remove()

    def test_success_exit_without_mapping_effect_does_not_report_installed(self):
        self.kernel.add_mapping = lambda regex: None
        with self.assertRaises(self.tool.InstallerError):
            self.install()
        self.assert_absent()

    def test_changed_module_checksum_is_not_overwritten_on_remove(self):
        self.install()
        data = self.kernel.read()
        data["modules"][0]["checksum"] = "b" * 64
        self.kernel.db.write_text(json.dumps(data))
        with self.assertRaises(self.tool.InstallerError):
            self.remove()
        self.assertEqual(self.kernel.modules()[0]["checksum"], "b" * 64)
        self.assertIsNotNone(self.store.read())

    def test_replaced_executable_is_not_automatically_adopted(self):
        self.install()
        replacement = self.root / "new"
        shutil.copyfile("/usr/bin/true", replacement)
        replacement.chmod(0o755)
        replacement.replace(self.game)
        with self.assertRaises(self.tool.InstallerError):
            self.remove()
        self.assertEqual(len(self.kernel.modules()), 1)

    def test_unattempted_module_cannot_become_owned_through_removal_phase(self):
        write = self.store.write

        def stop_after_preparation(record):
            write(record)
            if record["stage"] == "prepared":
                raise KeyboardInterrupt("durable prepared record, no acquisition")

        with (
            patch.object(self.store, "write", side_effect=stop_after_preparation),
            self.assertRaises(KeyboardInterrupt),
        ):
            self.install()
        self.assertEqual(self.kernel.modules(), [])

        def stop_after_removal_intent(record):
            write(record)
            if record["stage"] == "removing":
                raise KeyboardInterrupt("durable cleanup intent")

        with (
            patch.object(self.store, "write", side_effect=stop_after_removal_intent),
            self.assertRaises(KeyboardInterrupt),
        ):
            self.remove()
        external = self.kernel.read()
        external["modules"] = [{"priority": 400, "checksum": "a" * 64, "enabled": True}]
        self.kernel.db.write_text(json.dumps(external))
        with self.assertRaises(self.tool.InstallerError):
            self.remove()
        self.assertEqual(self.kernel.read(), external)
        self.assertEqual(self.store.read()["resources"]["module"], "released")

    def test_released_resources_are_never_reacquired_after_interruption(self):
        for resource in ("module", "mapping", "label"):
            with self.subTest(resource=resource):
                self.install()
                mapping = self.kernel.mappings()[0].copy()
                write = self.store.write

                def stop_at_release(record, resource=resource, write=write):
                    write(record)
                    if (
                        record["stage"] == "removing"
                        and record.get("resources", {}).get(resource) == "released"
                    ):
                        raise KeyboardInterrupt("durable resource release")

                with (
                    patch.object(self.store, "write", side_effect=stop_at_release),
                    self.assertRaises(KeyboardInterrupt),
                ):
                    self.remove()
                baseline = self.kernel.read()
                label = os.getxattr(self.game, "user.rimworld_label")
                record = self.store.read()
                external = json.loads(json.dumps(baseline))
                if resource == "module":
                    external["modules"] = [
                        {"priority": 400, "checksum": "a" * 64, "enabled": True}
                    ]
                elif resource == "mapping":
                    external["mappings"] = [mapping]
                else:
                    os.setxattr(
                        self.game,
                        "user.rimworld_label",
                        record["applied_label"].encode(),
                    )
                self.kernel.db.write_text(json.dumps(external))
                with self.assertRaises(self.tool.InstallerError):
                    self.remove()
                self.assertEqual(self.kernel.read(), external)
                self.assertEqual(self.store.read(), record)
                if resource == "label":
                    self.assertEqual(
                        os.getxattr(self.game, "user.rimworld_label"),
                        record["applied_label"].encode(),
                    )
                self.kernel.db.write_text(json.dumps(baseline))
                os.setxattr(self.game, "user.rimworld_label", label)
                self.remove()
                self.assert_absent()

    def test_legacy_journal_without_resource_provenance_is_not_adopted(self):
        self.install()
        legacy = self.store.read()
        legacy["schema"] = 1
        legacy.pop("resources", None)
        (self.store.directory / "state.json").write_text(json.dumps(legacy))
        with self.assertRaises(self.tool.InstallerError):
            self.remove()
        self.assertEqual(len(self.kernel.modules()), 1)
        self.assertTrue((self.store.directory / "state.json").exists())

    def test_owned_resource_cannot_transition_back_to_pending(self):
        self.install()
        record = self.store.read()
        with self.assertRaises(self.tool.InstallerError):
            self.engine.stage(record, "module_pending", module="pending")
        self.assertEqual(self.store.read(), record)

    def test_parent_directory_is_synced_before_mutation_even_on_creation_retry(self):
        events = []
        parent = self.store.directory.parent.stat()
        sync = os.fsync
        acquire = self.kernel.install_module

        def synchronize(fd):
            info = os.fstat(fd)
            if (info.st_dev, info.st_ino) == (parent.st_dev, parent.st_ino):
                events.append("parent")
            sync(fd)

        def acquire_module(package):
            events.append("module")
            acquire(package)

        self.kernel.install_module = acquire_module
        for existing in (False, True):
            with self.subTest(directory_already_exists=existing):
                self.assertEqual(self.store.directory.exists(), existing)
                events.clear()
                with patch.object(self.tool.os, "fsync", side_effect=synchronize):
                    self.install()
                self.assertIn("parent", events)
                self.assertLess(events.index("parent"), events.index("module"))
                self.remove()

    def test_failed_parent_sync_prevents_all_policy_mutations(self):
        parent = self.store.directory.parent.stat()
        synchronize = os.fsync

        def fail_parent(fd):
            info = os.fstat(fd)
            if (info.st_dev, info.st_ino) == (parent.st_dev, parent.st_ino):
                raise OSError("injected parent-directory durability failure")
            synchronize(fd)

        with (
            patch.object(self.tool.os, "fsync", side_effect=fail_parent),
            self.assertRaises(OSError),
        ):
            self.install()
        self.assert_absent()

    def test_command_keeps_lease_if_the_controller_is_killed(self):
        address = str(self.root / "writer.sock")
        child = (
            "import os,socket,sys; s=socket.socket(socket.AF_UNIX); "
            "s.connect(sys.argv[1]); s.sendall(b'ready'); s.recv(1); "
            "os.close(int(sys.argv[2])); s.sendall(b'released')"
        )
        worker = (
            "import importlib.util,os,sys; from pathlib import Path; "
            "s=importlib.util.spec_from_file_location('tool',sys.argv[1]); "
            "m=importlib.util.module_from_spec(s); s.loader.exec_module(m); "
            "m.ROOT_UID=os.getuid(); j=m.Journal(Path(sys.argv[2])); "
            "\nwith j.locked(create=True) as lease:\n"
            " system=m.System(); system.lock_fd=lease; "
            "system.run('/usr/bin/python3','-c',sys.argv[3],sys.argv[4],str(lease))\n"
        )
        with socket.socket(socket.AF_UNIX) as server:
            server.bind(address)
            server.listen(1)
            server.settimeout(5)
            process = subprocess.Popen(
                [
                    sys.executable,
                    "-I",
                    "-c",
                    worker,
                    str(SCRIPT),
                    str(self.store.directory),
                    child,
                    address,
                ],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.PIPE,
            )
            connection = None
            try:
                connection, _ = server.accept()
                connection.settimeout(5)
                self.assertEqual(connection.recv(5), b"ready")
                process.kill()
                process.wait(timeout=5)
                with self.assertRaises(self.tool.InstallerError), self.store.locked():
                    self.fail(
                        "recovery entered while the previous writer still held its lease"
                    )
                connection.sendall(b"x")
                self.assertEqual(connection.recv(8), b"released")
                with self.store.locked():
                    self.assertIsNone(self.store.read())
            finally:
                if connection is not None:
                    connection.close()
                if process.poll() is None:
                    process.kill()
                process.communicate(timeout=5)

    def test_symlink_state_directory_is_rejected_without_touching_target(self):
        outside = self.root / "outside"
        outside.mkdir()
        self.store.directory.symlink_to(outside)
        with self.assertRaises(self.tool.InstallerError):
            self.install()
        self.assertEqual(list(outside.iterdir()), [])

    def test_module_changed_during_label_restoration_is_not_removed(self):
        self.install()
        restore = self.kernel.set_label

        def replace_module_after_restore(fd, label):
            restore(fd, label)
            data = self.kernel.read()
            data["modules"][0]["checksum"] = "b" * 64
            self.kernel.db.write_text(json.dumps(data))

        self.kernel.set_label = replace_module_after_restore
        with self.assertRaises(self.tool.InstallerError):
            self.remove()
        self.assertEqual(self.kernel.modules()[0]["checksum"], "b" * 64)
        self.assertIsNotNone(self.store.read())

    def test_game_started_mid_install_retains_safe_recovery_state(self):
        add = self.kernel.add_mapping

        def start_after_mapping(regex):
            add(regex)
            self.kernel.active = True

        self.kernel.add_mapping = start_after_mapping
        with self.assertRaises(self.tool.InstallerError):
            self.install()
        self.assertIsNotNone(self.store.read())
        self.assertEqual(
            os.getxattr(self.game, "user.rimworld_label"),
            b"unconfined_u:object_r:data_home_t:s0",
        )
        self.kernel.active = False
        self.remove()
        self.assert_absent()

    def test_command_error_after_module_removal_is_recoverable(self):
        self.install()
        self.kernel.failures[("unmodule", "after")] = self.tool.InstallerError
        with self.assertRaises(self.tool.InstallerError):
            self.remove()
        self.assertIsNotNone(self.store.read())
        self.remove()
        self.assert_absent()

    def test_corrupt_or_public_journal_is_rejected(self):
        self.install()
        record = self.store.directory / "state.json"
        record.chmod(0o644)
        with self.assertRaises(self.tool.InstallerError):
            self.remove()
        record.chmod(0o600)
        record.write_text('{"schema": 999}')
        with self.assertRaises(self.tool.InstallerError):
            self.remove()
        self.assertEqual(len(self.kernel.modules()), 1)


class ToolOutputTests(unittest.TestCase):
    def setUp(self):
        self.tool = load_tool(self)

    def test_checksum_priority_and_disabled_module_rows_are_preserved(self):
        self.assertTrue(
            hasattr(self.tool, "parse_modules"), "module inspection is missing"
        )
        rows = self.tool.parse_modules(
            "100 unrelated pp sha256:" + "0" * 64 + "\n"
            "400 rimworld_jit pp sha256:" + "a" * 64 + "\n"
            "200 rimworld_jit cil sha256:" + "b" * 64 + " disabled\n"
        )
        self.assertEqual(
            rows,
            [
                {"priority": 400, "checksum": "a" * 64, "enabled": True},
                {"priority": 200, "checksum": "b" * 64, "enabled": False},
            ],
        )

    def test_export_directives_are_data_not_commands(self):
        self.assertTrue(
            hasattr(self.tool, "parse_mappings"), "mapping inspection is missing"
        )
        rows = self.tool.parse_mappings(
            "fcontext -D\n"
            "fcontext -a -f f -t rimworld_jit_exec_t -r 's0' '/games/Steam\\x20Library/RimWorld'\n"
            "fcontext -a -e /home /var/home\n"
        )
        self.assertEqual(
            rows[0],
            {
                "regex": r"/games/Steam\x20Library/RimWorld",
                "ftype": "f",
                "type": "rimworld_jit_exec_t",
                "seuser": "system_u",
                "range": "s0",
            },
        )
        self.assertEqual(rows[1], {"regex": "/var/home", "equiv": "/home"})


class BackendTests(unittest.TestCase):
    def setUp(self):
        self.tool = load_tool(self)

    def test_module_adapter_uses_full_priority_checksum_listing_and_clean_environment(
        self,
    ):
        output = b"400 rimworld_jit pp sha256:" + b"a" * 64 + b"\n"
        completed = subprocess.CompletedProcess([], 0, stdout=output, stderr=b"")
        with (
            patch.dict(os.environ, {"LD_PRELOAD": "/untrusted/library.so"}),
            patch.object(self.tool.subprocess, "run", return_value=completed) as run,
        ):
            rows = self.tool.System().modules()
        self.assertEqual(
            rows, [{"priority": 400, "checksum": "a" * 64, "enabled": True}]
        )
        self.assertEqual(run.call_args.args[0][1:], ["-lfull", "-m"])
        self.assertNotIn("LD_PRELOAD", run.call_args.kwargs["env"])
        self.assertFalse(run.call_args.kwargs.get("shell", False))

    def test_running_game_domain_is_detected_without_an_exe_link(self):
        with tempfile.TemporaryDirectory() as temporary:
            process = Path(temporary) / "123"
            (process / "attr").mkdir(parents=True)
            (process / "attr/current").write_text(
                "unconfined_u:unconfined_r:rimworld_jit_t:s0"
            )
            with patch.object(self.tool.Path, "iterdir", return_value=iter([process])):
                self.assertTrue(self.tool.System().running(Path("/games/RimWorld")))

    def test_missing_exe_with_unreadable_domain_is_not_assumed_safe(self):
        with tempfile.TemporaryDirectory() as temporary:
            process = Path(temporary) / "123"
            process.mkdir()
            with (
                patch.object(self.tool.Path, "iterdir", return_value=iter([process])),
                patch.object(
                    self.tool.Path,
                    "read_text",
                    side_effect=PermissionError(13, "denied"),
                ),
                self.assertRaises(self.tool.InstallerError),
            ):
                self.tool.System().running(Path("/games/RimWorld"))

    def test_kernel_thread_or_vanished_process_without_exe_is_not_a_game(self):
        with tempfile.TemporaryDirectory() as temporary:
            process = Path(temporary) / "123"
            (process / "attr").mkdir(parents=True)
            context = process / "attr/current"
            context.write_text("system_u:system_r:kernel_t:s0")
            for vanished in (False, True):
                if vanished:
                    context.unlink()
                with patch.object(
                    self.tool.Path, "iterdir", return_value=iter([process])
                ):
                    self.assertFalse(
                        self.tool.System().running(Path("/games/RimWorld"))
                    )

    def test_deleted_game_executable_still_blocks_changes(self):
        with tempfile.TemporaryDirectory() as temporary:
            process = Path(temporary) / "123"
            (process / "attr").mkdir(parents=True)
            (process / "attr/current").write_text(
                "unconfined_u:unconfined_r:unconfined_t:s0"
            )
            (process / "exe").symlink_to("/games/RimWorld (deleted)")
            with patch.object(self.tool.Path, "iterdir", return_value=iter([process])):
                self.assertTrue(self.tool.System().running(Path("/games/RimWorld")))

    def test_root_command_nonzero_is_not_treated_as_success(self):
        completed = subprocess.CompletedProcess(
            [], 1, stdout=b"", stderr=b"transaction failed"
        )
        with (
            patch.object(self.tool.subprocess, "run", return_value=completed),
            self.assertRaises(self.tool.InstallerError),
        ):
            self.tool.System().remove_module()

    def test_label_is_synchronized_before_its_release_can_be_recorded(self):
        with tempfile.TemporaryDirectory() as temporary:
            game = make_game(Path(temporary))
            fd = os.open(game, os.O_RDONLY)
            events = []
            put, synchronize = os.setxattr, os.fsync

            def set_label(target, attribute, value):
                self.assertEqual(target, fd)
                put(target, "user.test_label", value)
                events.append("label")

            def sync_label(target):
                self.assertEqual(target, fd)
                synchronize(target)
                events.append("durable")

            try:
                with (
                    patch.object(self.tool.os, "setxattr", side_effect=set_label),
                    patch.object(self.tool.os, "fsync", side_effect=sync_label),
                ):
                    self.tool.System().set_label(
                        fd, "unconfined_u:object_r:data_home_t:s0"
                    )
                self.assertEqual(events, ["label", "durable"])
            finally:
                os.close(fd)

    def test_label_adapter_preserves_context_and_targets_the_open_descriptor(self):
        with tempfile.TemporaryDirectory() as temporary:
            game = make_game(Path(temporary))
            os.setxattr(
                game, "user.test_label", b"unconfined_u:object_r:data_home_t:s0\x00"
            )
            fd = os.open(game, os.O_RDONLY)
            get, put = os.getxattr, os.setxattr

            def read(target, attribute):
                self.assertEqual(target, fd)
                self.assertEqual(attribute, "security.selinux")
                return get(target, "user.test_label")

            def write(target, attribute, value):
                self.assertEqual(target, fd)
                self.assertEqual(attribute, "security.selinux")
                put(target, "user.test_label", value)

            try:
                with (
                    patch.object(self.tool.os, "getxattr", side_effect=read),
                    patch.object(self.tool.os, "setxattr", side_effect=write),
                ):
                    system = self.tool.System()
                    self.assertEqual(
                        system.get_label(fd), "unconfined_u:object_r:data_home_t:s0"
                    )
                    system.set_label(fd, "unconfined_u:object_r:rimworld_jit_exec_t:s0")
                self.assertEqual(
                    get(fd, "user.test_label"),
                    b"unconfined_u:object_r:rimworld_jit_exec_t:s0\x00",
                )
            finally:
                os.close(fd)


class CliTests(unittest.TestCase):
    def setUp(self):
        self.tool = load_tool(self)
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.home = Path(self.temp.name)
        self.game = make_game(self.home / "direct")

    def run_cli(self, *args):
        env = dict(
            os.environ, HOME=str(self.home), XDG_DATA_HOME=str(self.home / "xdg")
        )
        return subprocess.run(
            [sys.executable, str(SCRIPT), *args],
            input="",
            text=True,
            capture_output=True,
            env=env,
            timeout=15,
            check=False,
        )

    def test_dry_run_runs_without_build_authentication_or_mutation(self):
        self.assertTrue(hasattr(self.tool, "main"), "installer CLI is missing")
        output = io.StringIO()
        with (
            patch.object(
                self.tool.subprocess,
                "run",
                side_effect=AssertionError("external command"),
            ),
            patch.object(
                self.tool.os, "setxattr", side_effect=AssertionError("label write")
            ),
            patch.object(
                self.tool.Path, "mkdir", side_effect=AssertionError("directory write")
            ),
            redirect_stdout(output),
        ):
            result = self.tool.main(["install", "--dry-run", "--game", str(self.game)])
        self.assertEqual(result, 0)
        self.assertIn(str(self.game), output.getvalue())
        self.assertIn("unverified", output.getvalue().lower())

    def test_real_cli_dry_run_and_help_have_useful_outputs(self):
        p = self.run_cli("install", "--dry-run", "--game", str(self.game))
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertIn(str(self.game), p.stdout)
        self.assertIn("dry run", p.stdout.lower())
        p = self.run_cli("--help")
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertIn("install", p.stdout)
        p = self.run_cli("plan")
        self.assertNotEqual(p.returncode, 0)

    def test_discovery_ambiguity_requires_explicit_selection(self):
        root = self.home / ".local/share/Steam"
        add_library(root)
        other = self.home / "other"
        add_library(other)
        (root / "steamapps/libraryfolders.vdf").write_text(
            f'"libraryfolders" {{ "1" {{ "path" "{other}" }} }}'
        )
        p = self.run_cli("install", "--dry-run")
        self.assertNotEqual(p.returncode, 0)
        self.assertIn("--game", p.stderr)

    def test_explicit_game_bypasses_broken_steam_metadata(self):
        root = self.home / ".local/share/Steam/steamapps"
        root.mkdir(parents=True)
        (root / "libraryfolders.vdf").write_text('"libraryfolders" {')
        p = self.run_cli("install", "--dry-run", "--game", str(self.game))
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertIn(str(self.game), p.stdout)

    def test_package_changed_after_confirmation_is_not_silently_rehashed(self):
        package = self.home / "built.pp"
        package.write_bytes(b"reviewed package")
        snapshots = self.home / "root-snapshot"
        snapshots.mkdir()

        @contextmanager
        def build():
            yield package

        def confirm(message, yes=False):
            package.write_bytes(b"different package")

        def apply(action, request):
            self.tool.snapshot_package(request, snapshots)
            return 0

        with (
            patch.object(self.tool, "build_package", build),
            patch.object(self.tool, "confirm", confirm),
            patch.object(self.tool, "run_privileged", apply),
            patch.object(self.tool.os, "geteuid", return_value=1000),
            patch.dict(os.environ, {"SUDO_UID": str(os.getuid())}),
            redirect_stdout(io.StringIO()),
            redirect_stderr(io.StringIO()),
        ):
            result = self.tool.main(["install", "--game", str(self.game), "--yes"])
        self.assertNotEqual(result, 0)
        self.assertFalse((snapshots / "rimworld_jit.pp").exists())

    def test_root_installation_is_refused_before_building(self):
        self.assertTrue(hasattr(self.tool, "main"), "installer CLI is missing")
        errors = io.StringIO()
        with (
            patch.object(self.tool.os, "geteuid", return_value=0),
            redirect_stderr(errors),
        ):
            result = self.tool.main(["install", "--game", str(self.game), "--yes"])
        self.assertNotEqual(result, 0)
        self.assertIn("normal user", errors.getvalue().lower())

    def test_eof_cancels_confirmation_and_yes_is_explicit(self):
        self.assertTrue(hasattr(self.tool, "confirm"), "confirmation is missing")

        class Terminal(io.StringIO):
            def isatty(self):
                return True

        with (
            patch.object(self.tool.sys, "stdin", Terminal("")),
            redirect_stdout(io.StringIO()),
            self.assertRaises(self.tool.InstallerError),
        ):
            self.tool.confirm("Apply?")
        with patch.object(self.tool.sys, "stdin", io.StringIO("")):
            self.tool.confirm("Apply?", yes=True)

    def test_privileged_confirmation_works_on_a_nonseekable_terminal(self):
        master, slave = pty.openpty()
        self.addCleanup(os.close, master)
        self.addCleanup(os.close, slave)
        slave_path = os.ttyname(slave)
        original_open = open

        def terminal_open(path, *args, **kwargs):
            return original_open(
                slave_path if path == "/dev/tty" else path, *args, **kwargs
            )

        os.write(master, b"yes\n")
        with patch("builtins.open", side_effect=terminal_open):
            self.tool.confirm("Remove owned policy?", terminal=True)

    def test_missing_dependencies_never_reach_privileged_application(self):
        self.assertTrue(hasattr(self.tool, "main"), "installer CLI is missing")
        with (
            patch.object(self.tool, "missing_dependencies", return_value=["make"]),
            patch.object(self.tool.os, "geteuid", return_value=1000),
            patch.object(
                self.tool, "run_privileged", side_effect=AssertionError("sudo reached")
            ),
            redirect_stderr(io.StringIO()),
            redirect_stdout(io.StringIO()),
        ):
            result = self.tool.main(["install", "--game", str(self.game), "--yes"])
        self.assertNotEqual(result, 0)

    def test_worker_refuses_unprivileged_invocation_before_request_read(self):
        p = self.run_cli("_root", "install")
        self.assertNotEqual(p.returncode, 0)
        self.assertIn("root", p.stderr.lower())

    def test_default_status_observes_directory_presence_without_authentication(self):
        directory = self.home / "state"
        outputs = []
        with (
            patch.object(self.tool, "STATE_DIR", directory),
            patch.object(self.tool, "ROOT_UID", os.geteuid()),
        ):
            for create in (False, True):
                if create:
                    directory.mkdir(mode=0o700)
                output = io.StringIO()
                with (
                    redirect_stdout(output),
                    patch.object(
                        self.tool.subprocess,
                        "run",
                        side_effect=AssertionError("authentication"),
                    ),
                ):
                    self.assertEqual(self.tool.main(["status"]), 0)
                outputs.append(output.getvalue())
        self.assertNotEqual(outputs[0], outputs[1])
        self.assertIn("unverified", outputs[0])
        self.assertIn("unverified", outputs[1])

    def test_default_status_does_not_authenticate_or_claim_absence(self):
        self.assertTrue(hasattr(self.tool, "main"), "installer CLI is missing")
        output = io.StringIO()
        with (
            patch.object(
                self.tool.subprocess,
                "run",
                side_effect=AssertionError("authentication"),
            ),
            patch.object(self.tool, "STATE_DIR", self.home / "no-state"),
            redirect_stdout(output),
        ):
            result = self.tool.main(["status"])
        self.assertEqual(result, 0)
        self.assertIn("unverified", output.getvalue().lower())


if __name__ == "__main__":
    unittest.main()
