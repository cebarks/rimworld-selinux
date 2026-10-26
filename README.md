# rimworld-selinux

A narrowly scoped SELinux executable-heap exception for modded RimWorld 1.7 on Fedora's targeted policy, preserving **default tiered JIT compilation**.

This is a policy workaround, **not an upstream Harmony/runtime fix and not a hardened game sandbox**. Review the [security model](#security-model) before installing. No privileged installer or prebuilt policy package is provided.

## Problem / symptoms

Launching modded RimWorld can generate repeated SELinux `execheap` denials naming the `.NET Tiered Com` thread. This is a process memory-protection denial, not an ordinary game-file access denial.

Do not install this policy to silence unrelated `execmem`, `execmod`, or file-access alerts. Ordinary JIT compilation does not inherently require making the process's brk heap executable.

## Cause and evidence

A live trace identified a Harmony/MonoMod detour-reapplication callback attempting `mprotect` with read/write/execute protection on 13 bytes in the process heap. The request was denied in the desktop's `unconfined_t` domain. Managed JIT symbols resolved the path through `LinuxSystem.ProtectRWX`, `CreateSimpleDetour`, and the method-compiled callback.

The exact managed method and reason for its heap patch target remain unidentified. There is no clean, unmodded-game reproduction. This policy permits the observed operation; it does not establish that every patch address is correct or resolve unrelated mod errors.

Disabling tiered compilation suppressed the observed alerts, but changes compilation/optimization behavior. This project instead retains tiering and grants the permission to a dedicated game domain.

## Fixes applied / policy behavior

The source is `rimworld_jit.te`, built with
`make -f /usr/share/selinux/devel/Makefile rimworld_jit.pp` and installed with
`sudo semodule -i rimworld_jit.pp`. The operator registers only the canonical
`GAME` path using `sudo semanage fcontext -a -f f -t rimworld_jit_exec_t` and
runs `sudo restorecon -v` on that exact file, as shown in the installation
section. That changes the executable type to `rimworld_jit_exec_t`; no game
contents, runtime configuration, or directory-tree labels are edited.

The module defines:

- `rimworld_jit_t`: the game's process domain.
- `rimworld_jit_exec_t`: an entrypoint label, applied to **one exact executable path** selected by the operator.
- An automatic transition from `unconfined_t` when that entrypoint executes, retaining the `unconfined_r` role.
- `allow rimworld_jit_t self:process execheap;`.
- Source/target-specific `nnp_transition` and `nosuid_transition` permissions, required because Steam Linux Runtime 4 sets `no_new_privs` and bind-mounts the game `nosuid`.

Steam and runtime setup remain in their original domain. The policy does not enable `selinuxuser_execheap` globally, disable enforcing, disable `no_new_privs`, remove `nosuid`, or alter Steam launch options.

Unlike a machine-specific `.fc` file, the public package embeds **no home-directory or library-path mapping**. The manual steps below register a persistent mapping for your selected executable.

## Security model

`unconfined_domain(rimworld_jit_t)` retains broadly unconfined desktop access. The purpose is to scope the additional executable-heap permission, **not** to restrict the game's filesystem, network, or other desktop access.

- The exception covers code in the game domain, including mods and children that remain there.
- A user-writable game executable is not a cryptographic identity or a strong boundary against arbitrary code already running as that user. Such code may be able to replace or execute the labeled entrypoint.
- Executable heap increases the attack surface of that process. Install only if you accept this tradeoff for trusted game/mod code.
- The NNP/nosuid rules explicitly permit this particular SELinux transition under those restrictions; the flags themselves remain enabled.
- Do not label Steam, a shell, the runtime entry script, an entire library, or the game's directory tree with the entrypoint type.

A thread-name-filtered `audit2allow` rule for `unconfined_t self:process execheap` would still affect the whole desktop domain. It is not an equivalent game-specific solution.

## Tested environment and limits

The policy logic was validated with:

- Fedora 44 targeted policy `44.11`, x86-64.
- RimWorld `1.7.4985 rev1269` and bundled `.NET 10.0.13-waylithclr.dev`.
- Steam Linux Runtime 4, GameMode, the Steam overlay, and the existing `-force-vulkan` argument.

A normal Steam launch entered `rimworld_jit_t` while Steam stayed in `unconfined_t`. A tiered compiler worker was observed, with no tiering-disable environment override. GameMode was active; its library and the overlay library were mapped; `NoNewPrivs` remained `1`.

Seven startup samples and a later journal check found **zero new game/domain AVCs through approximately nine minutes after launch**, versus repeated early AVCs in the original run. A separate audit-transport query confirmed journal readability. A short compiler-thread trace had no `mprotect` permission failures, although it did not capture the exact original 13-byte operation. The live process had executable heap pages.

This is a bounded startup validation, **not a full gameplay/save-load pass**, a guarantee for other mod sets, or proof that all mod initialization errors are fixed. The public package is built offline; its policy body matches the live-tested policy, but its portable manual labeling procedure is a separate documented deployment path.

## Prerequisites and build

These instructions target Fedora's targeted policy and an unconfined desktop login. Other distributions, confined user roles, Flatpak Steam, and other container layouts are not validated.

Run the guide as your regular desktop user, using `sudo` only where shown. Read each section and **stop if a command fails**; do not paste the entire guide into a root shell.

```sh
sudo dnf install make selinux-policy-devel checkpolicy policycoreutils \
  policycoreutils-python-utils setools-console python3

git clone https://github.com/cebarks/rimworld-selinux.git
cd rimworld-selinux
make -f /usr/share/selinux/devel/Makefile rimworld_jit.pp
```

The build uses the distribution's existing SELinux Makefile. Generated `.pp`, `.mod`, `.if`, `.fc`, and `tmp/` artifacts are not source files to commit. Building does not install the module or relabel anything.

## Install

### 1. Close RimWorld and inspect the existing state

Exit the game normally before changing its entrypoint/domain policy. Confirm the alert is the described `execheap` denial, your desktop is `unconfined_t`, and the system is enforcing:

```sh
id -Z
getenforce
getsebool selinuxuser_execheap
sudo semodule -lfull | awk '$2 == "rimworld_jit" { print }'
```

If `rimworld_jit` already exists, stop and review that installation before replacing it. Do not overwrite another module or mapping blindly. If the global heap boolean is already on, this guide does not turn it off automatically; review why it was enabled separately. The validated state is **Enforcing** with `selinuxuser_execheap --> off`.

### 2. Select exactly the native game executable

The default Steam path is shown below. Change it for a custom library location. Select the RimWorld 1.7 native `RimWorld` executable, **not a launcher, directory, DLL, or script**:

```sh
GAME=$(realpath -e -- "$HOME/.local/share/Steam/steamapps/common/RimWorld/RimWorld")
test -f "${GAME:?}" && test -x "$GAME"
printf '%s\n' "$GAME"
stat --printf='%C %n\n' -- "$GAME"
```

Record that original label for rollback. Confirm the displayed canonical path is the intended executable. This guide restores the policy's default label on removal, not arbitrary prior `chcon` customizations.

Generate a literal file-context regex. Unsafe bytes are hex-escaped because regex metacharacters must remain literal and whitespace separates fields in SELinux context files. This handles spaces and special characters without broadening the match:

```sh
GAME_REGEX=$(python3 - "${GAME:?}" <<'PY'
import os
import sys

safe = b"/_-abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
print("".join(chr(b) if b in safe else rf"\x{b:02x}"
              for b in os.fsencode(sys.argv[1])))
PY
)
printf '%s\n' "$GAME_REGEX"
```

Keep `GAME` and `GAME_REGEX` for verification and removal. In a later shell, regenerate them from the **same executable path**, not a moved installation's new path.

### 3. Install the module and exact-path mapping

From the checked-out repository directory:

```sh
sudo semodule -i rimworld_jit.pp
sudo semanage fcontext -a -f f -t rimworld_jit_exec_t -- "${GAME_REGEX:?}"
sudo restorecon -v -- "${GAME:?}"
matchpathcon -V -- "$GAME"
```

`-f f` restricts the mapping to a regular file. No recursive relabel is needed. The expected executable type is `rimworld_jit_exec_t`; its SELinux user/range may differ by system.

If mapping creation fails, **stop before relabeling** and inspect existing mappings. Do not substitute `-m`, delete unrelated entries, or generate broad allow rules just to make installation succeed. The mapping only sets an entrypoint; the module supplies the process-domain transition.

## Verify a normal Steam launch

Use your normal Steam launch path. Keep existing GameMode/renderer options; do not add `DOTNET_TieredCompilation=0` or `COMPlus_TieredCompilation=0` for this workaround. For example, the tested existing launch options were:

```text
gamemoderun %command% -force-vulkan
```

That is a description of the tested setup, not a requirement to change your renderer.

```sh
ps -C RimWorld,steam -o label,pid,comm,args
getenforce
getsebool selinuxuser_execheap
sesearch -A -s rimworld_jit_t -t rimworld_jit_t -c process -p execheap
sesearch -A -s unconfined_t -t unconfined_t -c process -p execheap
sesearch -A -s unconfined_t -t rimworld_jit_t -c process2
```

Expected results:

- RimWorld runs in `rimworld_jit_t`; Steam remains in `unconfined_t`.
- The game domain has an unconditional heap allow.
- The ordinary desktop's heap allow remains boolean-conditional and the global boolean stays off. A `sesearch` conditional-rule suffix such as `:True` is not proof of the running kernel's boolean value; check it with `getsebool`.
- The specific source/target pair has both NNP/nosuid transition permissions.
- No tiering-disable override was added. Tiered workers can retire when idle; their absence in one later snapshot does not prove tiering is off.

Inspect **fresh** denials since the launch, replacing the timestamp with your launch time:

```sh
journalctl --since '10 minutes ago' --no-pager -o cat -g 'avc:.*denied'
```

Correlate records with the actual game PID or `rimworld_jit_t`, not old desktop notifications. `journalctl` exit 1 means no matching entries; permission/read errors are not a clean result. Check audit logging/readability separately before treating silence as success. On the test machine, `/var/log/audit/audit.log` was stale while the system journal's audit transport remained readable, so an empty `ausearch` result alone was misleading.

If using a diagnostic launcher, redirect verbose game stdout/stderr to a file. Some agent/process supervisors terminate tasks when captured output exceeds their cap; that must not be mistaken for a game crash.

## Updates, moves, and troubleshooting

Steam updates can replace the executable's inode and lose the entrypoint label. For the **same registered path**, after exiting the game:

```sh
sudo restorecon -v -- "${GAME:?}"
matchpathcon -V -- "$GAME"
```

Do not relabel the whole game tree. If the executable moves, remove the old mapping and register an exact mapping for the new canonical path. Do not leave stale mappings or add `(/.*)?` to cover a library.

If startup fails or new denials appear, inspect the actual domain and denied operation. Do not disable enforcing, enable a desktop-wide heap boolean, remove Steam's NNP/nosuid restrictions, or automatically run `audit2allow`. A missing transition and a game-domain memory denial are different failures.

## Remove / rollback

Exit RimWorld normally first. Use the same `GAME` and `GAME_REGEX` that were registered; regenerate them as above if necessary. If the game was moved or deleted, use the original registered regex for deletion rather than silently switching to a new path.

Remove the exact local mapping, restore the executable's normal policy label **while the module still exists**, and only then remove the module:

```sh
sudo semanage fcontext -d -f f -- "${GAME_REGEX:?}"
sudo restorecon -v -- "${GAME:?}"
sudo semodule -r rimworld_jit
matchpathcon -V -- "$GAME"
```

Stop if mapping deletion or relabeling fails. Never use `semanage fcontext -D`, remove unrelated modules, or remove a domain still used by a running game. If you had a deliberate non-default label before installation, restore and verify it before removing the module instead of assuming the default label is equivalent.

No global boolean, Steam launch option, or runtime configuration was changed by these instructions, so none needs reverting. Removing this workaround may bring back the original alerts until the underlying interaction is fixed.

## License

Copyright 2026 Anten Skrabec. Licensed under [Apache License 2.0](LICENSE). The license covers this repository's original source and documentation; Fedora's policy-development interfaces and other external dependencies retain their own licenses. No game, Harmony, MonoMod, or .NET binaries are distributed here.
