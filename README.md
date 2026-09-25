# TitanHide — PatchGuard-compatible branch

This branch keeps the original TitanHide source for reference, but changes the recommended x64 design so normal use does **not** require disabling PatchGuard or Driver Signature Enforcement.

The recommended path is now the x32dbg/x64dbg plugin in **driverless user mode**.

## What changed

Original TitanHide performs kernel SSDT/code patching. On modern x64 Windows that conflicts with PatchGuard.

This branch adds an x64 compatibility path that:

- does not patch the SSDT;
- does not overwrite `ntoskrnl.exe` code;
- does not use the legacy kernel code-cave hook path;
- does not use the legacy `ETHREAD.CrossThreadFlags` DKOM path;
- can run the x64dbg plugin without loading `TitanHide.sys`;
- moves common anti-debug handling to the debugger/plugin side.

The original kernel-hook implementation is still present in the repository for reference and legacy experimentation, but the compatibility path does not initialize it on x64.

## Recommended mode

In x64dbg:

```
TitanHideMode user
```

Both x86 and x64 plugin builds default to `user` mode.

### Available modes

| Mode | Behavior |
| --- | --- |
| `TitanHideMode user` | Recommended. No kernel driver is opened. Uses x64dbg/user-mode compatibility logic. |
| `TitanHideMode auto` | Tries the driver first, then falls back to user mode. |
| `TitanHideMode driver` | Legacy/testing path. On this compatibility branch the x64 driver does not initialize the original SSDT hooks. |

## PatchGuard / DSE

### Driverless user mode

For:

```
TitanHideMode user
```

you do **not** need to:

```
bcdedit /set testsigning on
```

and you do **not** need EfiGuard, SandboxBootkit, Shark, UPGDSED, or another PatchGuard bypass.

You can leave:

- PatchGuard enabled;
- Driver Signature Enforcement enabled;
- Test Signing disabled.

### Optional kernel driver

If you want to load `TitanHide.sys` on a normal Windows installation with DSE enabled, the driver must use a signature trusted by Windows.

An unsigned development `.sys` will not load on stock Windows with DSE enabled. Test-signing is a development option, not a requirement for a properly signed release driver.

## x86/x64 user-mode compatibility features

The x32dbg/x64dbg plugins currently provide:

| Feature | Status |
| --- | --- |
| x64dbg built-in debugger hiding | Implemented |
| `PEB.BeingDebugged` | Implemented |
| Debug heap bits in `PEB.NtGlobalFlag` | Implemented |
| `ProcessDebugPort` | Implemented |
| `ProcessDebugObjectHandle` | Implemented |
| `ProcessDebugFlags` | Implemented |
| `SystemKernelDebuggerInformation` | Implemented |
| `SystemKernelDebuggerInformationEx` | Implemented |
| `ThreadHideFromDebugger` / `NtSetInformationThread` | Implemented |
| `NtCreateThreadEx` `HIDE_FROM_DEBUGGER` | Implemented |
| `NtSystemDebugControl` anti-debug queries | Implemented |
| `NtQueryObject` / DebugObject filtering | Implemented |
| `NtClose` invalid/protected-handle behavior | Implemented |
| `NtDuplicateObject` protected close-source handling | Implemented |
| `NtGetContextThread` DRx hiding | Implemented |
| `NtSetContextThread` DRx protection | Implemented |

## How user mode works

The compatibility layer uses x64dbg-managed breakpoints on selected `ntdll.dll` exports.

For anti-debug queries that can be answered safely at entry, the plugin writes the expected output and returns directly to the caller.

For context/handle operations, the plugin uses the debugger process to duplicate the target handle and perform the equivalent operation without modifying PatchGuard-protected kernel state.

For `NtQueryObject`, the plugin performs a real local `NtQueryObject`, filters DebugObject information, relocates returned string pointers to the target buffer, and returns the filtered result.

### Important limitation

These hooks intercept calls that pass through the normal `ntdll.dll` exports.

Code using:

- manually issued syscalls;
- a separately mapped clean copy of `ntdll.dll`;
- custom syscall stubs;

can bypass this interception layer.

The x64dbg breakpoints are also user-mode software breakpoints, so sufficiently aggressive anti-debug code can potentially detect them. This branch avoids PatchGuard/DSE bypasses; it is not intended to make user-mode instrumentation impossible to detect.

## VMProtect mode

For VMProtect targets, use:

```
TitanHideMode vmp
TitanHide
```

Stage 1 VMProtect compatibility currently adds:

- `PEB.OSBuildNumber = 1337`, matching the strategy used by ScyllaHide's VMProtect profile;
- `NtQueryInformationThread(ThreadHideFromDebugger)` filtering;
- automatic removal of the main module entry-point breakpoint;
- all normal driverless anti-debug filtering already provided by `user` mode.

This improves compatibility with VMProtect, but it does **not yet** fully defeat direct-syscall or custom-syscall-stub checks. Those require an in-process hook / instrumentation-callback layer rather than only breakpoints on normal `ntdll.dll` exports.

## Themida / WinLicense diagnostic mode

For authorized analysis of Themida/WinLicense targets, use:

```
TitanHideMode themida-diagnostic
TitanHide
```

This mode does **not** falsify API results. It logs the anti-debug calls that pass through the normal `ntdll.dll` exports and automatically continues execution.

Currently logged calls include:

- `NtQueryInformationProcess` and its information class;
- `NtQueryInformationThread`;
- `NtSetInformationThread`;
- `NtQuerySystemInformation`;
- `NtQueryObject`;
- `NtClose`;
- `NtDuplicateObject`;
- `NtCreateThreadEx`;
- `NtGetContextThread` / `NtSetContextThread`;
- `NtSystemDebugControl`.

Use the x32dbg/x64dbg log pane to see which checks occur immediately before the protector reports a debugger. This is intended to identify compatibility problems without adding direct-syscall or injected stealth bypasses.

## Commands

### Show or change mode

```
TitanHideMode
TitanHideMode user
TitanHideMode auto
TitanHideMode driver
```

### Hide current debuggee

```
TitanHide
```

### Restore plugin-managed state

```
TitanUnhide
```

`TitanUnhide` removes TitanHide's user-mode API breakpoints and restores the backed-up PEB values.

### Options

Show current bit mask:

```
TitanHideOptions
```

Set it:

```
TitanHideOptions 0xFFFFFFFF
```

The bit definitions remain in:

```
TitanHide/TitanHide.h
```

### Legacy driver name

```
TitanHideName TitanHide
```

This only matters when using a driver-based mode.

## Building

### Requirements

- Visual Studio 2022
- Windows SDK
- WDK 10 for the kernel-driver project

Open:

```
TitanHide.sln
```

and build the desired x64 configuration.

For driverless use, the important output is the x64dbg plugin. A kernel driver is not required at runtime.

## Driverless installation

1. Build the TitanHide debugger plugin for the target architecture.
2. Copy `TitanHide.dp32` to the x32dbg plugin directory, or `TitanHide.dp64` to the x64dbg plugin directory.
3. Start x64dbg.
4. Start or attach to the target.
5. The x64 build defaults to user mode, or explicitly run:

```
TitanHideMode user
TitanHide
```

No `sc create`, `sc start`, test-signing, or PatchGuard-disabling step is required for this mode.

## Optional signed-driver installation

If you have a properly signed `TitanHide.sys`:

```
copy TitanHide.sys %systemroot%\system32\drivers\
sc create TitanHide binPath= %systemroot%\system32\drivers\TitanHide.sys type= kernel
sc start TitanHide
sc query TitanHide
```

The compatibility x64 driver intentionally does not activate the legacy SSDT/kernel-code hooks.

## Current scope

This branch targets both **x32dbg (32-bit)** and **x64dbg (64-bit)**.

The driverless Nt* compatibility layer uses architecture-aware argument handling:
- x64: RCX/RDX/R8/R9 plus the x64 stack calling convention;
- x86: stdcall arguments from the debuggee stack.

GitHub Actions builds and validates both `TitanHide.dp32` and `TitanHide.dp64`.

## Safety / stability

Kernel debugging and anti-anti-debug work can destabilize a system. Use a VM or disposable test machine while developing or testing kernel components.

The driverless `user` mode is preferred when the kernel driver is not specifically required.

## Credits

TitanHide is based on the original TitanHide project and retains its existing license and attribution. The user-mode compatibility approach also follows well-established anti-anti-debug techniques used by projects such as ScyllaHide.
