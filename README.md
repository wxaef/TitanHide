**Do not come here and open issues about problems with installation, crashes with bug check 0x109: CRITICAL_STRUCTURE_CORRUPTION or questions on how to disable PatchGuard. I will permanently ban you from the issue tracker. If you don't know how to properly install the tool you don't know enough to use it responsibly and you should use something else like [ScyllaHide](https://github.com/x64dbg/ScyllaHide).

# Overview

This branch contains two modes of interest: the original TitanHide implementation and an x64 PatchGuard-compatible driver mode. The compatibility mode keeps the device/control path but does not activate the legacy SSDT, kernel code-patching, or DKOM paths. Legacy hiding logic remains in the source tree for reference and migration to supported user-mode debugger/plugin techniques.

The idea for this project was thought of together with cypher, shoutout man!

# Features

- ProcessDebugFlags (NtQueryInformationProcess)
- ProcessDebugPort (NtQueryInformationProcess)
- ProcessDebugObjectHandle (NtQueryInformationProcess)
- DebugObject (NtQueryObject)
- SystemKernelDebuggerInformation (NtQuerySystemInformation)
- SystemDebugControl (NtSystemDebugControl)
- NtClose (STATUS_INVALID_HANDLE/STATUS_HANDLE_NOT_CLOSABLE exceptions)
- ThreadHideFromDebugger (NtSetInformationThread)
- Protect DRx (HW BPs) (NtGetContextThread/NtSetContextThread)

# Test environments

- Windows 10 x64 & x86
- Windows 8.1 x64 & x86
- Windows 7 x64 & x86 (SP1)
- Windows XP x86 (SP3)
- Windows XP x64 (SP1)

# Compiling

1. Install Visual Studio 2022.
2. Install the [WDK10](https://go.microsoft.com/fwlink/?linkid=2128854)/[WDK8](https://go.microsoft.com/fwlink/p/?LinkID=324284)/[WDK7](https://www.microsoft.com/download/confirmation.aspx?id=11800).
3. Open `TitanHide.sln` and hit compile!

# Requirements

## PatchGuard-compatible x64 mode

This branch enables a PatchGuard-compatible mode by default on x64.

In this mode TitanHide does **not**:

- patch the SSDT;
- overwrite `ntoskrnl.exe` code;
- use the legacy kernel code-cave hook path;
- modify `ETHREAD.CrossThreadFlags` through the legacy DKOM path.

You therefore do **not** need to disable PatchGuard to load and run the compatibility-mode driver.

> Important: the legacy kernel-hook implementation is still present in the source tree for reference, but it is not activated by the x64 driver entry path in this branch.

Because the legacy global Nt* interception is disabled, kernel-backed hiding features that depended on those hooks are not provided by the compatibility-mode driver. Those features should be implemented in the debugger/user-mode plugin layer instead of by patching protected kernel structures.

## Driver signing / DSE

Do not disable Driver Signature Enforcement for normal use.

Windows still requires a kernel driver to have a signature trusted by the platform. For a normal end-user build, sign and submit the driver through the supported Microsoft driver-signing process and install the resulting signed `TitanHide.sys`.

An unsigned local development build will **not** load on a stock Windows installation with DSE enabled. Test-signing mode is only a development option and is not required for a properly signed release build.

## x64dbg driverless compatibility mode

The x64dbg plugin can now operate without `TitanHide.sys`.

Use:

```
TitanHideMode user
```

Available modes:

- `TitanHideMode auto` - try the driver first, then fall back to user-mode compatibility mode.
- `TitanHideMode driver` - require the legacy driver path.
- `TitanHideMode user` - do not open the driver at all.

In user mode the plugin currently:

- invokes x64dbg's built-in `hide` support;
- clears `PEB.BeingDebugged`;
- clears the classic debug-heap bits from `PEB.NtGlobalFlag`;
- restores the original PEB values when `TitanUnhide` is used.

This makes the plugin usable on a stock system without loading the kernel driver.

Current x64 user-mode interception coverage:

| Original TitanHide option | User-mode compatibility status |
| --- | --- |
| ProcessDebugPort | Implemented |
| ProcessDebugObjectHandle | Implemented |
| ProcessDebugFlags | Implemented |
| SystemKernelDebuggerInformation | Implemented |
| SystemKernelDebuggerInformationEx | Implemented |
| ThreadHideFromDebugger via NtSetInformationThread | Implemented |
| THREAD_CREATE_FLAGS_HIDE_FROM_DEBUGGER via NtCreateThreadEx | Implemented |
| NtSystemDebugControl | Implemented for the same non-dump commands as legacy TitanHide |
| NtQueryObject / DebugObject counts | Not yet migrated |
| NtClose exception behavior | Not yet migrated |
| NtGetContextThread / NtSetContextThread DRx protection | Not yet migrated |

The implemented Nt* compatibility hooks use x64dbg-managed breakpoints at ntdll API entry points and short-circuit only the anti-debug query classes listed above. They do not patch SSDT entries or protected kernel code.

# Installation

1. Copy `TitanHide.sys` to `%systemroot%\system32\drivers`.
2. Run the command `sc create TitanHide binPath= %systemroot%\system32\drivers\TitanHide.sys type= kernel` to create the TitanHide service.
3. Run the command `sc start TitanHide` to start the TitanHide service.
4. Run the command `sc query TitanHide` to check if TitanHide is running.

To check if TitanHide is working correctly, use [DebugView](https://technet.microsoft.com/en-us/sysinternals/debugview.aspx) or check `C:\TitanHide.log`.

## Hiding

For VMProtect 3.9.4 and above you need to change the service name to something else. For example `sc create NotTitanHide`, which will bypass their latest 'detection'. After changing the service name you will need to configure the plugin with the following command in x64dbg:

```
TitanHideName NotTitanHide
```

# Remarks

- When using x64dbg, you can use the TitanHide plugin (available on the download page).
- **NEVER RUN THIS DRIVER ON A PRODUCTION SYSTEM, ALWAYS USE A VM!**

