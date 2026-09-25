#include "plugin.h"
#include <windows.h>
#include <stdio.h>
#include <string>
#include "../TitanHide/TitanHide.h"

static DWORD pid = 0;
static bool hidden = false;
static std::string driverName = "TitanHide";

static ULONG GetTitanHideOptions();
#ifdef _WIN64
static bool InstallUserApiHooks();
static void RemoveUserApiHooks();
#endif

enum TITANHIDE_MODE
{
    TitanHideModeAuto,
    TitanHideModeDriver,
    TitanHideModeUser
};

static TITANHIDE_MODE mode = TitanHideModeAuto;

struct PEB_BACKUP
{
    bool valid;
    duint peb;
    BYTE beingDebugged;
    DWORD ntGlobalFlag;
};

static PEB_BACKUP pebBackup = {};

static const char* ModeName(TITANHIDE_MODE value)
{
    switch(value)
    {
    case TitanHideModeDriver:
        return "driver";
    case TitanHideModeUser:
        return "user";
    default:
        return "auto";
    }
}

static bool PatchPebAntiDebug()
{
    const duint peb = DbgValFromString("peb()");
    if(!peb)
    {
        _plugin_logputs("[" PLUGIN_NAME "] Could not resolve PEB address");
        return false;
    }

    BYTE originalBeingDebugged = 0;
    DWORD originalNtGlobalFlag = 0;
#ifdef _WIN64
    const duint ntGlobalFlagOffset = 0xBC;
#else
    const duint ntGlobalFlagOffset = 0x68;
#endif

    if(!DbgMemRead(peb + 2, &originalBeingDebugged, sizeof(originalBeingDebugged)))
        return false;

    DbgMemRead(peb + ntGlobalFlagOffset, &originalNtGlobalFlag, sizeof(originalNtGlobalFlag));

    if(!pebBackup.valid)
    {
        pebBackup.valid = true;
        pebBackup.peb = peb;
        pebBackup.beingDebugged = originalBeingDebugged;
        pebBackup.ntGlobalFlag = originalNtGlobalFlag;
    }

    BYTE beingDebugged = 0;
    if(!DbgMemWrite(peb + 2, &beingDebugged, sizeof(beingDebugged)))
    {
        _plugin_logputs("[" PLUGIN_NAME "] Failed to clear PEB.BeingDebugged");
        return false;
    }

    DWORD ntGlobalFlag = 0;
    if(DbgMemRead(peb + ntGlobalFlagOffset, &ntGlobalFlag, sizeof(ntGlobalFlag)))
    {
        // Clear the three classic debug-heap creation flags while preserving
        // unrelated process flags.
        ntGlobalFlag &= ~(0x10u | 0x20u | 0x40u);
        DbgMemWrite(peb + ntGlobalFlagOffset, &ntGlobalFlag, sizeof(ntGlobalFlag));
    }

    _plugin_logprintf("[" PLUGIN_NAME "] User-mode PEB anti-debug flags cleared at %p\n", (void*)peb);
    return true;
}

static bool ApplyUserModeHide()
{
    // x64dbg's built-in hide command handles debugger-side user-mode hiding.
    const bool commandOk = DbgCmdExecDirect("hide");
    const bool pebOk = PatchPebAntiDebug();
#ifdef _WIN64
    const bool hooksOk = InstallUserApiHooks();
#else
    const bool hooksOk = false;
#endif
    return commandOk || pebOk || hooksOk;
}

static void RestorePebAntiDebug()
{
    if(!pebBackup.valid || !pebBackup.peb)
        return;

#ifdef _WIN64
    const duint ntGlobalFlagOffset = 0xBC;
#else
    const duint ntGlobalFlagOffset = 0x68;
#endif

    DbgMemWrite(pebBackup.peb + 2, &pebBackup.beingDebugged, sizeof(pebBackup.beingDebugged));
    DbgMemWrite(pebBackup.peb + ntGlobalFlagOffset, &pebBackup.ntGlobalFlag, sizeof(pebBackup.ntGlobalFlag));
    pebBackup = {};
}


#ifdef _WIN64
static bool userHooksInstalled = false;

static bool SetTitanBreakpoint(const char* api, const char* name)
{
    char command[512] = {};
    sprintf_s(command, "bp \"ntdll.dll:%s\",\"%s\"", api, name);
    return DbgCmdExecDirect(command);
}

static void DeleteTitanBreakpoint(const char* name)
{
    char command[256] = {};
    sprintf_s(command, "bc \"%s\"", name);
    DbgCmdExecDirect(command);
}

static bool InstallUserApiHooks()
{
    if(userHooksInstalled)
        return true;

    bool ok = true;
    ok &= SetTitanBreakpoint("NtQueryInformationProcess", "TitanHide.NtQueryInformationProcess");
    ok &= SetTitanBreakpoint("NtSetInformationThread", "TitanHide.NtSetInformationThread");
    ok &= SetTitanBreakpoint("NtQuerySystemInformation", "TitanHide.NtQuerySystemInformation");
    ok &= SetTitanBreakpoint("NtSystemDebugControl", "TitanHide.NtSystemDebugControl");
    ok &= SetTitanBreakpoint("NtCreateThreadEx", "TitanHide.NtCreateThreadEx");

    userHooksInstalled = ok;
    _plugin_logprintf("[" PLUGIN_NAME "] User-mode Nt* interception %s\n", ok ? "enabled" : "partially failed");
    return ok;
}

static void RemoveUserApiHooks()
{
    if(!userHooksInstalled)
        return;

    DeleteTitanBreakpoint("TitanHide.NtQueryInformationProcess");
    DeleteTitanBreakpoint("TitanHide.NtSetInformationThread");
    DeleteTitanBreakpoint("TitanHide.NtQuerySystemInformation");
    DeleteTitanBreakpoint("TitanHide.NtSystemDebugControl");
    DeleteTitanBreakpoint("TitanHide.NtCreateThreadEx");
    userHooksInstalled = false;
}

static bool ReadStackPointer(duint offset, duint* value)
{
    const duint rsp = DbgValFromString("rsp");
    return rsp != 0 && DbgMemRead(rsp + offset, value, sizeof(*value));
}

static bool ReturnFromNtCall(duint status)
{
    const duint rsp = DbgValFromString("rsp");
    duint returnAddress = 0;
    if(!rsp || !DbgMemRead(rsp, &returnAddress, sizeof(returnAddress)) || !returnAddress)
        return false;

    if(!DbgValToString("rax", status))
        return false;
    if(!DbgValToString("rsp", rsp + sizeof(duint)))
        return false;
    if(!DbgValToString("rip", returnAddress))
        return false;

    return true;
}

static bool HandleNtQueryInformationProcess()
{
    const ULONG options = GetTitanHideOptions();
    const ULONG infoClass = (ULONG)DbgValFromString("rdx");
    const duint output = DbgValFromString("r8");
    const ULONG outputLength = (ULONG)DbgValFromString("r9");

    duint returnLengthPtr = 0;
    ReadStackPointer(0x28, &returnLengthPtr);

    // PROCESSINFOCLASS values used by Windows anti-debug checks.
    if(infoClass == 7 && (options & HideProcessDebugPort))
    {
        if(output && outputLength >= sizeof(duint))
        {
            duint value = 0;
            DbgMemWrite(output, &value, sizeof(value));
            if(returnLengthPtr)
            {
                ULONG length = (ULONG)sizeof(duint);
                DbgMemWrite(returnLengthPtr, &length, sizeof(length));
            }
            return ReturnFromNtCall(0);
        }
    }
    else if(infoClass == 30 && (options & HideProcessDebugObjectHandle))
    {
        if(output && outputLength >= sizeof(duint))
        {
            duint value = 0;
            DbgMemWrite(output, &value, sizeof(value));
            if(returnLengthPtr)
            {
                ULONG length = (ULONG)sizeof(duint);
                DbgMemWrite(returnLengthPtr, &length, sizeof(length));
            }

            // STATUS_PORT_NOT_SET
            return ReturnFromNtCall(0xC0000353u);
        }
    }
    else if(infoClass == 31 && (options & HideProcessDebugFlags))
    {
        if(output && outputLength >= sizeof(ULONG))
        {
            ULONG value = TRUE;
            DbgMemWrite(output, &value, sizeof(value));
            if(returnLengthPtr)
            {
                ULONG length = sizeof(ULONG);
                DbgMemWrite(returnLengthPtr, &length, sizeof(length));
            }
            return ReturnFromNtCall(0);
        }
    }

    return false;
}

static bool HandleNtSetInformationThread()
{
    const ULONG options = GetTitanHideOptions();
    const ULONG infoClass = (ULONG)DbgValFromString("rdx");
    const ULONG infoLength = (ULONG)DbgValFromString("r9");

    // ThreadHideFromDebugger == 0x11. Pretend the request succeeded without
    // actually hiding the thread from the debugger.
    if(infoClass == 0x11 && infoLength == 0 && (options & HideThreadHideFromDebugger))
        return ReturnFromNtCall(0);

    return false;
}


static bool HandleNtSystemDebugControl()
{
    const ULONG options = GetTitanHideOptions();
    const ULONG command = (ULONG)DbgValFromString("rcx");

    if(!(options & HideNtSystemDebugControl))
        return false;

    // Preserve the two dump-related commands used by the original TitanHide
    // implementation. All other SystemDebugControl requests are reported as
    // unavailable to user-mode anti-debug checks.
    const ULONG SysDbgGetTriageDump = 29;
    const ULONG SysDbgGetLiveKernelDump = 37;
    if(command == SysDbgGetTriageDump || command == SysDbgGetLiveKernelDump)
        return false;

    // STATUS_DEBUGGER_INACTIVE
    return ReturnFromNtCall(0xC0000354u);
}

static bool HandleNtCreateThreadEx()
{
    const ULONG options = GetTitanHideOptions();
    if(!(options & HideThreadHideFromDebugger))
        return false;

    // CreateFlags is the 7th parameter:
    // rcx, rdx, r8, r9, then stack parameters starting at rsp+0x28.
    duint createFlagsAddress = DbgValFromString("rsp") + 0x38;
    ULONG createFlags = 0;
    if(!DbgMemRead(createFlagsAddress, &createFlags, sizeof(createFlags)))
        return false;

    const ULONG THREAD_CREATE_FLAGS_HIDE_FROM_DEBUGGER = 0x4;
    if((createFlags & THREAD_CREATE_FLAGS_HIDE_FROM_DEBUGGER) == 0)
        return false;

    createFlags &= ~THREAD_CREATE_FLAGS_HIDE_FROM_DEBUGGER;
    DbgMemWrite(createFlagsAddress, &createFlags, sizeof(createFlags));
    _plugin_logputs("[" PLUGIN_NAME "] Cleared NtCreateThreadEx HIDE_FROM_DEBUGGER flag");
    return false; // let the real NtCreateThreadEx execute with sanitized flags
}

static bool HandleNtQuerySystemInformation()
{
    const ULONG options = GetTitanHideOptions();
    const ULONG infoClass = (ULONG)DbgValFromString("rcx");
    const duint output = DbgValFromString("rdx");
    const ULONG outputLength = (ULONG)DbgValFromString("r8");
    const duint returnLengthPtr = DbgValFromString("r9");

    if(!(options & HideSystemDebuggerInformation) || !output)
        return false;

    // SystemKernelDebuggerInformation == 35.
    if(infoClass == 35 && outputLength >= 2)
    {
        BYTE info[2] = { FALSE, TRUE };
        DbgMemWrite(output, info, sizeof(info));
        if(returnLengthPtr)
        {
            ULONG length = sizeof(info);
            DbgMemWrite(returnLengthPtr, &length, sizeof(length));
        }
        return ReturnFromNtCall(0);
    }

    // SystemKernelDebuggerInformationEx == 149 on current NT definitions.
    if(infoClass == 149 && outputLength >= 3)
    {
        BYTE info[3] = { FALSE, FALSE, FALSE };
        DbgMemWrite(output, info, sizeof(info));
        if(returnLengthPtr)
        {
            ULONG length = sizeof(info);
            DbgMemWrite(returnLengthPtr, &length, sizeof(length));
        }
        return ReturnFromNtCall(0);
    }

    return false;
}
#endif

static ULONG GetTitanHideOptions()
{
    duint options = 0;
    if (!BridgeSettingGetUint("TitanHide", "Options", &options))
        options = 0xffffffff;
    return (ULONG)options;
}

static bool TitanHideCall(HIDE_COMMAND Command)
{
    auto path = "\\\\.\\" + driverName;
    HANDLE hDevice = CreateFileA(path.c_str(), GENERIC_READ | GENERIC_WRITE, 0, 0, OPEN_EXISTING, 0, 0);
    if (hDevice == INVALID_HANDLE_VALUE)
    {
        _plugin_logputs("[" PLUGIN_NAME "] Could not open TitanHide handle (wrong driver name?)");
        return false;
    }
    HIDE_INFO HideInfo;
    HideInfo.Command = Command;
    HideInfo.Pid = pid;
    HideInfo.Type = GetTitanHideOptions();
    DWORD written = 0;
    auto result = false;
    if (WriteFile(hDevice, &HideInfo, sizeof(HIDE_INFO), &written, 0))
    {
        _plugin_logprintf("[" PLUGIN_NAME "] Process %shidden!\n", Command == UnhidePid ? "un" : "");
        result = true;
    }
    else
    {
        _plugin_logputs("[" PLUGIN_NAME "] WriteFile error...");
    }
    CloseHandle(hDevice);
    return result;
}

static bool cbTitanHide(int argc, char* argv[])
{
    if(hidden)
        return true;

    _plugin_logprintf("[" PLUGIN_NAME "] Hiding PID %X (%ud), mode=%s\n", pid, pid, ModeName(mode));

    bool result = false;
    if(mode == TitanHideModeDriver)
    {
        result = TitanHideCall(HidePid);
        if(result)
            ApplyUserModeHide();
    }
    else if(mode == TitanHideModeUser)
    {
        result = ApplyUserModeHide();
    }
    else
    {
        // Auto mode prefers the legacy driver when available, but gracefully
        // falls back to the PatchGuard/DSE-friendly user-mode path.
        result = TitanHideCall(HidePid);
        if(result)
            ApplyUserModeHide();
        else
        {
            _plugin_logputs("[" PLUGIN_NAME "] Driver unavailable; falling back to user-mode compatibility mode");
            result = ApplyUserModeHide();
        }
    }

    hidden = result;
    return hidden;
}

static bool cbTitanUnhide(int argc, char* argv[])
{
    if(!hidden)
        return true;

    _plugin_logprintf("[" PLUGIN_NAME "] Unhiding PID %X (%ud)\n", pid, pid);

    if(mode == TitanHideModeDriver)
        TitanHideCall(UnhidePid);
    else if(mode == TitanHideModeAuto)
        TitanHideCall(UnhidePid);

#ifdef _WIN64
    RemoveUserApiHooks();
#endif
    RestorePebAntiDebug();
    hidden = false;
    return true;
}

static bool cbTitanHideMode(int argc, char* argv[])
{
    if(argc < 2)
    {
        _plugin_logprintf("[" PLUGIN_NAME "] Current mode: %s\n", ModeName(mode));
        return true;
    }

    if(_stricmp(argv[1], "auto") == 0)
        mode = TitanHideModeAuto;
    else if(_stricmp(argv[1], "driver") == 0)
        mode = TitanHideModeDriver;
    else if(_stricmp(argv[1], "user") == 0 || _stricmp(argv[1], "compat") == 0)
        mode = TitanHideModeUser;
    else
    {
        _plugin_logputs("[" PLUGIN_NAME "] Usage: TitanHideMode auto|driver|user");
        return false;
    }

    BridgeSettingSetUint("TitanHide", "Mode", (duint)mode);
    _plugin_logprintf("[" PLUGIN_NAME "] New mode: %s\n", ModeName(mode));
    return true;
}

static bool cbTitanHideOptions(int argc, char* argv[])
{
    if (argc < 2)
    {
        _plugin_logprintf("[" PLUGIN_NAME "] Options: 0x%08X\n", GetTitanHideOptions());
    }
    else
    {
        duint options = DbgValFromString(argv[1]);
        BridgeSettingSetUint("TitanHide", "Options", options & 0xffffffff);
        if(hidden && mode != TitanHideModeUser)
            TitanHideCall(HidePid);
        _plugin_logprintf("[" PLUGIN_NAME "] New options: 0x%08X\n", GetTitanHideOptions());
    }
    return true;
}

static bool cbTitanHideName(int argc, char* argv[])
{
    if (argc < 2)
    {
        _plugin_logprintf("[" PLUGIN_NAME "] Current driver name: '%s'\n", driverName.c_str());
    }
    else
    {
        driverName = argv[1];
        BridgeSettingSet("TitanHide", "DriverName", driverName.c_str());
        _plugin_logprintf("[" PLUGIN_NAME "] New driver name: '%s'\n", driverName.c_str());
    }
    return true;
}

PLUG_EXPORT void CBCREATEPROCESS(CBTYPE cbType, PLUG_CB_CREATEPROCESS* info)
{
    pid = info->fdProcessInfo->dwProcessId;
    hidden = false;
    pebBackup = {};
}

PLUG_EXPORT void CBATTACH(CBTYPE cbType, PLUG_CB_ATTACH* info)
{
    pid = info->dwProcessId;
    hidden = false;
    pebBackup = {};
}

PLUG_EXPORT void CBSYSTEMBREAKPOINT(CBTYPE cbType, PLUG_CB_SYSTEMBREAKPOINT* info)
{
    char* argv = "TitanHide";
    cbTitanHide(1, &argv);
}


PLUG_EXPORT void CBBREAKPOINT(CBTYPE cbType, PLUG_CB_BREAKPOINT* info)
{
#ifdef _WIN64
    if(!hidden || !info || !info->breakpoint || mode == TitanHideModeDriver)
        return;

    const char* name = info->breakpoint->name;
    bool handled = false;

    if(strcmp(name, "TitanHide.NtQueryInformationProcess") == 0)
        handled = HandleNtQueryInformationProcess();
    else if(strcmp(name, "TitanHide.NtSetInformationThread") == 0)
        handled = HandleNtSetInformationThread();
    else if(strcmp(name, "TitanHide.NtQuerySystemInformation") == 0)
        handled = HandleNtQuerySystemInformation();
    else if(strcmp(name, "TitanHide.NtSystemDebugControl") == 0)
        handled = HandleNtSystemDebugControl();
    else if(strcmp(name, "TitanHide.NtCreateThreadEx") == 0)
        handled = HandleNtCreateThreadEx();

    if(handled)
        DbgCmdExecDirect("run");
#else
    UNREFERENCED_PARAMETER(cbType);
    UNREFERENCED_PARAMETER(info);
#endif
}

PLUG_EXPORT void CBSTOPDEBUG(CBTYPE cbType, PLUG_CB_STOPDEBUG* info)
{
    char* argv = "TitanUnhide";
    cbTitanUnhide(1, &argv);
}

void TitanHideInit(PLUG_INITSTRUCT* initStruct)
{
    char setting[MAX_SETTING_SIZE] = "";
    BridgeSettingGet("TitanHide", "DriverName", setting);
    if (setting[0] != '\0')
    {
        driverName = setting;
    }

    duint savedMode = 0;
    if(BridgeSettingGetUint("TitanHide", "Mode", &savedMode) && savedMode <= TitanHideModeUser)
        mode = (TITANHIDE_MODE)savedMode;

    _plugin_registercommand(pluginHandle, "TitanHide", cbTitanHide, true);
    _plugin_registercommand(pluginHandle, "TitanUnhide", cbTitanUnhide, true);
    _plugin_registercommand(pluginHandle, "TitanHideOptions", cbTitanHideOptions, false);
    _plugin_registercommand(pluginHandle, "TitanHideName", cbTitanHideName, false);
    _plugin_registercommand(pluginHandle, "TitanHideMode", cbTitanHideMode, false);
}

void TitanHideStop()
{
#ifdef _WIN64
    RemoveUserApiHooks();
#endif
    _plugin_unregistercommand(pluginHandle, "TitanHideMode");
    _plugin_unregistercommand(pluginHandle, "TitanHideName");
    _plugin_unregistercommand(pluginHandle, "TitanHideOptions");
    _plugin_unregistercommand(pluginHandle, "TitanUnhide");
    _plugin_unregistercommand(pluginHandle, "TitanHide");
}
