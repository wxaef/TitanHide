#include "plugin.h"
#include <windows.h>
#include <stdio.h>
#include <string>
#include "../TitanHide/TitanHide.h"

static DWORD pid = 0;
static bool hidden = false;
static std::string driverName = "TitanHide";

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
    return commandOk || pebOk;
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
    _plugin_unregistercommand(pluginHandle, "TitanHideMode");
    _plugin_unregistercommand(pluginHandle, "TitanHideName");
    _plugin_unregistercommand(pluginHandle, "TitanHideOptions");
    _plugin_unregistercommand(pluginHandle, "TitanUnhide");
    _plugin_unregistercommand(pluginHandle, "TitanHide");
}
