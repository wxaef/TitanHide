#include "pluginmain.h"
#include "plugin.h"

int pluginHandle;
HWND hwndDlg;
int hMenu;
int hMenuDisasm;
int hMenuDump;
int hMenuStack;

enum TITANHIDE_MENU_ID
{
    MENU_HIDE = 1,
    MENU_UNHIDE,
    MENU_MODE_USER,
    MENU_MODE_VMP,
    MENU_MODE_AUTO,
    MENU_SHOW_MODE
};

PLUG_EXPORT bool pluginit(PLUG_INITSTRUCT* initStruct)
{
    initStruct->pluginVersion = PLUGIN_VERSION;
    initStruct->sdkVersion = PLUG_SDKVERSION;
    strncpy_s(initStruct->pluginName, PLUGIN_NAME, _TRUNCATE);
    pluginHandle = initStruct->pluginHandle;
    TitanHideInit(initStruct);
    return true;
}

PLUG_EXPORT bool plugstop()
{
    TitanHideStop();
    return true;
}

PLUG_EXPORT void plugsetup(PLUG_SETUPSTRUCT* setupStruct)
{
    hwndDlg = setupStruct->hwndDlg;
    hMenu = setupStruct->hMenu;
    hMenuDisasm = setupStruct->hMenuDisasm;
    hMenuDump = setupStruct->hMenuDump;
    hMenuStack = setupStruct->hMenuStack;

    _plugin_menuaddentry(hMenu, MENU_HIDE, "Hide current debuggee");
    _plugin_menuaddentry(hMenu, MENU_UNHIDE, "Unhide");
    _plugin_menuaddseparator(hMenu);
    _plugin_menuaddentry(hMenu, MENU_MODE_USER, "Use user mode (driverless)");
    _plugin_menuaddentry(hMenu, MENU_MODE_VMP, "Use VMProtect mode");
    _plugin_menuaddentry(hMenu, MENU_MODE_AUTO, "Use auto mode");
    _plugin_menuaddentry(hMenu, MENU_SHOW_MODE, "Show current mode");
}

PLUG_EXPORT void CBMENUENTRY(CBTYPE cbType, PLUG_CB_MENUENTRY* info)
{
    if(!info)
        return;

    switch(info->hEntry)
    {
    case MENU_HIDE:
        DbgCmdExecDirect("TitanHide");
        break;
    case MENU_UNHIDE:
        DbgCmdExecDirect("TitanUnhide");
        break;
    case MENU_MODE_USER:
        DbgCmdExecDirect("TitanHideMode user");
        break;
    case MENU_MODE_VMP:
        DbgCmdExecDirect("TitanHideMode vmp");
        break;
    case MENU_MODE_AUTO:
        DbgCmdExecDirect("TitanHideMode auto");
        break;
    case MENU_SHOW_MODE:
        DbgCmdExecDirect("TitanHideMode");
        break;
    default:
        break;
    }
}
