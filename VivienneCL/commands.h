#pragma once

#include <Windows.h>

#include <string>
#include <vector>

//=============================================================================
// Console Commands
//=============================================================================
#define CMD_CLEARHARDWAREBREAKPOINT "clear"
#define CMD_COMMANDS                "commands"
#define CMD_CEC_REGISTER            "cecr"
#define CMD_CEC_MEMORY              "cecm"
#define CMD_EXITCLIENT              "exit"
#define CMD_HELP                    "help"
#define CMD_LOOKUPPROCESSIDBYNAME   "pid"
#define CMD_QUERYSYSTEMDEBUGSTATE   "qdr"
#define CMD_SETHARDWAREBREAKPOINT   "setbp"

//=============================================================================
// Command Interface
//=============================================================================
_Check_return_
BOOL
CmdDisplayCommands(
    _In_ const std::vector<std::string>& ArgTokens
);

_Check_return_
BOOL
CmdLookupProcessIdByName(
    _In_ const std::vector<std::string>& ArgTokens
);

_Check_return_
BOOL
CmdQuerySystemDebugState(
    _In_ const std::vector<std::string>& ArgTokens
);

_Check_return_
BOOL
CmdSetHardwareBreakpoint(
    _In_ const std::vector<std::string>& ArgTokens
);

_Check_return_
BOOL
CmdClearHardwareBreakpoint(
    _In_ const std::vector<std::string>& ArgTokens
);

_Check_return_
BOOL
CmdCaptureRegisterValues(
    _In_ const std::vector<std::string>& ArgTokens
);

_Check_return_
BOOL
CmdCaptureMemoryValues(
    _In_ const std::vector<std::string>& ArgTokens
);

_Check_return_
BOOL
CmdDisplayHelpText(
    _In_ const std::vector<std::string>& ArgTokens
);
