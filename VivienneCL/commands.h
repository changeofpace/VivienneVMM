/*++

Copyright (c) 2019-2020 changeofpace. All rights reserved.

Use of this source code is governed by the MIT license. See the 'LICENSE' file
for more information.

--*/

#pragma once

#include <Windows.h>

#include <string.h>

#include <string>
#include <vector>

#include "../common/config.h"

//=============================================================================
// Macros
//=============================================================================
#define CMD_ICOMPARE(Argument, Command) (0 == _stricmp(Argument, Command))

//=============================================================================
// Console Commands
//=============================================================================

//
// General
//
#define CMD_COMMANDS                        "commands"
#define CMD_COMMANDS_SHORT                  "cmds"
#define CMD_HELP                            "help"
#define CMD_EXIT_CLIENT                     "exit"

//
// Process
//
#define CMD_GET_PROCESS_ID                  "GetProcessId"
#define CMD_GET_PROCESS_ID_SHORT            "procid"
#define CMD_GET_PROCESS_INFORMATION         "GetProcessInformation"
#define CMD_GET_PROCESS_INFORMATION_SHORT   "procinfo"

#if defined(CFG_BPM_HARDWARE_BREAKPOINT_MANAGER)
//
// Hardware Breakpoints
//
#define CMD_QUERY_SYSTEM_DEBUG_STATE        "QuerySystemDebugState"
#define CMD_QUERY_SYSTEM_DEBUG_STATE_SHORT  "qsds"
#define CMD_SET_HARDWARE_BREAKPOINT         "SetHwBp"
#define CMD_SET_HARDWARE_BREAKPOINT_SHORT   "shb"
#define CMD_CLEAR_HARDWARE_BREAKPOINT       "ClearHwBp"
#define CMD_CLEAR_HARDWARE_BREAKPOINT_SHORT "chb"

//
// Capture Execution Context
//
#define CMD_CEC_REGISTER                    "CaptureExecCtxRegister"
#define CMD_CEC_REGISTER_SHORT              "cecr"
#define CMD_CEC_MEMORY                      "CaptureExecCtxMemory"
#define CMD_CEC_MEMORY_SHORT                "cecm"
#endif

#if defined(CFG_BPM_EPT_BREAKPOINT_MANAGER)
//
// Ept Breakpoints
//
#define CMD_QUERY_EPT_BREAKPOINT_INFORMATION                    "QueryEptBpInfo"
#define CMD_QUERY_EPT_BREAKPOINT_INFORMATION_SHORT              "qebi"
#define CMD_SET_EPT_BREAKPOINT_BASIC                            "SetEptBpBasic"
#define CMD_SET_EPT_BREAKPOINT_BASIC_SHORT                      "sebb"
#define CMD_SET_EPT_BREAKPOINT_GENERAL_REGISTER_CONTEXT         "SetEptBpRegisters"
#define CMD_SET_EPT_BREAKPOINT_GENERAL_REGISTER_CONTEXT_SHORT   "sebg"
#define CMD_SET_EPT_BREAKPOINT_KEYED_REGISTER_CONTEXT           "SetEptBpKeyed"
#define CMD_SET_EPT_BREAKPOINT_KEYED_REGISTER_CONTEXT_SHORT     "sebk"
#define CMD_DISABLE_EPT_BREAKPOINT                              "DisableEptBp"
#define CMD_DISABLE_EPT_BREAKPOINT_SHORT                        "deb"
#define CMD_CLEAR_EPT_BREAKPOINT                                "ClearEptBp"
#define CMD_CLEAR_EPT_BREAKPOINT_SHORT                          "ceb"
#define CMD_PRINT_EPT_BREAKPOINT_LOG_HEADER                     "PrintEptBpLogHeader"
#define CMD_PRINT_EPT_BREAKPOINT_LOG_HEADER_SHORT               "peblh"
#define CMD_PRINT_EPT_BREAKPOINT_LOG_ELEMENTS                   "PrintEptBpLogElements"
#define CMD_PRINT_EPT_BREAKPOINT_LOG_ELEMENTS_SHORT             "peble"
#endif

//=============================================================================
// Command Interface
//=============================================================================

//
// General
//
BOOL
CmdCommands(
    _In_ const std::vector<std::string>& ArgTokens
);

BOOL
CmdHelp(
    _In_ const std::vector<std::string>& ArgTokens
);

//
// Process
//
BOOL
CmdGetProcessId(
    _In_ const std::vector<std::string>& ArgTokens
);

BOOL
CmdGetProcessInformation(
    _In_ const std::vector<std::string>& ArgTokens
);

#if defined(CFG_BPM_HARDWARE_BREAKPOINT_MANAGER)
//
// Hardware Breakpoints
//
BOOL
CmdQuerySystemDebugState(
    _In_ const std::vector<std::string>& ArgTokens
);

BOOL
CmdSetHardwareBreakpoint(
    _In_ const std::vector<std::string>& ArgTokens
);

BOOL
CmdClearHardwareBreakpoint(
    _In_ const std::vector<std::string>& ArgTokens
);

//
// Capture Execution Context
//
BOOL
CmdCaptureRegisterValues(
    _In_ const std::vector<std::string>& ArgTokens
);

BOOL
CmdCaptureMemoryValues(
    _In_ const std::vector<std::string>& ArgTokens
);
#endif

#if defined(CFG_BPM_EPT_BREAKPOINT_MANAGER)
//
// Ept Breakpoints
//
BOOL
CmdQueryEptBreakpointInformation(
    _In_ const std::vector<std::string>& ArgTokens
);

BOOL
CmdSetEptBreakpointBasic(
    _In_ const std::vector<std::string>& ArgTokens
);

BOOL
CmdSetEptBreakpointGeneralRegisterContext(
    _In_ const std::vector<std::string>& ArgTokens
);

BOOL
CmdSetEptBreakpointKeyedRegisterContext(
    _In_ const std::vector<std::string>& ArgTokens
);

BOOL
CmdDisableEptBreakpoint(
    _In_ const std::vector<std::string>& ArgTokens
);

BOOL
CmdClearEptBreakpoint(
    _In_ const std::vector<std::string>& ArgTokens
);

BOOL
CmdPrintEptBreakpointLogHeader(
    _In_ const std::vector<std::string>& ArgTokens
);

BOOL
CmdPrintEptBreakpointLogElements(
    _In_ const std::vector<std::string>& ArgTokens
);
#endif
