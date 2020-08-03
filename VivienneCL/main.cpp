/*++

Copyright (c) 2019-2020 changeofpace. All rights reserved.

Use of this source code is governed by the MIT license. See the 'LICENSE' file
for more information.

--*/

#include <Windows.h>

#include <iostream>
#include <iterator>
#include <string>
#include <sstream>
#include <vector>

#include "commands.h"
#include "debug.h"
#include "driver_io.h"
#include "log.h"
#include "string_util.h"


static
VOID
PrintClientBanner()
{
    INF_PRINT("VivienneCL 1.0.0 (2020-08-02)");
    INF_PRINT("Type 'help' for command information.");
}


static
VOID
ProcessCommands()
{
    for (;;)
    {
        std::string Input = {};
        std::vector<std::string> ArgTokens = {};
        PCSTR pszCommand = NULL;

        //
        // Prompt and tokenize input.
        //
        std::cout << "> ";
        std::getline(std::cin, Input);

        //
        // Skip empty lines.
        //
        if (!StrSplitStringByWhitespace(Input, ArgTokens))
        {
            std::cin.clear();
            continue;
        }

        //
        // Dispatch the command.
        //
        pszCommand = ArgTokens[0].data();

        //---------------------------------------------------------------------
        // General
        //---------------------------------------------------------------------
        if (CMD_ICOMPARE(CMD_EXIT_CLIENT, pszCommand))
        {
            break;
        }
        else if (
            CMD_ICOMPARE(pszCommand, CMD_COMMANDS) ||
            CMD_ICOMPARE(pszCommand, CMD_COMMANDS_SHORT))
        {
            CmdCommands(ArgTokens);
        }
        else if (CMD_ICOMPARE(pszCommand, CMD_HELP))
        {
            CmdHelp(ArgTokens);
        }
        //---------------------------------------------------------------------
        // Process
        //---------------------------------------------------------------------
        else if (
            CMD_ICOMPARE(pszCommand, CMD_GET_PROCESS_ID) ||
            CMD_ICOMPARE(pszCommand, CMD_GET_PROCESS_ID_SHORT))
        {
            CmdGetProcessId(ArgTokens);
        }
        else if (
            CMD_ICOMPARE(pszCommand, CMD_GET_PROCESS_INFORMATION) ||
            CMD_ICOMPARE(pszCommand, CMD_GET_PROCESS_INFORMATION_SHORT))
        {
            CmdGetProcessInformation(ArgTokens);
        }
#if defined(CFG_BPM_HARDWARE_BREAKPOINT_MANAGER)
        //---------------------------------------------------------------------
        // Hardware Breakpoints
        //---------------------------------------------------------------------
        else if (
            CMD_ICOMPARE(pszCommand, CMD_QUERY_SYSTEM_DEBUG_STATE) ||
            CMD_ICOMPARE(pszCommand, CMD_QUERY_SYSTEM_DEBUG_STATE_SHORT))
        {
            CmdQuerySystemDebugState(ArgTokens);
        }
        else if (
            CMD_ICOMPARE(pszCommand, CMD_SET_HARDWARE_BREAKPOINT) ||
            CMD_ICOMPARE(pszCommand, CMD_SET_HARDWARE_BREAKPOINT_SHORT))
        {
            CmdSetHardwareBreakpoint(ArgTokens);
        }
        else if (
            CMD_ICOMPARE(pszCommand, CMD_CLEAR_HARDWARE_BREAKPOINT) ||
            CMD_ICOMPARE(pszCommand, CMD_CLEAR_HARDWARE_BREAKPOINT_SHORT))
        {
            CmdClearHardwareBreakpoint(ArgTokens);
        }
        //---------------------------------------------------------------------
        // Capture Execution Context
        //---------------------------------------------------------------------
        else if (
            CMD_ICOMPARE(pszCommand, CMD_CEC_REGISTER) ||
            CMD_ICOMPARE(pszCommand, CMD_CEC_REGISTER_SHORT))
        {
            CmdCaptureRegisterValues(ArgTokens);
        }
        else if (
            CMD_ICOMPARE(pszCommand, CMD_CEC_MEMORY) ||
            CMD_ICOMPARE(pszCommand, CMD_CEC_MEMORY_SHORT))
        {
            CmdCaptureMemoryValues(ArgTokens);
        }
#endif
#if defined(CFG_BPM_EPT_BREAKPOINT_MANAGER)
        //---------------------------------------------------------------------
        // Ept Breakpoints
        //---------------------------------------------------------------------
        else if (
            CMD_ICOMPARE(pszCommand, CMD_QUERY_EPT_BREAKPOINT_INFORMATION) ||
            CMD_ICOMPARE(pszCommand, CMD_QUERY_EPT_BREAKPOINT_INFORMATION_SHORT))
        {
            CmdQueryEptBreakpointInformation(ArgTokens);
        }
        else if (
            CMD_ICOMPARE(pszCommand, CMD_SET_EPT_BREAKPOINT_BASIC) ||
            CMD_ICOMPARE(pszCommand, CMD_SET_EPT_BREAKPOINT_BASIC_SHORT))
        {
            CmdSetEptBreakpointBasic(ArgTokens);
        }
        else if (
            CMD_ICOMPARE(pszCommand, CMD_SET_EPT_BREAKPOINT_GENERAL_REGISTER_CONTEXT) ||
            CMD_ICOMPARE(pszCommand, CMD_SET_EPT_BREAKPOINT_GENERAL_REGISTER_CONTEXT_SHORT))
        {
            CmdSetEptBreakpointGeneralRegisterContext(ArgTokens);
        }
        else if (
            CMD_ICOMPARE(pszCommand, CMD_SET_EPT_BREAKPOINT_KEYED_REGISTER_CONTEXT) ||
            CMD_ICOMPARE(pszCommand, CMD_SET_EPT_BREAKPOINT_KEYED_REGISTER_CONTEXT_SHORT))
        {
            CmdSetEptBreakpointKeyedRegisterContext(ArgTokens);
        }
        else if (
            CMD_ICOMPARE(pszCommand, CMD_DISABLE_EPT_BREAKPOINT) ||
            CMD_ICOMPARE(pszCommand, CMD_DISABLE_EPT_BREAKPOINT_SHORT))
        {
            CmdDisableEptBreakpoint(ArgTokens);
        }
        else if (
            CMD_ICOMPARE(pszCommand, CMD_CLEAR_EPT_BREAKPOINT) ||
            CMD_ICOMPARE(pszCommand, CMD_CLEAR_EPT_BREAKPOINT_SHORT))
        {
            CmdClearEptBreakpoint(ArgTokens);
        }
        else if (
            CMD_ICOMPARE(pszCommand, CMD_PRINT_EPT_BREAKPOINT_LOG_HEADER) ||
            CMD_ICOMPARE(pszCommand, CMD_PRINT_EPT_BREAKPOINT_LOG_HEADER_SHORT))
        {
            CmdPrintEptBreakpointLogHeader(ArgTokens);
        }
        else if (
            CMD_ICOMPARE(pszCommand, CMD_PRINT_EPT_BREAKPOINT_LOG_ELEMENTS) ||
            CMD_ICOMPARE(pszCommand, CMD_PRINT_EPT_BREAKPOINT_LOG_ELEMENTS_SHORT))
        {
            CmdPrintEptBreakpointLogElements(ArgTokens);
        }
#endif
        //---------------------------------------------------------------------
        // Unhandled
        //---------------------------------------------------------------------
        else
        {
            ERR_PRINT("Invalid command.");
        }

        //
        // Prepare next line.
        //
        std::cout << std::endl;
        std::cin.clear();
    }
}


VOID
__cdecl
ProcessTerminationHandler()
{
    VivienneIoTermination();
}


int
main(
    _In_ int argc,
    _In_ char* argv[]
)
{
    int mainstatus = EXIT_SUCCESS;

    if (!LogInitialization(LOG_CONFIG_STDOUT))
    {
        mainstatus = EXIT_FAILURE;
        DEBUG_BREAK();
        goto exit;
    }

    if (!VivienneIoInitialization())
    {
        ERR_PRINT("VivienneIoInitialization failed: %u", GetLastError());
        mainstatus = EXIT_FAILURE;
        goto exit;
    }

    //
    // Register a termination handler for cleanup.
    //
    if (atexit(ProcessTerminationHandler))
    {
        ERR_PRINT("atexit failed.");
        mainstatus = EXIT_FAILURE;
        goto exit;
    }

    PrintClientBanner();
    ProcessCommands();

exit:
    return mainstatus;
}
