/*++

Copyright (c) 2019 changeofpace. All rights reserved.

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


_Check_return_
static
int
ProcessCommands()
{
    int status = EXIT_SUCCESS;

    for (;;)
    {
        std::string Input;
        std::string Command;
        std::vector<std::string> ArgTokens;

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

        Command = ArgTokens[0];

        //
        // Dispatch Commands.
        //
        if (CMD_EXITCLIENT == Command)
        {
            break;
        }
        else if (CMD_HELP == Command)
        {
            (VOID)CmdDisplayHelpText(ArgTokens);
        }
        else if (CMD_COMMANDS == Command)
        {
            (VOID)CmdDisplayCommands(ArgTokens);
        }
        else if (CMD_LOOKUPPROCESSIDBYNAME == Command)
        {
            (VOID)CmdLookupProcessIdByName(ArgTokens);
        }
        else if (CMD_QUERYSYSTEMDEBUGSTATE == Command)
        {
            (VOID)CmdQuerySystemDebugState(ArgTokens);
        }
        else if (CMD_SETHARDWAREBREAKPOINT == Command)
        {
            (VOID)CmdSetHardwareBreakpoint(ArgTokens);
        }
        else if (CMD_CLEARHARDWAREBREAKPOINT == Command)
        {
            (VOID)CmdClearHardwareBreakpoint(ArgTokens);
        }
        else if (CMD_CEC_REGISTER == Command)
        {
            (VOID)CmdCaptureRegisterValues(ArgTokens);
        }
        else if (CMD_CEC_MEMORY == Command)
        {
            (VOID)CmdCaptureMemoryValues(ArgTokens);
        }
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

    return status;
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
        DEBUG_BREAK;
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

    mainstatus = ProcessCommands();

exit:
    return mainstatus;
}
