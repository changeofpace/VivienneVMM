#include <Windows.h>

#include <iostream>
#include <iterator>
#include <string>
#include <sstream>
#include <vector>

#include "commands.h"
#include "driver_io.h"
#include "string_util.h"


#define VVMM_SUCCESS 0
#define VVMM_FAILURE 1


//
// ProcessCommands
//
static
int
ProcessCommands()
{
    int status = VVMM_FAILURE;

    for (;;)
    {
        std::string Input;
        std::string Command;
        std::vector<std::string> ArgTokens;

        // Prompt and tokenize input.
        std::cout << "> ";
        std::getline(std::cin, Input);

        // Skip empty lines.
        if (!StrSplitStringByWhitespace(Input, ArgTokens))
        {
            std::cin.clear();
            continue;
        }

        Command = ArgTokens[0];

        // Dispatch Commands.
        if (CMD_EXITCLIENT == Command)
        {
            status = VVMM_SUCCESS;
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
            printf("Invalid command.\n");
        }

        // Prepare next line.
        std::cout << std::endl;
        std::cin.clear();
    }

    return status;
}


//
// ProcessTerminationHandler
//
VOID
__cdecl
ProcessTerminationHandler()
{
    (VOID)DrvTermination();
}


//
// main
//
int
main(
    _In_ int argc,
    _In_ char* argv[]
)
{
    int mainstatus = VVMM_FAILURE;

    if (!DrvInitialization())
    {
        printf("DrvInitialization failed: %u\n", GetLastError());
        goto exit;
    }

    // Register a termination handler for cleanup.
    if (atexit(ProcessTerminationHandler))
    {
        printf("atexit failed.\n");
        goto exit;
    }

    mainstatus = ProcessCommands();

exit:
    return mainstatus;
}