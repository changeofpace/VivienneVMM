/*++

Copyright (c) 2019-2020 changeofpace. All rights reserved.

Use of this source code is governed by the MIT license. See the 'LICENSE' file
for more information.

--*/

#include "commands.h"

#include <algorithm>
#include <memory>
#include <sstream>

#include "debug.h"
#include "driver_io.h"
#if defined(CFG_BPM_EPT_BREAKPOINT_MANAGER)
#include "ept_breakpoint.h"
#endif
#include "log.h"
#include "memory_util.h"
#include "ntdll.h"
#include "process.h"
#include "token_parser.h"

#include "..\common\arch_x64.h"
#include "..\common\driver_io_types.h"


//
// TODO Commands should be refactored into classes.
//
// TODO Use R"(...)" syntax for all usage text and improve legacy command text.
//
// TODO Refactor / remove the 'help' command or make each command behave like
//  the CECM command.
//
// TODO Add command to read process memory.
//
// TODO Reduce duplicate extended information text for ept breakpoint commands.
//
// TODO Replace all calls to 'LogPrintDirect' with 'INF_PRINT'.
//


//=============================================================================
// Utilities
//=============================================================================
FORCEINLINE
static
VOID
CmdpPrintAlignedCommandName(
    _In_z_ PSTR pszName,
    _In_opt_z_ PSTR pszShortName
)
{
    INF_PRINT("    %-27s%s",
        pszName,
        (ARGUMENT_PRESENT(pszShortName) ?
            pszShortName :
            ""));
}


static
VOID
CmdpPrintUsageText(
    _In_z_ PCSTR pszName,
    _In_opt_z_ PSTR pszShortName,
    _In_z_ PCSTR pszUsageText
)
{
    INF_PRINT("%s", pszUsageText);
    INF_PRINT("");

    if (ARGUMENT_PRESENT(pszShortName))
    {
        INF_PRINT("Type '%s %s' or '%s %s' for more information.",
            CMD_HELP,
            pszName,
            CMD_HELP,
            pszShortName);
    }
    else
    {
        INF_PRINT("Type '%s %s' for more information.", CMD_HELP, pszName);
    }
}


//=============================================================================
// General Commands
//=============================================================================
static PCSTR g_ExitClientExtInfoText = "Terminate the VivienneCL session.";

static PCSTR g_CommandsExtInfoText = "Display a list of available commands.";

//
// CmdCommands
//
// Display a list of supported commands.
//
_Use_decl_annotations_
BOOL
CmdCommands(
    const std::vector<std::string>& ArgTokens
)
{
    UNREFERENCED_PARAMETER(ArgTokens);

    INF_PRINT("General Commands:");
    CmdpPrintAlignedCommandName(CMD_COMMANDS, CMD_COMMANDS_SHORT);
    CmdpPrintAlignedCommandName(CMD_HELP, NULL);
    CmdpPrintAlignedCommandName(CMD_EXIT_CLIENT, NULL);

    INF_PRINT("Process:");
    CmdpPrintAlignedCommandName(
        CMD_GET_PROCESS_ID,
        CMD_GET_PROCESS_ID_SHORT);
    CmdpPrintAlignedCommandName(
        CMD_GET_PROCESS_INFORMATION,
        CMD_GET_PROCESS_INFORMATION_SHORT);

#if defined(CFG_BPM_HARDWARE_BREAKPOINT_MANAGER)
    INF_PRINT("Hardware Breakpoint Commands:");
    CmdpPrintAlignedCommandName(CMD_QUERY_SYSTEM_DEBUG_STATE, NULL);
    CmdpPrintAlignedCommandName(
        CMD_SET_HARDWARE_BREAKPOINT,
        CMD_SET_HARDWARE_BREAKPOINT_SHORT);
    CmdpPrintAlignedCommandName(
        CMD_CLEAR_HARDWARE_BREAKPOINT,
        CMD_CLEAR_HARDWARE_BREAKPOINT_SHORT);

    INF_PRINT("Capture Execution Context Commands:");
    CmdpPrintAlignedCommandName(CMD_CEC_REGISTER, NULL);
    CmdpPrintAlignedCommandName(CMD_CEC_MEMORY, NULL);
#endif

#if defined(CFG_BPM_EPT_BREAKPOINT_MANAGER)
    INF_PRINT("Ept Breakpoint Commands:");
    CmdpPrintAlignedCommandName(
        CMD_QUERY_EPT_BREAKPOINT_INFORMATION,
        CMD_QUERY_EPT_BREAKPOINT_INFORMATION_SHORT);
    CmdpPrintAlignedCommandName(
        CMD_SET_EPT_BREAKPOINT_BASIC,
        CMD_SET_EPT_BREAKPOINT_BASIC_SHORT);
    CmdpPrintAlignedCommandName(
        CMD_SET_EPT_BREAKPOINT_GENERAL_REGISTER_CONTEXT,
        CMD_SET_EPT_BREAKPOINT_GENERAL_REGISTER_CONTEXT_SHORT);
    CmdpPrintAlignedCommandName(
        CMD_SET_EPT_BREAKPOINT_KEYED_REGISTER_CONTEXT,
        CMD_SET_EPT_BREAKPOINT_KEYED_REGISTER_CONTEXT_SHORT);
    CmdpPrintAlignedCommandName(
        CMD_DISABLE_EPT_BREAKPOINT,
        CMD_DISABLE_EPT_BREAKPOINT_SHORT);
    CmdpPrintAlignedCommandName(
        CMD_CLEAR_EPT_BREAKPOINT,
        CMD_CLEAR_EPT_BREAKPOINT_SHORT);
    CmdpPrintAlignedCommandName(
        CMD_PRINT_EPT_BREAKPOINT_LOG_HEADER,
        CMD_PRINT_EPT_BREAKPOINT_LOG_HEADER_SHORT);
    CmdpPrintAlignedCommandName(
        CMD_PRINT_EPT_BREAKPOINT_LOG_ELEMENTS,
        CMD_PRINT_EPT_BREAKPOINT_LOG_ELEMENTS_SHORT);
#endif

    return TRUE;
}


//=============================================================================
// Process Commands
//=============================================================================
#define GET_PROCESS_ID_ARGC 2

static PCSTR g_GetProcessIdUsageText = "Usage: GetProcessId process_id";

static PCSTR g_GetProcessIdExtInfoText =
R"(Usage: GetProcessId process_name

    Short Name
        procid

    Summary
        Lookup process ids by process name.

    Parameters
        process_name (string)
            The target process name including file extension.

    Example
        procid calc.exe)";

_Use_decl_annotations_
BOOL
CmdGetProcessId(
    const std::vector<std::string>& ArgTokens
)
{
    PCSTR ProcessName = NULL;
    std::vector<ULONG_PTR> ProcessIds;
    BOOL status = TRUE;

    if (GET_PROCESS_ID_ARGC != ArgTokens.size())
    {
        CmdpPrintUsageText(
            CMD_GET_PROCESS_ID,
            CMD_GET_PROCESS_ID_SHORT,
            g_GetProcessIdUsageText);
        status = FALSE;
        goto exit;
    }

    ProcessName = ArgTokens[1].data();

    status = PsLookupProcessIdByName(ProcessName, ProcessIds);
    if (!status)
    {
        goto exit;
    }

    if (!ProcessIds.size())
    {
        ERR_PRINT("Process not found.");
        status = FALSE;
        goto exit;
    }

    for (SIZE_T i = 0; i < ProcessIds.size(); ++i)
    {
        INF_PRINT("    %5Iu", ProcessIds[i]);
    }

exit:
    return status;
}


#define GET_PROCESS_INFORMATION_ARGC 2

static PCSTR g_GetProcessInformationUsageText =
    "Usage: GetProcessInformation process_id";

static PCSTR g_GetProcessInformationExtInfoText =
R"(Usage: GetProcessInformation process_id

    Short Name
        procinfo

    Summary
        Query general information for the specified process.

    Parameters
        process_id (decimal)
            The target process id.)";

_Use_decl_annotations_
BOOL
CmdGetProcessInformation(
    const std::vector<std::string>& ArgTokens
)
{
    ULONG_PTR ProcessId = 0;
    VIVIENNE_PROCESS_INFORMATION ProcessInfo = {};
    BOOL status = TRUE;

    if (GET_PROCESS_INFORMATION_ARGC != ArgTokens.size())
    {
        CmdpPrintUsageText(
            CMD_GET_PROCESS_INFORMATION,
            CMD_GET_PROCESS_INFORMATION_SHORT,
            g_GetProcessInformationUsageText);
        status = FALSE;
        goto exit;
    }

    status = ParseProcessIdToken(ArgTokens[1], &ProcessId);
    if (!status)
    {
        goto exit;
    }

    status = PsGetProcessInformation(ProcessId, &ProcessInfo);
    if (!status)
    {
        goto exit;
    }

    INF_PRINT("Process Information:");
    INF_PRINT("    BaseAddress: %p", ProcessInfo.BaseAddress);

exit:
    return status;
}


#if defined(CFG_BPM_HARDWARE_BREAKPOINT_MANAGER)
//=============================================================================
// Hardware Breakpoint Commands
//=============================================================================

//
// CmdQuerySystemDebugState
//
// Query the breakpoint manager's debug register state for all processors.
//
_Use_decl_annotations_
BOOL
CmdQuerySystemDebugState(
    const std::vector<std::string>& ArgTokens
)
{
    PSYSTEM_DEBUG_STATE pSystemDebugState = NULL;
    ULONG cbSystemDebugState = NULL;
    ULONG RequiredSize = 0;
    PDEBUG_REGISTER_STATE pDebugRegisterState = NULL;
    BOOL status = TRUE;

    UNREFERENCED_PARAMETER(ArgTokens);

    //
    // Initial allocation size.
    //
    cbSystemDebugState = sizeof(*pSystemDebugState);

    pSystemDebugState = (PSYSTEM_DEBUG_STATE)HeapAlloc(
        GetProcessHeap(),
        HEAP_ZERO_MEMORY,
        cbSystemDebugState);
    if (!pSystemDebugState)
    {
        ERR_PRINT("Out of memory.");
        status = FALSE;
        goto exit;
    }

    //
    // Multi-processor systems will fail the initial query to obtain the
    //  required struct size.
    //
    if (!VivienneIoQuerySystemDebugState(pSystemDebugState, cbSystemDebugState))
    {
        RequiredSize = pSystemDebugState->Size;

        status = HeapFree(GetProcessHeap(), 0, pSystemDebugState);
        if (!status)
        {
            ERR_PRINT("HeapFree failed: %u", GetLastError());
            goto exit;
        }

        pSystemDebugState = (PSYSTEM_DEBUG_STATE)HeapAlloc(
            GetProcessHeap(),
            HEAP_ZERO_MEMORY,
            RequiredSize);
        if (!pSystemDebugState)
        {
            ERR_PRINT("Out of memory.");
            status = FALSE;
            goto exit;
        }

        status =
            VivienneIoQuerySystemDebugState(pSystemDebugState, RequiredSize);
        if (!status)
        {
            ERR_PRINT(
                "VivienneIoQuerySystemDebugState failed twice: %u",
                GetLastError());
            goto exit;
        }
    }

    //
    // Print debug register state for all processors.
    //
    for (ULONG i = 0; i < pSystemDebugState->NumberOfProcessors; ++i)
    {
        INF_PRINT("Processor %u:", i);

        pDebugRegisterState =
            pSystemDebugState->Processors[i].DebugRegisters;

        for (ULONG j = 0;
            j < ARRAYSIZE(pSystemDebugState->Processors->DebugRegisters);
            ++j)
        {
            INF_PRINT(
                "    Dr%u: pid= %04Iu addr= 0x%016IX type= %d size= %d",
                j,
                pDebugRegisterState[j].ProcessId,
                pDebugRegisterState[j].Address,
                pDebugRegisterState[j].Type,
                pDebugRegisterState[j].Size);
        }
    }

exit:
    if (pSystemDebugState)
    {
        VERIFY(HeapFree(GetProcessHeap(), 0, pSystemDebugState));
    }

    return status;
}


//
// CmdSetHardwareBreakpoint
//
// Install a hardware breakpoint on all processors.
//
// Whenever the breakpoint condition is triggered, the contents of the general
//  purpose registers are logged to the VM log file.
//
#define SETHARDWAREBREAKPOINT_ARGC 5
#define SETHARDWAREBREAKPOINT_USAGE                                         \
    "Usage: " CMD_SET_HARDWARE_BREAKPOINT " index pid access|size address\n"\
    "    Short Name\n"                                                      \
    "        shb\n"                                                         \
    "    Summary\n"                                                         \
    "        Install a hardware breakpoint on all processors.\n"            \
    "    Parameters\n"                                                      \
    "        index:     [0-3]        debug address register index\n"        \
    "        pid:       #            an active process id (integer)\n"      \
    "        access:    'e,r,w'      execution, read, write\n"              \
    "        size:      '1,2,4,8'    byte, word, dword, qword\n"            \
    "        address:   #            valid user-mode address (hex)\n"       \
    "    Example\n"                                                         \
    "        " CMD_SET_HARDWARE_BREAKPOINT_SHORT " 0 1002 e1 77701650\n"

_Use_decl_annotations_
BOOL
CmdSetHardwareBreakpoint(
    const std::vector<std::string>& ArgTokens
)
{
    ULONG DebugRegisterIndex = 0;
    ULONG_PTR ProcessId = 0;
    ULONG_PTR Address = 0;
    HWBP_TYPE Type = {};
    HWBP_SIZE Size = {};
    BOOL status = TRUE;

    if (SETHARDWAREBREAKPOINT_ARGC != ArgTokens.size())
    {
        LogPrintDirect(SETHARDWAREBREAKPOINT_USAGE);
        status = FALSE;
        goto exit;
    }

    status = ParseDebugRegisterIndexToken(ArgTokens[1], &DebugRegisterIndex);
    if (!status)
    {
        goto exit;
    }

    status = ParseProcessIdToken(ArgTokens[2], &ProcessId);
    if (!status)
    {
        goto exit;
    }

    status = ParseAddressToken(ArgTokens[4], &Address);
    if (!status)
    {
        goto exit;
    }

    status =
        ParseHardwareBreakpointAccessSizeToken(ArgTokens[3], &Type, &Size);
    if (!status)
    {
        goto exit;
    }

    status = IsBreakpointAddressAligned(Address, Type, Size);
    if (!status)
    {
        goto exit;
    }

    status = VivienneIoSetHardwareBreakpoint(
        ProcessId,
        DebugRegisterIndex,
        Address,
        Type,
        Size);
    if (!status)
    {
        ERR_PRINT("VivienneIoSetHardwareBreakpoint failed: %u",
            GetLastError());
        goto exit;
    }

exit:
    return status;
}


//
// CmdClearHardwareBreakpoint
//
// Uninstall a hardware breakpoint on all processors.
//
#define CLEARHARDWAREBREAKPOINT_ARGC 2
#define CLEARHARDWAREBREAKPOINT_USAGE                               \
    "Usage: " CMD_CLEAR_HARDWARE_BREAKPOINT " index\n"              \
    "    Short Name\n"                                              \
    "        chb\n"                                                 \
    "    Summary\n"                                                 \
    "        Clear a hardware breakpoint on all processors.\n"      \
    "    Parameters\n"                                              \
    "        index:     [0-3]        debug address register index\n"\
    "    Example\n"                                                 \
    "        " CMD_CLEAR_HARDWARE_BREAKPOINT_SHORT " 0\n"

_Use_decl_annotations_
BOOL
CmdClearHardwareBreakpoint(
    const std::vector<std::string>& ArgTokens
)
{
    ULONG DebugRegisterIndex = 0;
    BOOL status = TRUE;

    if (CLEARHARDWAREBREAKPOINT_ARGC != ArgTokens.size())
    {
        LogPrintDirect(CLEARHARDWAREBREAKPOINT_USAGE);
        status = FALSE;
        goto exit;
    }

    status = ParseDebugRegisterIndexToken(ArgTokens[1], &DebugRegisterIndex);
    if (!status)
    {
        goto exit;
    }

    status = VivienneIoClearHardwareBreakpoint(DebugRegisterIndex);
    if (!status)
    {
        ERR_PRINT("VivienneIoClearHardwareBreakpoint failed: %u",
            GetLastError());
        goto exit;
    }

exit:
    return status;
}


//=============================================================================
//  Capture Execution Context Commands
//=============================================================================

//
// CmdCaptureRegisterValues
//
// Install a hardware breakpoint on all processors which, when triggered, will
//  examine the contents of the target register and record all unique values.
//  On success, the list of unique values is printed to stdout.
//
#define CEC_REGISTER_ARGC 7
#define CEC_REGISTER_USAGE \
    "Usage: " CMD_CEC_REGISTER " index pid access|size address register"    \
    " duration\n"                                                           \
    "    Short Name\n"                                                      \
    "        cecr\n"                                                        \
    "    Summary\n"                                                         \
    "        Capture unique register context at a target address.\n"        \
    "    Parameters\n"                                                      \
    "        index:     [0-3]           debug address register index\n"     \
    "        pid:       #               an active process id (integer)\n"   \
    "        access:    'e,r,w'         execution, read, write\n"           \
    "        size:      '1,2,4,8'       byte, word, dword, qword\n"         \
    "        address:   #               valid user-mode address (hex)\n"    \
    "        register:  'rip,rax,etc'   the target register\n"              \
    "        duration:  #               capture duration in milliseconds (integer)\n" \
    "    Example\n"                                                         \
    "        " CMD_CEC_REGISTER_SHORT " 0 1002 e1 77701650 rbx 5000\n"
#define CEC_REGISTER_BUFFER_SIZE (PAGE_SIZE * 2)

_Use_decl_annotations_
BOOL
CmdCaptureRegisterValues(
    const std::vector<std::string>& ArgTokens
)
{
    ULONG DebugRegisterIndex = 0;
    ULONG_PTR ProcessId = 0;
    ULONG_PTR Address = 0;
    HWBP_TYPE Type = {};
    HWBP_SIZE Size = {};
    X64_REGISTER Register = {};
    ULONG DurationInMilliseconds = 0;
    PCEC_REGISTER_VALUES pValuesCtx = NULL;
    BOOL status = TRUE;

    if (CEC_REGISTER_ARGC != ArgTokens.size())
    {
        LogPrintDirect(CEC_REGISTER_USAGE);
        status = FALSE;
        goto exit;
    }

    status = ParseDebugRegisterIndexToken(ArgTokens[1], &DebugRegisterIndex);
    if (!status)
    {
        goto exit;
    }

    status = ParseProcessIdToken(ArgTokens[2], &ProcessId);
    if (!status)
    {
        goto exit;
    }

    status =
        ParseHardwareBreakpointAccessSizeToken(ArgTokens[3], &Type, &Size);
    if (!status)
    {
        goto exit;
    }

    status = ParseAddressToken(ArgTokens[4], &Address);
    if (!status)
    {
        goto exit;
    }

    status = IsBreakpointAddressAligned(Address, Type, Size);
    if (!status)
    {
        goto exit;
    }

    status = ParseRegisterToken(ArgTokens[5], &Register);
    if (!status)
    {
        goto exit;
    }

    status =
        ParseUnsignedLongToken(ArgTokens[6], FALSE, &DurationInMilliseconds);
    if (!status)
    {
        goto exit;
    }

    //
    // Allocate the captured context buffer.
    //
    pValuesCtx = (PCEC_REGISTER_VALUES)HeapAlloc(
        GetProcessHeap(),
        HEAP_ZERO_MEMORY,
        CEC_REGISTER_BUFFER_SIZE);
    if (!pValuesCtx)
    {
        ERR_PRINT("HeapAlloc failed: %u", GetLastError());
        status = FALSE;
        goto exit;
    }

    status = VivienneIoCaptureRegisterValues(
        ProcessId,
        DebugRegisterIndex,
        Address,
        Type,
        Size,
        Register,
        DurationInMilliseconds,
        pValuesCtx,
        CEC_REGISTER_BUFFER_SIZE);
    if (!status)
    {
        ERR_PRINT("VivienneIoCaptureRegisterValues failed: %u",
            GetLastError());
        goto exit;
    }

    //
    // Log results.
    //
    INF_PRINT("Found %u unique values:", pValuesCtx->NumberOfValues);

    for (ULONG i = 0; i < pValuesCtx->NumberOfValues; ++i)
    {
        INF_PRINT("    %u: 0x%IX", i, pValuesCtx->Values[i]);
    }

exit:
    if (pValuesCtx)
    {
        VERIFY(HeapFree(GetProcessHeap(), 0, pValuesCtx));
    }

    return status;
}


//
// CmdCaptureMemoryValues
//
// Install a hardware breakpoint on all processors which, when triggered, will
//  record all unique values at the memory address defined by the memory
//  description parameter.
//
#define CEC_MEMORY_ARGC 8
#define CEC_MEMORY_BUFFER_SIZE (PAGE_SIZE * 2)

static PCSTR g_CecmUsageText =
R"(Usage: CaptureExecCtxMemory index pid access|size bp_address mem_type mem_expression duration

    Short Name
        cecm

    Summary
        Capture unique values of type mem_type at the memory address described
        by mem_expression.

        This command sets a hardware breakpoint specified by 'access', 'size',
        and 'bp_address' using the debug address register specified by 'index'.
        The breakpoint callback calculates the effective address by evaluating
        the memory expression (mem_expression) using the guest context. A value
        of type 'mem_type' is read from the effective address. Unique values
        are stored to the user data buffer.

    Parameters
        index
            The debug address register index used for the hardware breakpoint.

        pid (decimal)
            The target process id.

        access
            The hardware breakpoint type (WinDbg format):
                'e'     execute
                'r'     read
                'w'     write

        size
            The hardware breakpoint size (WinDbg format):
                '1'     byte
                '2'     word
                '4'     dword
                '8'     qword

        address (hex, '0x' prefix optional)
            The hardware breakpoint address.

        mem_type
            The data type used to interpret the effective address:
                'b'     byte
                'w'     word
                'd'     dword
                'q'     qword
                'f'     float
                'o'     double

        mem_expression
            An absolute virtual address or a valid indirect address in assembly
            language format (without spaces). Indirect addresses have the form:

                base_register + index_register * scale_factor +- displacement

            Examples of valid indirect address expressions:
                0x140000
                140000
                rax
                rax+FF
                rax+rdi
                rax+rdi*8
                rax+rdi*8-20
                rdi*8+20

        duration
            The amount of time in milliseconds in which the hardware breakpoint
            is installed to sample the effective address.

    Example
        The target instruction:

            0x1400000   mov     rcx, [rcx+rax*8]    ; an array of floats

        The following command captures a float array element whenever the
        instruction at address 0x140000 is executed:

            cecm 0 123 e1 1400000 f rcx+rax*8 5000
)";

_Use_decl_annotations_
BOOL
CmdCaptureMemoryValues(
    const std::vector<std::string>& ArgTokens
)
{
    ULONG DebugRegisterIndex = 0;
    ULONG_PTR ProcessId = 0;
    ULONG_PTR Address = 0;
    HWBP_TYPE Type = {};
    HWBP_SIZE Size = {};
    MEMORY_DATA_TYPE MemoryDataType = {};
    CEC_MEMORY_DESCRIPTION MemoryDescription = {};
    ULONG DurationInMilliseconds = 0;
    PCEC_MEMORY_VALUES pValuesCtx = NULL;
    PMEMORY_DATA_VALUE pMemoryDataValue = NULL;
    BOOL status = TRUE;

    if (CEC_MEMORY_ARGC != ArgTokens.size())
    {
        LogPrintDirect(g_CecmUsageText);
        status = FALSE;
        goto exit;
    }

    status = ParseDebugRegisterIndexToken(ArgTokens[1], &DebugRegisterIndex);
    if (!status)
    {
        goto exit;
    }

    status = ParseProcessIdToken(ArgTokens[2], &ProcessId);
    if (!status)
    {
        goto exit;
    }

    status =
        ParseHardwareBreakpointAccessSizeToken(ArgTokens[3], &Type, &Size);
    if (!status)
    {
        goto exit;
    }

    status = ParseAddressToken(ArgTokens[4], &Address);
    if (!status)
    {
        goto exit;
    }

    status = IsBreakpointAddressAligned(Address, Type, Size);
    if (!status)
    {
        goto exit;
    }

    status = ParseMemoryDataTypeToken(ArgTokens[5], &MemoryDataType);
    if (!status)
    {
        goto exit;
    }

    status = ParseMemoryDescriptionToken(
        ArgTokens[6],
        MemoryDataType,
        &MemoryDescription);
    if (!status)
    {
        goto exit;
    }

    status =
        ParseUnsignedLongToken(ArgTokens[7], FALSE, &DurationInMilliseconds);
    if (!status)
    {
        goto exit;
    }

    //
    // Allocate the captured context buffer.
    //
    pValuesCtx = (PCEC_MEMORY_VALUES)HeapAlloc(
        GetProcessHeap(),
        HEAP_ZERO_MEMORY,
        CEC_MEMORY_BUFFER_SIZE);
    if (!pValuesCtx)
    {
        ERR_PRINT("HeapAlloc failed: %u", GetLastError());
        status = FALSE;
        goto exit;
    }

    status = VivienneIoCaptureMemoryValues(
        ProcessId,
        DebugRegisterIndex,
        Address,
        Type,
        Size,
        &MemoryDescription,
        DurationInMilliseconds,
        pValuesCtx,
        CEC_MEMORY_BUFFER_SIZE);
    if (!status)
    {
        ERR_PRINT("VivienneIoCaptureMemoryValues failed: %u",
            GetLastError());
        goto exit;
    }

    //
    // Log results.
    //
    INF_PRINT("Found %u unique values:", pValuesCtx->NumberOfValues);

    //
    // TODO FUTURE Each values buffer entry is the same size as a ULONG_PTR to
    //  to reduce complexity.
    //
    for (ULONG i = 0; i < pValuesCtx->NumberOfValues; ++i)
    {
        pMemoryDataValue = (PMEMORY_DATA_VALUE)&pValuesCtx->Values[i];

        switch (pValuesCtx->DataType)
        {
            case MDT_BYTE:
                INF_PRINT("    %u: 0x%hhX", i, pMemoryDataValue->Byte);
                break;
            case MDT_WORD:
                INF_PRINT("    %u: 0x%hX", i, pMemoryDataValue->Word);
                break;
            case MDT_DWORD:
                INF_PRINT("    %u: 0x%X", i, pMemoryDataValue->Dword);
                break;
            case MDT_QWORD:
                INF_PRINT("    %u: 0x%IX", i, pMemoryDataValue->Qword);
                break;
            case MDT_FLOAT:
                INF_PRINT("    %u: %f", i, pMemoryDataValue->Float);
                break;
            case MDT_DOUBLE:
                INF_PRINT("    %u: %f", i, pMemoryDataValue->Double);
                break;
            default:
                ERR_PRINT(
                    "Unexpected memory data type: %u",
                    pValuesCtx->DataType);
                status = FALSE;
                goto exit;
        }
    }

    //
    // Log statistics.
    //
    INF_PRINT("Statistics:");
    INF_PRINT("    %Iu hits.", pValuesCtx->Statistics.HitCount);

    if (pValuesCtx->Statistics.SkipCount)
    {
        INF_PRINT("    %Iu skips.",
            pValuesCtx->Statistics.SkipCount);
    }

    if (pValuesCtx->Statistics.InvalidPteErrors)
    {
        INF_PRINT("    %Iu invalid pte errors.",
            pValuesCtx->Statistics.InvalidPteErrors);
    }

    if (pValuesCtx->Statistics.UntouchedPageErrors)
    {
        INF_PRINT("    %Iu untouched page errors.",
            pValuesCtx->Statistics.UntouchedPageErrors);
    }

    if (pValuesCtx->Statistics.SpanningAddressErrors)
    {
        INF_PRINT("    %Iu spanning address errors.",
            pValuesCtx->Statistics.SpanningAddressErrors);
    }

    if (pValuesCtx->Statistics.SystemAddressErrors)
    {
        INF_PRINT("    %Iu system address errors.",
            pValuesCtx->Statistics.SystemAddressErrors);
    }

    if (pValuesCtx->Statistics.ValidationErrors)
    {
        INF_PRINT("    %Iu validation errors.",
            pValuesCtx->Statistics.ValidationErrors);
    }

exit:
    if (pValuesCtx)
    {
        VERIFY(HeapFree(GetProcessHeap(), 0, pValuesCtx));
    }

    return status;
}
#endif


#if defined(CFG_BPM_EPT_BREAKPOINT_MANAGER)
//=============================================================================
//  Ept Breakpoint Commands
//=============================================================================
#include <unordered_map>

//
// User mode bookkeeping for our ept breakpoint handles.
//
static std::unordered_map<HANDLE, PEPT_BREAKPOINT_LOG> g_EptBreakpoints = {};


_Success_(return != FALSE)
_Check_return_
BOOL
CmdpInsertEptBreakpointLog(
    _In_ HANDLE hLog,
    _In_ PEPT_BREAKPOINT_LOG pLog
)
{
    std::pair<std::unordered_map<HANDLE, PEPT_BREAKPOINT_LOG>::iterator, bool> Entry = {};
    BOOL status = TRUE;

    try
    {
        Entry = g_EptBreakpoints.emplace(hLog, pLog);
        if (!Entry.second)
        {
            ERR_PRINT(
                "Failed to insert ept breakpoint log. (Duplicate log handle)");
            status = FALSE;
            goto exit;
        }
    }
    catch (const std::bad_alloc&)
    {
        ERR_PRINT("Failed to insert ept breakpoint log. (Exception)");
        status = FALSE;
        goto exit;
    }

exit:
    return status;
}


_Success_(return != FALSE)
_Check_return_
BOOL
CmdpRemoveEptBreakpointLog(
    _In_ HANDLE hLog
)
{
    BOOL status = TRUE;

    if (1 != g_EptBreakpoints.erase(hLog))
    {
        ERR_PRINT("Failed to remove ept breakpoint log.");
        status = FALSE;
        goto exit;
    }

exit:
    return status;
}


_Check_return_
PEPT_BREAKPOINT_LOG
CmdpLookupEptBreakpointLog(
    _In_ HANDLE hLog
)
{
    std::unordered_map<HANDLE, PEPT_BREAKPOINT_LOG>::iterator pEntry = {};
    PEPT_BREAKPOINT_LOG pLog = NULL;

    pEntry = g_EptBreakpoints.find(hLog);

    if (pEntry == g_EptBreakpoints.end())
    {
        ERR_PRINT("Failed to find ept breakpoint log.");
        goto exit;
    }

    pLog = pEntry->second;

exit:
    return pLog;
}


#define QUERY_EPT_BREAKPOINT_INFORMATION_ARGC   1

static PCSTR g_QueryEptBreakpointInformationUsageText =
    "Usage: QueryEptBpInfo";

static PCSTR g_QueryEptBreakpointInformationExtInfoText =
R"(Usage: QueryEptBpInfo

    Short Name
        qebi

    Summary
        Print breakpoint information for each ept breakpoint on the system.
        Print general statistics about the ept breakpoint manager.)";

_Use_decl_annotations_
BOOL
CmdQueryEptBreakpointInformation(
    const std::vector<std::string>& ArgTokens
)
{
    PEPT_BREAKPOINT_INFORMATION pEptBreakpointInfo = NULL;
    BOOL status = TRUE;

    if (QUERY_EPT_BREAKPOINT_INFORMATION_ARGC != ArgTokens.size())
    {
        CmdpPrintUsageText(
            CMD_QUERY_EPT_BREAKPOINT_INFORMATION,
            CMD_QUERY_EPT_BREAKPOINT_INFORMATION_SHORT,
            g_QueryEptBreakpointInformationUsageText);
        status = FALSE;
        goto exit;
    }

    status = EbpQueryEptBreakpointInformation(&pEptBreakpointInfo, NULL);
    if (!status)
    {
        goto exit;
    }

    EbpPrintEptBreakpointInformation(pEptBreakpointInfo);

exit:
    if (pEptBreakpointInfo)
    {
        VERIFY(MemFreeHeap(pEptBreakpointInfo));
    }

    return status;
}


#define SET_EPT_BREAKPOINT_BASIC_ARGC 6

static PCSTR g_SetEptBreakpointBasicUsageText =
    "Usage: SetEptBpBasic pid access|size address log_size make_page_resident";

static PCSTR g_SetEptBreakpointExtInfoText =
R"(Usage: SetEptBpBasic pid access|size address log_size make_page_resident

    Short Name
        sebb

    Summary
        Set an ept breakpoint in the target process context. The corresponding
        breakpoint log contains 'basic' elements. Each element contains the
        following fields:

            TriggerAddress - Unique address of the instruction that triggered
                the breakpoint condition.

            HitCount - Number of times this element triggered the breakpoint
                condition.

    Parameters
        pid (decimal)
            The target process id.

        access|size (WinDbg hardware breakpoint syntax)
            access (one character)
                The ept breakpoint type:

                    'e'     execute
                    'r'     read
                    'w'     write

            size (one decimal integer)
                The ept breakpoint size:

                    '1'     byte
                    '2'     word
                    '4'     dword
                    '8'     qword

            NOTE Execution breakpoints must be '1' byte size.

        address (hex, '0x' prefix optional)
            The target virtual address.

        log_size (hex, '0x' prefix optional)
            The size in bytes of the returned log. i.e., How many elements the
            log can store.

        make_page_resident (decimal)
            If non-zero then the physical page that contains the target virtual
            address is made resident if it is currently paged out.

    Return Value
        A handle (decimal) to the breakpoint log.

    Remarks
        Ept breakpoints are in one of the following states at any given time:

            Installing
            Active
            Inactive

        If an ept breakpoint is in the 'installing' state then it is currently
        being installed on all processors. The breakpoint becomes 'active' as
        soon as installation succeeds.

        The breakpoint log for an 'active' ept breakpoint is valid, readable,
        and the breakpoint log elements are updated by the ept breakpoint
        manager.

        Ept breakpoints become 'inactive' when their target process terminates,
        or they are manually disabled by calling 'DisableEptBp'. The breakpoint
        log for an 'inactive' ept breakpoint is valid and readable, but its
        breakpoint log elements are no longer updated by the ept breakpoint
        manager. Inactive ept breakpoints are uninstalled from all processors.
        Inactive breakpoints remain in the 'inactive' state until they are
        manually cleared by calling 'ClearEptBp' or the VivienneCL session
        ends.

        The 'BreakpointStatus' field of a breakpoint log header contains the
        current state of its corresponding ept breakpoint.

        Ept breakpoints can have a significant performance cost because an ept
        violation occurs whenever the guest accesses the target page in a
        manner which matches the ept breakpoint condition. e.g., If we set an
        execute ept breakpoint in an an address in a page, then the guest will
        experience an ept violation VM exit whenever it executes an instruction
        inside that page. Users should disable ept breakpoints when they are
        no longer required.

    Example
        Set an execution breakpoint at 0x70000 in process 314, use 0x1000 bytes
        for the breakpoint log, and make the physical page resident:

            sebb 314 e1 70000 1000 1
)";

_Use_decl_annotations_
BOOL
CmdSetEptBreakpointBasic(
    const std::vector<std::string>& ArgTokens
)
{
    ULONG_PTR ProcessId = 0;
    ULONG_PTR Address = 0;
    EPT_BREAKPOINT_TYPE BreakpointType = {};
    EPT_BREAKPOINT_SIZE BreakpointSize = {};
    SIZE_T cbLog = 0;
    ULONG MakePageResidentValue = 0;
    BOOLEAN fMakePageResident = FALSE;
    HANDLE hLog = NULL;
    PEPT_BREAKPOINT_LOG pLog = NULL;
    BOOL status = TRUE;

    if (SET_EPT_BREAKPOINT_BASIC_ARGC != ArgTokens.size())
    {
        CmdpPrintUsageText(
            CMD_SET_EPT_BREAKPOINT_BASIC,
            CMD_SET_EPT_BREAKPOINT_BASIC_SHORT,
            g_SetEptBreakpointBasicUsageText);
        status = FALSE;
        goto exit;
    }

    status = ParseProcessIdToken(ArgTokens[1], &ProcessId);
    if (!status)
    {
        goto exit;
    }

    status = ParseEptBreakpointAccessSizeToken(
        ArgTokens[2],
        &BreakpointType,
        &BreakpointSize);
    if (!status)
    {
        goto exit;
    }

    status = ParseAddressToken(ArgTokens[3], &Address);
    if (!status)
    {
        goto exit;
    }

    status = ParseUnsignedLongLongToken(ArgTokens[4], TRUE, &cbLog);
    if (!status)
    {
        ERR_PRINT("Invalid log_size.");
        goto exit;
    }

    status =
        ParseUnsignedLongToken(ArgTokens[5], FALSE, &MakePageResidentValue);
    if (!status)
    {
        ERR_PRINT("Invalid make_page_resident.");
        goto exit;
    }

    if (MakePageResidentValue)
    {
        fMakePageResident = TRUE;
    }
    else
    {
        fMakePageResident = FALSE;
    }

    status = EbpSetEptBreakpointBasic(
        ProcessId,
        Address,
        BreakpointType,
        BreakpointSize,
        cbLog,
        fMakePageResident,
        &hLog,
        &pLog);
    if (!status)
    {
        goto exit;
    }

    status = CmdpInsertEptBreakpointLog(hLog, pLog);
    if (!status)
    {
        goto exit;
    }

    INF_PRINT("Log handle: %Iu", hLog);

exit:
    return status;
}


#define SET_EPT_BREAKPOINT_GENERAL_REGISTER_CONTEXT_ARGC 6

static PCSTR g_SetEptBreakpointGeneralRegisterContextUsageText =
"Usage: SetEptBpRegisters pid access|size address log_size make_page_resident";

static PCSTR g_SetEptBreakpointGeneralRegisterContextExtInfoText =
R"(Usage: SetEptBpRegisters pid access|size address log_size make_page_resident

    Short Name
        sebg

    Summary
        Set an ept breakpoint in the target process context. The corresponding
        breakpoint log contains 'general register context' elements. Each
        element contains the following fields:

            TriggerAddress - Non-unique address of the instruction that
                triggered the breakpoint condition.

            Registers - The values in the general purpose registers when the
                breakpoint condition was triggered.

            Flags - The value in the RFLAGS register when the breakpoint
                condition was triggered.

    Parameters
        pid (decimal)
            The target process id.

        access|size (WinDbg hardware breakpoint syntax)
            access (one character)
                The ept breakpoint type:

                    'e'     execute
                    'r'     read
                    'w'     write

            size (one decimal integer)
                The ept breakpoint size:

                    '1'     byte
                    '2'     word
                    '4'     dword
                    '8'     qword

            NOTE Execution breakpoints must be '1' byte size.

        address (hex, '0x' prefix optional)
            The target virtual address.

        log_size (hex, '0x' prefix optional)
            The size in bytes of the returned log. i.e., How many elements the
            log can store.

        make_page_resident (decimal)
            If non-zero then the physical page that contains the target virtual
            address is made resident if it is currently paged out.

    Return Value
        A handle (decimal) to the breakpoint log.

    Remarks
        Ept breakpoints are in one of the following states at any given time:

            Installing
            Active
            Inactive

        If an ept breakpoint is in the 'installing' state then it is currently
        being installed on all processors. The breakpoint becomes 'active' as
        soon as installation succeeds.

        The breakpoint log for an 'active' ept breakpoint is valid, readable,
        and the breakpoint log elements are updated by the ept breakpoint
        manager.

        Ept breakpoints become 'inactive' when their target process terminates,
        or they are manually disabled by calling 'DisableEptBp'. The breakpoint
        log for an 'inactive' ept breakpoint is valid and readable, but its
        breakpoint log elements are no longer updated by the ept breakpoint
        manager. Inactive ept breakpoints are uninstalled from all processors.
        Inactive breakpoints remain in the 'inactive' state until they are
        manually cleared by calling 'ClearEptBp' or the VivienneCL session
        ends.

        The 'BreakpointStatus' field of a breakpoint log header contains the
        current state of its corresponding ept breakpoint.

        Ept breakpoints can have a significant performance cost because an ept
        violation occurs whenever the guest accesses the target page in a
        manner which matches the ept breakpoint condition. e.g., If we set an
        execute ept breakpoint in an an address in a page, then the guest will
        experience an ept violation VM exit whenever it executes an instruction
        inside that page. Users should disable ept breakpoints when they are
        no longer required.

    Example
        Set a write-access breakpoint for a word-sized value at 0x141800 in
        process 2000, use 0x20000 bytes for the breakpoint log, and do not make
        the physical page resident:

            sebg 2000 w2 141800 20000 0
)";

_Use_decl_annotations_
BOOL
CmdSetEptBreakpointGeneralRegisterContext(
    const std::vector<std::string>& ArgTokens
)
{
    ULONG_PTR ProcessId = 0;
    ULONG_PTR Address = 0;
    EPT_BREAKPOINT_TYPE BreakpointType = {};
    EPT_BREAKPOINT_SIZE BreakpointSize = {};
    SIZE_T cbLog = 0;
    ULONG MakePageResidentValue = 0;
    BOOLEAN fMakePageResident = FALSE;
    HANDLE hLog = NULL;
    PEPT_BREAKPOINT_LOG pLog = NULL;
    BOOL status = TRUE;

    if (SET_EPT_BREAKPOINT_GENERAL_REGISTER_CONTEXT_ARGC != ArgTokens.size())
    {
        CmdpPrintUsageText(
            CMD_SET_EPT_BREAKPOINT_GENERAL_REGISTER_CONTEXT,
            CMD_SET_EPT_BREAKPOINT_GENERAL_REGISTER_CONTEXT_SHORT,
            g_SetEptBreakpointGeneralRegisterContextUsageText);
        status = FALSE;
        goto exit;
    }

    status = ParseProcessIdToken(ArgTokens[1], &ProcessId);
    if (!status)
    {
        goto exit;
    }

    status = ParseEptBreakpointAccessSizeToken(
        ArgTokens[2],
        &BreakpointType,
        &BreakpointSize);
    if (!status)
    {
        goto exit;
    }

    status = ParseAddressToken(ArgTokens[3], &Address);
    if (!status)
    {
        goto exit;
    }

    status = ParseUnsignedLongLongToken(ArgTokens[4], TRUE, &cbLog);
    if (!status)
    {
        ERR_PRINT("Invalid log_size.");
        goto exit;
    }

    status =
        ParseUnsignedLongToken(ArgTokens[5], FALSE, &MakePageResidentValue);
    if (!status)
    {
        ERR_PRINT("Invalid make_page_resident.");
        goto exit;
    }

    if (MakePageResidentValue)
    {
        fMakePageResident = TRUE;
    }
    else
    {
        fMakePageResident = FALSE;
    }

    status = EbpSetEptBreakpointGeneralRegisterContext(
        ProcessId,
        Address,
        BreakpointType,
        BreakpointSize,
        cbLog,
        fMakePageResident,
        &hLog,
        &pLog);
    if (!status)
    {
        goto exit;
    }

    status = CmdpInsertEptBreakpointLog(hLog, pLog);
    if (!status)
    {
        goto exit;
    }

    INF_PRINT("Log handle: %Iu", hLog);

exit:
    return status;
}


#define SET_EPT_BREAKPOINT_KEYED_REGISTER_CONTEXT_ARGC 7

static PCSTR g_SetEptBreakpointKeyedRegisterContextUsageText =
"Usage: SetEptBpKeyed pid access|size address log_size make_page_resident register_key";

static PCSTR g_SetEptBreakpointKeyedRegisterContextExtInfoText =
R"(Usage: SetEptBpKeyed pid access|size address log_size make_page_resident register_key

    Short Name
        sebk

    Summary
        Set an ept breakpoint in the target process context. The corresponding
        breakpoint log contains 'keyed register context' elements. Each
        element contains the following fields:

            KeyValue - The unique value of the register specified in the
                'RegisterKey' field of the log header.

            TriggerAddress - Address of the instruction that triggered the
                breakpoint condition.

            HitCount - Number of times this element triggered the breakpoint
                condition.

            Registers - The values in the general purpose registers when the
                breakpoint condition was triggered.

            Flags - The value in the RFLAGS register when the breakpoint
                condition was triggered.

        The ept breakpoint manager updates the breakpoint log for unique values
        in the key register. e.g., If an ept breakpoint uses 'rax' for its
        register key, and the guest triggers the breakpoint condition twice
        with rax = 4, then only the first trigger event is recorded in the log.
        If the guest triggers the breakpoint condition again with rax = 5 then
        the log is updated because there is no element whose rax value is 5.

    Parameters
        pid (decimal)
            The target process id.

        access|size (WinDbg hardware breakpoint syntax)
            access (one character)
                The ept breakpoint type:

                    'e'     execute
                    'r'     read
                    'w'     write

            size (one decimal integer)
                The ept breakpoint size:

                    '1'     byte
                    '2'     word
                    '4'     dword
                    '8'     qword

            NOTE Execution breakpoints must be '1' byte size.

        address (hex, '0x' prefix optional)
            The target virtual address.

        log_size (hex, '0x' prefix optional)
            The size in bytes of the returned log. i.e., How many elements the
            log can store.

        make_page_resident (decimal)
            If non-zero then the physical page that contains the target virtual
            address is made resident if it is currently paged out.

        register_key (register string)
            Specify which register is used to determine uniqueness of a guest
            context when the breakpoint condition is triggered.

            e.g., If 'register_key' is 'rax' then each element in the
            breakpoint log will have a unique value in the rax register.

    Return Value
        A handle (decimal) to the breakpoint log.

    Remarks
        Ept breakpoints are in one of the following states at any given time:

            Installing
            Active
            Inactive

        If an ept breakpoint is in the 'installing' state then it is currently
        being installed on all processors. The breakpoint becomes 'active' as
        soon as installation succeeds.

        The breakpoint log for an 'active' ept breakpoint is valid, readable,
        and the breakpoint log elements are updated by the ept breakpoint
        manager.

        Ept breakpoints become 'inactive' when their target process terminates,
        or they are manually disabled by calling 'DisableEptBp'. The breakpoint
        log for an 'inactive' ept breakpoint is valid and readable, but its
        breakpoint log elements are no longer updated by the ept breakpoint
        manager. Inactive ept breakpoints are uninstalled from all processors.
        Inactive breakpoints remain in the 'inactive' state until they are
        manually cleared by calling 'ClearEptBp' or the VivienneCL session
        ends.

        The 'BreakpointStatus' field of a breakpoint log header contains the
        current state of its corresponding ept breakpoint.

        Ept breakpoints can have a significant performance cost because an ept
        violation occurs whenever the guest accesses the target page in a
        manner which matches the ept breakpoint condition. e.g., If we set an
        execute ept breakpoint in an an address in a page, then the guest will
        experience an ept violation VM exit whenever it executes an instruction
        inside that page. Users should disable ept breakpoints when they are
        no longer required.

    Example
        Set a read-access breakpoint for a qword-sized value at 0x21210 in
        process 5004, use 0x1000 bytes for the breakpoint log, and do not make
        the physical page resident:

            sebk 5004 a8 0x21210 0x1000 0
)";

_Use_decl_annotations_
BOOL
CmdSetEptBreakpointKeyedRegisterContext(
    const std::vector<std::string>& ArgTokens
)
{
    ULONG_PTR ProcessId = 0;
    ULONG_PTR Address = 0;
    EPT_BREAKPOINT_TYPE BreakpointType = {};
    EPT_BREAKPOINT_SIZE BreakpointSize = {};
    SIZE_T cbLog = 0;
    ULONG MakePageResidentValue = 0;
    BOOLEAN fMakePageResident = FALSE;
    X64_REGISTER RegisterKey = {};
    HANDLE hLog = NULL;
    PEPT_BREAKPOINT_LOG pLog = NULL;
    BOOL status = TRUE;

    if (SET_EPT_BREAKPOINT_KEYED_REGISTER_CONTEXT_ARGC != ArgTokens.size())
    {
        CmdpPrintUsageText(
            CMD_SET_EPT_BREAKPOINT_KEYED_REGISTER_CONTEXT,
            CMD_SET_EPT_BREAKPOINT_KEYED_REGISTER_CONTEXT_SHORT,
            g_SetEptBreakpointKeyedRegisterContextUsageText);
        status = FALSE;
        goto exit;
    }

    status = ParseProcessIdToken(ArgTokens[1], &ProcessId);
    if (!status)
    {
        goto exit;
    }

    status = ParseEptBreakpointAccessSizeToken(
        ArgTokens[2],
        &BreakpointType,
        &BreakpointSize);
    if (!status)
    {
        goto exit;
    }

    status = ParseAddressToken(ArgTokens[3], &Address);
    if (!status)
    {
        goto exit;
    }

    status = ParseUnsignedLongLongToken(ArgTokens[4], TRUE, &cbLog);
    if (!status)
    {
        ERR_PRINT("Invalid log_size.");
        goto exit;
    }

    status =
        ParseUnsignedLongToken(ArgTokens[5], FALSE, &MakePageResidentValue);
    if (!status)
    {
        ERR_PRINT("Invalid make_page_resident.");
        goto exit;
    }

    if (MakePageResidentValue)
    {
        fMakePageResident = TRUE;
    }
    else
    {
        fMakePageResident = FALSE;
    }

    status = ParseRegisterToken(ArgTokens[6], &RegisterKey);
    if (!status)
    {
        ERR_PRINT("Invalid register_key.");
        goto exit;
    }

    status = EbpSetEptBreakpointKeyedRegisterContext(
        ProcessId,
        Address,
        BreakpointType,
        BreakpointSize,
        cbLog,
        fMakePageResident,
        RegisterKey,
        &hLog,
        &pLog);
    if (!status)
    {
        goto exit;
    }

    status = CmdpInsertEptBreakpointLog(hLog, pLog);
    if (!status)
    {
        goto exit;
    }

    INF_PRINT("Log handle: %Iu", hLog);

exit:
    return status;
}


#define DISABLE_EPT_BREAKPOINT_ARGC 2

static PCSTR g_DisableEptBreakpointUsageText =
    "Usage: DisableEptBp log_handle";

static PCSTR g_DisableEptBreakpointExtInfoText =
R"(Usage: DisableEptBp log_handle

    Short Name
        deb

    Summary
        Disable an active ept breakpoint.

        The disabled breakpoint becomes 'inactive' after it is successfully
        uninstalled from all processors. The breakpoint log for an 'inactive'
        ept breakpoint is valid and readable, but its breakpoint log elements
        are no longer updated by the ept breakpoint manager.

        Inactive breakpoints remain in the 'inactive' state until they are
        manually cleared by calling 'ClearEptBp' or the VivienneCL session
        ends.

        Disabling an ept breakpoint removes the performance cost associated
        with handling its ept violations while still allowing the user to read
        its breakpoint log.

    Parameters
        log_handle (decimal)
            The handle for the ept breakpoint to be disabled.

    Example
        Disable the ept breakpoint whose handle value is 133:

            deb 133)";

_Use_decl_annotations_
BOOL
CmdDisableEptBreakpoint(
    const std::vector<std::string>& ArgTokens
)
{
    HANDLE hLog = NULL;
    BOOL status = TRUE;

    if (DISABLE_EPT_BREAKPOINT_ARGC != ArgTokens.size())
    {
        CmdpPrintUsageText(
            CMD_DISABLE_EPT_BREAKPOINT,
            CMD_DISABLE_EPT_BREAKPOINT_SHORT,
            g_DisableEptBreakpointUsageText);
        status = FALSE;
        goto exit;
    }

    status =
        ParseUnsignedLongLongToken(ArgTokens[1], FALSE, (PULONGLONG)&hLog);
    if (!status)
    {
        ERR_PRINT("Invalid log_handle.");
        goto exit;
    }

    status = EbpDisableEptBreakpoint(hLog);
    if (!status)
    {
        goto exit;
    }

exit:
    return status;
}


#define CLEAR_EPT_BREAKPOINT_ARGC 2

static PCSTR g_ClearEptBreakpointUsageText = "Usage: ClearEptBp log_handle";

static PCSTR g_ClearEptBreakpointExtInfoText =
R"(Usage: ClearEptBp log_handle

    Short Name
        ceb

    Summary
        Uninstall the target ept breakpoint from all processors and unmap the
        corresponding breakpoint log.

    Parameters
        log_handle (decimal)
            The handle for the ept breakpoint to be cleared.

    Example
        Clear the ept breakpoint whose handle value is 6:

            ceb 6)";

_Use_decl_annotations_
BOOL
CmdClearEptBreakpoint(
    const std::vector<std::string>& ArgTokens
)
{
    HANDLE hLog = NULL;
    BOOL status = TRUE;

    if (CLEAR_EPT_BREAKPOINT_ARGC != ArgTokens.size())
    {
        CmdpPrintUsageText(
            CMD_CLEAR_EPT_BREAKPOINT,
            CMD_CLEAR_EPT_BREAKPOINT_SHORT,
            g_ClearEptBreakpointUsageText);
        status = FALSE;
        goto exit;
    }

    status =
        ParseUnsignedLongLongToken(ArgTokens[1], FALSE, (PULONGLONG)&hLog);
    if (!status)
    {
        ERR_PRINT("Invalid log_handle.");
        goto exit;
    }

    status = EbpClearEptBreakpoint(hLog);
    if (!status)
    {
        goto exit;
    }

    //
    // Remove the log.
    //
    status = CmdpRemoveEptBreakpointLog(hLog);
    if (!status)
    {
        goto exit;
    }

exit:
    return status;
}


#define PRINT_EPT_BREAKPOINT_LOG_HEADER_ARGC    2

static PCSTR g_PrintEptBreakpointLogHeaderUsageText =
    "Usage: PrintEptBpLogHeader log_handle";

static PCSTR g_PrintEptBreakpointLogHeaderExtInfoText =
R"(Usage: PrintEptBpLogHeader log_handle

    Short Name
        peblh

    Summary
        Print the breakpoint log header for the specified ept breakpoint.

    Parameters
        log_handle (decimal)
            The handle for the target ept breakpoint.

    Example
        Print the breakpoint log header for the ept breakpoint whose handle
        value is 20:

            peblh 20)";

_Use_decl_annotations_
BOOL
CmdPrintEptBreakpointLogHeader(
    _In_ const std::vector<std::string>& ArgTokens
)
{
    HANDLE hLog = NULL;
    PEPT_BREAKPOINT_LOG pLog = NULL;
    BOOL status = TRUE;

    if (PRINT_EPT_BREAKPOINT_LOG_HEADER_ARGC != ArgTokens.size())
    {
        CmdpPrintUsageText(
            CMD_PRINT_EPT_BREAKPOINT_LOG_HEADER,
            CMD_PRINT_EPT_BREAKPOINT_LOG_HEADER_SHORT,
            g_PrintEptBreakpointLogHeaderUsageText);
        status = FALSE;
        goto exit;
    }

    status =
        ParseUnsignedLongLongToken(ArgTokens[1], FALSE, (PULONGLONG)&hLog);
    if (!status)
    {
        ERR_PRINT("Invalid log_handle.");
        goto exit;
    }

    pLog = CmdpLookupEptBreakpointLog(hLog);
    if (!pLog)
    {
        goto exit;
    }

    EbpPrintEptBreakpointLogHeader(hLog, &pLog->Header);

exit:
    return status;
}


#define PRINT_EPT_BREAKPOINT_LOG_ELEMENTS_ARGC_MINIMUM  2
#define PRINT_EPT_BREAKPOINT_LOG_ELEMENTS_ARGC_MAXIMUM  4

static PCSTR g_PrintEptBreakpointLogElementsUsageText =
    "Usage: PrintEptBpLogElements log_handle [start_index] l[count]";

static PCSTR g_PrintEptBreakpointLogElementsExtInfoText =
R"(Usage: PrintEptBpLogElements log_handle [start_index] l[count]

    Short Name
        peble

    Summary
        Print breakpoint log elements for the specified ept breakpoint.

    Parameters
        log_handle (decimal)
            The handle for the target ept breakpoint.

        start_index (decimal, optional)
            Specify the index of the element to begin printing at.

        count (decimal, 'l' or 'L' prefix, optional)
            Specify the number of elements to print.

            If no 'start_index' parameter is specified then the first 'count'
            elements of the log are printed.

            This parameter must be prefixed with an 'l' or 'L' character. This
            syntax is similar to the 'Address Range' syntax in WinDbg.

    Example
        Print the first element of the breakpoint log for the ept breakpoint
        whose handle value is 31:

            peble 31 1

        Print the first 101 elements of the breakpoint log for the ept
        breakpoint whose handle value is 90909:

            peble 90909 L101

        Print 222 elements starting at the 50th element of the breakpoint log
        for the ept breakpoint whose handle value is 3:

            peble 3 50 l222
)";

_Use_decl_annotations_
BOOL
CmdPrintEptBreakpointLogElements(
    _In_ const std::vector<std::string>& ArgTokens
)
{
    SIZE_T nArgTokens = 0;
    HANDLE hLog = NULL;
    ULONG StartIndex = 0;
    std::string Token = {};
    ULONG NumberOfElements = 0;
    PULONG pValue = 0;
    PEPT_BREAKPOINT_LOG pLog = NULL;
    BOOL status = TRUE;

    nArgTokens = ArgTokens.size();

    if (PRINT_EPT_BREAKPOINT_LOG_ELEMENTS_ARGC_MINIMUM > nArgTokens ||
        PRINT_EPT_BREAKPOINT_LOG_ELEMENTS_ARGC_MAXIMUM < nArgTokens)
    {
        CmdpPrintUsageText(
            CMD_PRINT_EPT_BREAKPOINT_LOG_ELEMENTS,
            CMD_PRINT_EPT_BREAKPOINT_LOG_ELEMENTS_SHORT,
            g_PrintEptBreakpointLogElementsUsageText);
        status = FALSE;
        goto exit;
    }

    status = ParseUnsignedLongPtrToken(ArgTokens[1], FALSE, (PULONG_PTR)&hLog);
    if (!status)
    {
        ERR_PRINT("Invalid log_handle.");
        goto exit;
    }

    if (3 == nArgTokens)
    {
        //
        // 'peble log_handle start_index'
        //
        //  or
        //
        // 'peble log_handle l#'
        //
        if (ArgTokens[2][0] == 'l' || ArgTokens[2][0] == 'L')
        {
            try
            {
                Token = ArgTokens[2].substr(1, std::string::npos);
            }
            catch (const std::exception&)
            {
                ERR_PRINT("Failed to parse count parameter. (Exception)");
                status = FALSE;
                goto exit;
            }

            pValue = &NumberOfElements;
        }
        else
        {
            Token = ArgTokens[2];
            pValue = &StartIndex;
        }

        status = ParseUnsignedLongToken(Token, FALSE, pValue);
        if (!status)
        {
            ERR_PRINT("Invalid parameter: %s", Token.c_str());
            status = FALSE;
            goto exit;
        }
    }
    else if (4 == nArgTokens)
    {
        //
        // 'peble log_handle start_index l#'
        //
        status = ParseUnsignedLongToken(ArgTokens[2], FALSE, &StartIndex);
        if (!status)
        {
            ERR_PRINT("Invalid start_index: %s", ArgTokens[2].c_str());
            status = FALSE;
            goto exit;
        }

        if (ArgTokens[3][0] != 'l' && ArgTokens[3][0] != 'L')
        {
            ERR_PRINT("Invalid count: %s", ArgTokens[3].c_str());
            status = FALSE;
            goto exit;
        }

        try
        {
            Token = ArgTokens[3].substr(1, std::string::npos);
        }
        catch (const std::exception&)
        {
            ERR_PRINT("Failed to parse count parameter. (Exception)");
            status = FALSE;
            goto exit;
        }

        status =
            ParseUnsignedLongToken(Token, FALSE, &NumberOfElements);
        if (!status)
        {
            ERR_PRINT("Invalid count: %s", Token.c_str());
            status = FALSE;
            goto exit;
        }
    }
    else if (2 != nArgTokens)
    {
        ERR_PRINT("Unexpected state. (nArgTokens = %Iu)", nArgTokens);
        status = FALSE;
        goto exit;
    }

    pLog = CmdpLookupEptBreakpointLog(hLog);
    if (!pLog)
    {
        goto exit;
    }

    status = EbpPrintEptBreakpointElements(
        hLog,
        pLog,
        StartIndex,
        NumberOfElements);
    if (!status)
    {
        goto exit;
    }

exit:
    return status;
}
#endif


//=============================================================================
// General Commands
//=============================================================================
static
VOID
CmdpPrintDefaultHelpText(
    _In_ const std::vector<std::string>& ArgTokens
)
{
    CmdCommands(ArgTokens);

    INF_PRINT("");
    INF_PRINT(
        "Type '%s command_name' for more information about a command.",
        CMD_HELP);
}


static PCSTR g_HelpExtInfoText =
R"(Usage: help [command_name]

    Summary
        Display extended command information.

    Parameters
        command_name (optional)
            If a valid command name is specified then that command's extended
            information is displayed.

            If an invalid command name is specified or no command name is
            specified then the available command list is displayed.)";

#define HELP_ARGC 2

//
// NOTE The 'help' command must be the last command in this file so that it has
//  access to all other commands.
//
_Use_decl_annotations_
BOOL
CmdHelp(
    const std::vector<std::string>& ArgTokens
)
{
    PCSTR pszCommand = NULL;

    if (HELP_ARGC != ArgTokens.size())
    {
        CmdpPrintDefaultHelpText(ArgTokens);
        goto exit;
    }

    pszCommand = ArgTokens[1].c_str();

    //-------------------------------------------------------------------------
    // General
    //-------------------------------------------------------------------------
    if (CMD_ICOMPARE(CMD_EXIT_CLIENT, pszCommand))
    {
        INF_PRINT(g_ExitClientExtInfoText);
    }
    else if (
        CMD_ICOMPARE(pszCommand, CMD_COMMANDS) ||
        CMD_ICOMPARE(pszCommand, CMD_COMMANDS_SHORT))
    {
        INF_PRINT(g_CommandsExtInfoText);
    }
    else if (CMD_ICOMPARE(pszCommand, CMD_HELP))
    {
        INF_PRINT(g_HelpExtInfoText);
    }
    //-------------------------------------------------------------------------
    // Process
    //-------------------------------------------------------------------------
    else if (
        CMD_ICOMPARE(pszCommand, CMD_GET_PROCESS_ID) ||
        CMD_ICOMPARE(pszCommand, CMD_GET_PROCESS_ID_SHORT))
    {
        INF_PRINT(g_GetProcessIdExtInfoText);
    }
    else if (
        CMD_ICOMPARE(pszCommand, CMD_GET_PROCESS_INFORMATION) ||
        CMD_ICOMPARE(pszCommand, CMD_GET_PROCESS_INFORMATION_SHORT))
    {
        INF_PRINT(g_GetProcessInformationExtInfoText);
    }
#if defined(CFG_BPM_HARDWARE_BREAKPOINT_MANAGER)
    //-------------------------------------------------------------------------
    // Hardware Breakpoints
    //-------------------------------------------------------------------------
    else if (
        CMD_ICOMPARE(pszCommand, CMD_QUERY_SYSTEM_DEBUG_STATE) ||
        CMD_ICOMPARE(pszCommand, CMD_QUERY_SYSTEM_DEBUG_STATE_SHORT))
    {
    }
    else if (
        CMD_ICOMPARE(pszCommand, CMD_SET_HARDWARE_BREAKPOINT) ||
        CMD_ICOMPARE(pszCommand, CMD_SET_HARDWARE_BREAKPOINT_SHORT))
    {
        LogPrintDirect(SETHARDWAREBREAKPOINT_USAGE);
    }
    else if (
        CMD_ICOMPARE(pszCommand, CMD_CLEAR_HARDWARE_BREAKPOINT) ||
        CMD_ICOMPARE(pszCommand, CMD_CLEAR_HARDWARE_BREAKPOINT_SHORT))
    {
        LogPrintDirect(CLEARHARDWAREBREAKPOINT_USAGE);
    }
    //-------------------------------------------------------------------------
    // Capture Execution Context
    //-------------------------------------------------------------------------
    else if (
        CMD_ICOMPARE(pszCommand, CMD_CEC_REGISTER) ||
        CMD_ICOMPARE(pszCommand, CMD_CEC_REGISTER_SHORT))
    {
        LogPrintDirect(CEC_REGISTER_USAGE);
    }
    else if (
        CMD_ICOMPARE(pszCommand, CMD_CEC_MEMORY) ||
        CMD_ICOMPARE(pszCommand, CMD_CEC_MEMORY_SHORT))
    {
        LogPrintDirect(g_CecmUsageText);
    }
#endif
#if defined(CFG_BPM_EPT_BREAKPOINT_MANAGER)
    //-------------------------------------------------------------------------
    // Ept Breakpoints
    //-------------------------------------------------------------------------
    else if (
        CMD_ICOMPARE(pszCommand, CMD_QUERY_EPT_BREAKPOINT_INFORMATION) ||
        CMD_ICOMPARE(pszCommand, CMD_QUERY_EPT_BREAKPOINT_INFORMATION_SHORT))
    {
        INF_PRINT(g_QueryEptBreakpointInformationExtInfoText);
    }
    else if (
        CMD_ICOMPARE(pszCommand, CMD_SET_EPT_BREAKPOINT_BASIC) ||
        CMD_ICOMPARE(pszCommand, CMD_SET_EPT_BREAKPOINT_BASIC_SHORT))
    {
        LogPrintDirect(g_SetEptBreakpointExtInfoText);
    }
    else if (
        CMD_ICOMPARE(pszCommand, CMD_SET_EPT_BREAKPOINT_GENERAL_REGISTER_CONTEXT) ||
        CMD_ICOMPARE(pszCommand, CMD_SET_EPT_BREAKPOINT_GENERAL_REGISTER_CONTEXT_SHORT))
    {
        LogPrintDirect(g_SetEptBreakpointGeneralRegisterContextExtInfoText);
    }
    else if (
        CMD_ICOMPARE(pszCommand, CMD_SET_EPT_BREAKPOINT_KEYED_REGISTER_CONTEXT) ||
        CMD_ICOMPARE(pszCommand, CMD_SET_EPT_BREAKPOINT_KEYED_REGISTER_CONTEXT_SHORT))
    {
        LogPrintDirect(g_SetEptBreakpointKeyedRegisterContextExtInfoText);
    }
    else if (
        CMD_ICOMPARE(pszCommand, CMD_DISABLE_EPT_BREAKPOINT) ||
        CMD_ICOMPARE(pszCommand, CMD_DISABLE_EPT_BREAKPOINT_SHORT))
    {
        INF_PRINT(g_DisableEptBreakpointExtInfoText);
    }
    else if (
        CMD_ICOMPARE(pszCommand, CMD_CLEAR_EPT_BREAKPOINT) ||
        CMD_ICOMPARE(pszCommand, CMD_CLEAR_EPT_BREAKPOINT_SHORT))
    {
        INF_PRINT(g_ClearEptBreakpointExtInfoText);
    }
    else if (
        CMD_ICOMPARE(pszCommand, CMD_PRINT_EPT_BREAKPOINT_LOG_HEADER) ||
        CMD_ICOMPARE(pszCommand, CMD_PRINT_EPT_BREAKPOINT_LOG_HEADER_SHORT))
    {
        INF_PRINT(g_PrintEptBreakpointLogHeaderExtInfoText);
    }
    else if (
        CMD_ICOMPARE(pszCommand, CMD_PRINT_EPT_BREAKPOINT_LOG_ELEMENTS) ||
        CMD_ICOMPARE(pszCommand, CMD_PRINT_EPT_BREAKPOINT_LOG_ELEMENTS_SHORT))
    {
        LogPrintDirect(g_PrintEptBreakpointLogElementsExtInfoText);
    }
#endif
    //-------------------------------------------------------------------------
    // Unhandled
    //-------------------------------------------------------------------------
    else
    {
        CmdpPrintDefaultHelpText(ArgTokens);
    }

exit:
    return TRUE;
}
