/*++

Copyright (c) 2019 changeofpace. All rights reserved.

Use of this source code is governed by the MIT license. See the 'LICENSE' file
for more information.

--*/

#include "commands.h"

#include <algorithm>
#include <memory>
#include <sstream>

#include "debug.h"
#include "driver_io.h"
#include "log.h"
#include "ntdll.h"
#include "process.h"
#include "token_parser.h"

#include "..\common\arch_x64.h"
#include "..\common\driver_io_types.h"


//=============================================================================
// Private Interface
//=============================================================================
static
VOID
CmdpPrintCommandList()
{
    INF_PRINT("    %s", CMD_CLEARHARDWAREBREAKPOINT);
    INF_PRINT("    %s", CMD_COMMANDS);
    INF_PRINT("    %s", CMD_CEC_REGISTER);
    INF_PRINT("    %s", CMD_CEC_MEMORY);
    INF_PRINT("    %s", CMD_EXITCLIENT);
    INF_PRINT("    %s", CMD_HELP);
    INF_PRINT("    %s", CMD_LOOKUPPROCESSIDBYNAME);
    INF_PRINT("    %s", CMD_QUERYSYSTEMDEBUGSTATE);
    INF_PRINT("    %s", CMD_SETHARDWAREBREAKPOINT);
}


//=============================================================================
// Command Interface
//=============================================================================

//
// CmdDisplayCommands
//
// Display a list of supported commands.
//
_Use_decl_annotations_
BOOL
CmdDisplayCommands(
    const std::vector<std::string>& ArgTokens
)
{
    UNREFERENCED_PARAMETER(ArgTokens);

    INF_PRINT("Commands:");

    CmdpPrintCommandList();

    return TRUE;
}


//
// CmdLookupProcessIdByName
//
// Return a vector of all the process ids whose names match the specified
//  process name.
//
#define LOOKUPPROCESSIDBYNAME_ARGC 2
#define LOOKUPPROCESSIDBYNAME_USAGE                                         \
    "Usage: " CMD_LOOKUPPROCESSIDBYNAME " process_name\n"                   \
    "    Summary\n"                                                         \
    "        Query process ids matching the specified process name.\n"      \
    "    Args\n"                                                            \
    "        process_name:  process name (including file extension)\n"      \
    "    Example\n"                                                         \
    "        pid calc.exe\n"

_Use_decl_annotations_
BOOL
CmdLookupProcessIdByName(
    const std::vector<std::string>& ArgTokens
)
{
    PCSTR ProcessName = NULL;
    std::vector<ULONG_PTR> ProcessIds;
    BOOL status = TRUE;

    if (LOOKUPPROCESSIDBYNAME_ARGC != ArgTokens.size())
    {
        LogPrintDirect(LOOKUPPROCESSIDBYNAME_USAGE);
        status = FALSE;
        goto exit;
    }

    ProcessName = ArgTokens[1].data();

    status = PsLookupProcessIdByName(ProcessName, ProcessIds);
    if (!status)
    {
        goto exit;
    }

    for (SIZE_T i = 0; i < ProcessIds.size(); ++i)
    {
        INF_PRINT("    %Iu (0x%IX)", ProcessIds[i], ProcessIds[i]);
    }

exit:
    return status;
}


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
    "Usage: " CMD_SETHARDWAREBREAKPOINT " index pid access|size address\n"  \
    "    Summary\n"                                                         \
    "        Install a hardware breakpoint on all processors.\n"            \
    "    Args\n"                                                            \
    "        index:     [0-3]        debug address register index\n"        \
    "        pid:       #            an active process id (integer)\n"      \
    "        access:    'e,r,w'      execution, read, write\n"              \
    "        size:      '1,2,4,8'    byte, word, dword, qword\n"            \
    "        address:   #            valid user-mode address (hex)\n"       \
    "    Example\n"                                                         \
    "        setbp 0 1002 e1 77701650\n"

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

    status = ParseAccessSizeToken(ArgTokens[3], &Type, &Size);
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
    "Usage: " CMD_CLEARHARDWAREBREAKPOINT " index\n"                \
    "    Summary\n"                                                 \
    "        Clear a hardware breakpoint on all processors.\n"      \
    "    Args\n"                                                    \
    "        index:     [0-3]        debug address register index\n"\
    "    Example\n"                                                 \
    "        clear 0\n"

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
    "    Summary\n"                                                         \
    "        Capture unique register context at a target address.\n"        \
    "    Args\n"                                                            \
    "        index:     [0-3]           debug address register index\n"     \
    "        pid:       #               an active process id (integer)\n"   \
    "        access:    'e,r,w'         execution, read, write\n"           \
    "        size:      '1,2,4,8'       byte, word, dword, qword\n"         \
    "        address:   #               valid user-mode address (hex)\n"    \
    "        register:  'rip,rax,etc'   the target register\n"              \
    "        duration:  #               capture duration in milliseconds\n" \
    "    Example\n"                                                         \
    "        " CMD_CEC_REGISTER " 0 1002 e1 77701650 rbx 5000\n"
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

    status = ParseAccessSizeToken(ArgTokens[3], &Type, &Size);
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

    status = ParseDurationToken(ArgTokens[6], &DurationInMilliseconds);
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
R"(Usage: cecm index pid access|size bp_address mem_type mem_expression duration

    Type 'help cecm' for extended information.
)";

static PCSTR g_CecmHelpText =
R"(Usage: cecm index pid access|size bp_address mem_type mem_expression duration

    Summary
        Capture unique values of type mem_type at the memory address described
        by mem_expression.

        This command sets a hardware breakpoint specified by 'access', 'size',
        and 'bp_address' using the debug address register specified by 'index'.
        The breakpoint callback calculates the effective address by evaluating
        the memory expression (mem_expression) using the guest context. A value
        of type 'mem_type' is read from the effective address. Unique values
        are stored to the user data buffer.

    Args
        index
            The debug address register index used for the hardware breakpoint.

        pid
            The target process id. (decimal)

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

        address
            The hardware breakpoint address. (hex, '0x' prefix optional)

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

    status = ParseAccessSizeToken(ArgTokens[3], &Type, &Size);
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

    status = ParseDurationToken(ArgTokens[7], &DurationInMilliseconds);
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


//
// CmdDisplayHelpText
//
// Display extended command information.
//
#define HELP_ARGC 2

#define CMD_HELP_USAGE "Usage: help command_name\n"

_Use_decl_annotations_
BOOL
CmdDisplayHelpText(
    const std::vector<std::string>& ArgTokens
)
{
    std::string CommandName = {};
    BOOL status = TRUE;

    if (HELP_ARGC != ArgTokens.size())
    {
        LogPrintDirect(CMD_HELP_USAGE);
        status = FALSE;
        goto exit;
    }

    CommandName = ArgTokens[1];

    if (CMD_CEC_MEMORY == CommandName)
    {
        LogPrintDirect(g_CecmHelpText);
    }
    else
    {
        INF_PRINT("Commands with extended information:");
        INF_PRINT("    %s", CMD_CEC_MEMORY);
    }

exit:
    return status;
}
