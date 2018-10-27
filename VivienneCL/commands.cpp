#include "commands.h"

#include <algorithm>
#include <cstdio>
#include <memory>

#include "driver_io.h"
#include "ntdll.h"
#include "process.h"

#include "..\common\arch_x64.h"


//=============================================================================
// Token Parsing and Sanitization
//=============================================================================

//
// IsBreakpointAddressAligned
//
_Check_return_
static
BOOL
IsBreakpointAddressAligned(
    _In_ ULONG_PTR Address,
    _In_ HWBP_TYPE Type,
    _In_ HWBP_SIZE Size
)
{
    ULONG cbCondition = 0;
    BOOL status = TRUE;

    // Skip non-data breakpoints.
    if (HWBP_TYPE::Access != Type ||
        HWBP_TYPE::Write != Type)
    {
        goto exit;
    }

    cbCondition = HwBpSizeToBytes(Size);

    if (!IS_ALIGNED(Address, cbCondition))
    {
        printf(
            "Misaligned breakpoint address: actual = 0x%IX, expected = 0x%IX\n",
            Address,
            (ULONG_PTR)(ALIGN_DOWN_POINTER_BY(Address, cbCondition)));
        status = FALSE;
        goto exit;
    }

exit:
    return status;
}


//
// ParseDebugRegisterIndexToken
//
_Check_return_
static
BOOL
ParseDebugRegisterIndexToken(
    _In_ const std::string& Token,
    _Out_ PULONG pDebugRegisterIndex
)
{
    ULONG DebugRegisterIndex = 0;
    BOOL status = TRUE;

    // Zero out parameters.
    *pDebugRegisterIndex = 0;

    try
    {
        // Try to parse a number.
        DebugRegisterIndex = std::stoul(Token);
    }
    catch (const std::exception& e)
    {
        printf("Invalid DebugRegisterIndex: %s.\n", e.what());
        status = FALSE;
        goto exit;
    }

    if (DAR_COUNT <= DebugRegisterIndex)
    {
        printf("Invalid DebugRegisterIndex: %s.\n", Token.c_str());
        status = FALSE;
        goto exit;
    }

    // Set out parameters.
    *pDebugRegisterIndex = DebugRegisterIndex;

exit:
    return status;
}


//
// ParseProcessIdToken
//
_Check_return_
static
BOOL
ParseProcessIdToken(
    _In_ const std::string& Token,
    _Out_ PULONG_PTR pProcessId
)
{
    ULONG_PTR ProcessId = 0;
    BOOL status = TRUE;

    // Zero out parameters.
    *pProcessId = 0;

    try
    {
        // Try to parse a hex number.
        ProcessId = (ULONG_PTR)std::stoull(Token);
    }
    catch (const std::exception& e)
    {
        printf("Invalid ProcessId: %s\n.", e.what());
        status = FALSE;
        goto exit;
    }

    // Set out parameters.
    *pProcessId = ProcessId;

exit:
    return status;
}


//
// ParseAddressToken
//
_Check_return_
static
BOOL
ParseAddressToken(
    _In_ const std::string& Token,
    _Out_ PULONG_PTR pAddress
)
{
    ULONG_PTR Address = 0;
    BOOL status = TRUE;

    // Zero out parameters.
    *pAddress = 0;

    try
    {
        // Try to parse a hex number.
        Address = (ULONG_PTR)std::stoull(Token, nullptr, 16);
    }
    catch (const std::exception& e)
    {
        printf("Invalid Address: %s\n.", e.what());
        status = FALSE;
        goto exit;
    }

    // Set out parameters.
    *pAddress = Address;

exit:
    return status;
}


#define ACCESS_SIZE_TOKEN_CCH 2

//
// ParseAccessSizeToken
//
_Check_return_
static
BOOL
ParseAccessSizeToken(
    _In_ const std::string& Token,
    _Out_ PHWBP_TYPE pType,
    _Out_ PHWBP_SIZE pSize
)
{
    HWBP_TYPE Type = {};
    HWBP_SIZE Size = {};
    BOOL status = TRUE;

    // Zero out parameters.
    *pType = {};
    *pSize = {};

    if (ACCESS_SIZE_TOKEN_CCH != Token.size())
    {
        printf("Invalid Access|Size: %s.\n", Token.c_str());
        status = FALSE;
        goto exit;
    }

    switch (Token[0])
    {
        case 'e': Type = HWBP_TYPE::Execute; break;
        case 'w': Type = HWBP_TYPE::Write;   break;
        case 'r': Type = HWBP_TYPE::Access;  break;
        default:
        {
            printf("Invalid Access: use 'e,r,w'.\n");
            status = FALSE;
            goto exit;
        }
    }

    switch (Token[1])
    {
        case '1': Size = HWBP_SIZE::Byte;  break;
        case '2': Size = HWBP_SIZE::Word;  break;
        case '4': Size = HWBP_SIZE::Dword; break;
        case '8': Size = HWBP_SIZE::Qword; break;
        default:
        {
            printf("Invalid Size: use '1,2,4,8'.\n");
            status = FALSE;
            goto exit;
        }
    }

    // Execution breakpoints must have size 1.
    if (HWBP_TYPE::Execute == Type &&
        HWBP_SIZE::Byte != Size)
    {
        Size = HWBP_SIZE::Byte;
    }

    // Set out parameters.
    *pType = Type;
    *pSize = Size;

exit:
    return status;
}


//
// ParseRegisterToken
//
_Check_return_
static
BOOL
ParseRegisterToken(
    _In_ const std::string& Token,
    _Out_ PX64_REGISTER pRegister
)
{
    std::string LowercaseToken(Token);
    X64_REGISTER Register = REGISTER_INVALID;
    BOOL status = TRUE;

    // Zero out parameters.
    *pRegister = REGISTER_INVALID;

    // Convert the token to lowercase.
    std::transform(
        LowercaseToken.begin(),
        LowercaseToken.end(),
        LowercaseToken.begin(),
        ::tolower);

    if      (LowercaseToken == "rip") Register = REGISTER_RIP;
    else if (LowercaseToken == "rax") Register = REGISTER_RAX;
    else if (LowercaseToken == "rcx") Register = REGISTER_RCX;
    else if (LowercaseToken == "rdx") Register = REGISTER_RDX;
    else if (LowercaseToken == "rdi") Register = REGISTER_RDI;
    else if (LowercaseToken == "rsi") Register = REGISTER_RSI;
    else if (LowercaseToken == "rbx") Register = REGISTER_RBX;
    else if (LowercaseToken == "rbp") Register = REGISTER_RBP;
    else if (LowercaseToken == "rsp") Register = REGISTER_RSP;
    else if (LowercaseToken == "r8")  Register = REGISTER_R8;
    else if (LowercaseToken == "r9")  Register = REGISTER_R9;
    else if (LowercaseToken == "r10") Register = REGISTER_R10;
    else if (LowercaseToken == "r11") Register = REGISTER_R11;
    else if (LowercaseToken == "r12") Register = REGISTER_R12;
    else if (LowercaseToken == "r13") Register = REGISTER_R13;
    else if (LowercaseToken == "r14") Register = REGISTER_R14;
    else if (LowercaseToken == "r15") Register = REGISTER_R15;
    else
    {
        printf("Invalid Register: %s.\n", LowercaseToken.c_str());
        status = FALSE;
        goto exit;
    }

    // Set out parameters.
    *pRegister = Register;

exit:
    return status;
}


//
// ParseDurationToken
//
_Check_return_
static
BOOL
ParseDurationToken(
    _In_ const std::string& Token,
    _Out_ PULONG pDurationInMilliseconds
)
{
    ULONG DurationInMilliseconds = 0;
    BOOL status = TRUE;

    // Zero out parameters.
    *pDurationInMilliseconds = 0;

    try
    {
        // Try to parse a hex number.
        DurationInMilliseconds = std::stoul(Token);
    }
    catch (const std::exception& e)
    {
        printf("Invalid DurationInMilliseconds: %s\n.", e.what());
        status = FALSE;
        goto exit;
    }

    // Set out parameters.
    *pDurationInMilliseconds = DurationInMilliseconds;

exit:
    return status;
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

    printf("Commands:\n");
    printf("    %s\n", CMD_CLEARHARDWAREBREAKPOINT);
    printf("    %s\n", CMD_COMMANDS);
    printf("    %s\n", CMD_CEC_REGISTER);
    printf("    %s\n", CMD_EXITCLIENT);
    printf("    %s\n", CMD_HELP);
    printf("    %s\n", CMD_LOOKUPPROCESSIDBYNAME);
    printf("    %s\n", CMD_QUERYSYSTEMDEBUGSTATE);
    printf("    %s\n", CMD_SETHARDWAREBREAKPOINT);

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
        printf("Invalid parameters.\n\n");
        printf(LOOKUPPROCESSIDBYNAME_USAGE);
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
        printf("    %Iu (0x%IX)\n", ProcessIds[i], ProcessIds[i]);
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

    // Initial allocation size.
    cbSystemDebugState = sizeof(*pSystemDebugState);

    pSystemDebugState = (PSYSTEM_DEBUG_STATE)HeapAlloc(
        GetProcessHeap(),
        HEAP_ZERO_MEMORY,
        cbSystemDebugState);
    if (!pSystemDebugState)
    {
        printf("Out of memory.\n");
        status = FALSE;
        goto exit;
    }

    // Multi-processor systems will fail the initial query to obtain the
    //  required struct size.
    if (!DrvQuerySystemDebugState(pSystemDebugState, cbSystemDebugState))
    {
        RequiredSize = pSystemDebugState->Size;

        status = HeapFree(GetProcessHeap(), 0, pSystemDebugState);
        if (!status)
        {
            printf("HeapFree failed: %u\n", GetLastError());
            goto exit;
        }

        pSystemDebugState = (PSYSTEM_DEBUG_STATE)HeapAlloc(
            GetProcessHeap(),
            HEAP_ZERO_MEMORY,
            RequiredSize);
        if (!pSystemDebugState)
        {
            printf("Out of memory.\n");
            status = FALSE;
            goto exit;
        }

        status = DrvQuerySystemDebugState(pSystemDebugState, RequiredSize);
        if (!status)
        {
            printf(
                "DrvQuerySystemDebugState failed twice: %u\n",
                GetLastError());
            goto exit;
        }
    }

    // Print debug register state for all processors.
    for (ULONG i = 0; i < pSystemDebugState->NumberOfProcessors; ++i)
    {
        printf("Processor %u:\n", i);

        pDebugRegisterState =
            pSystemDebugState->Processors[i].DebugRegisters;

        for (ULONG j = 0;
            j < ARRAYSIZE(pSystemDebugState->Processors->DebugRegisters);
            ++j)
        {
            printf(
                "    Dr%u: pid= %04Iu addr= 0x%016IX type= %d size= %d\n",
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
        status = HeapFree(GetProcessHeap(), 0, pSystemDebugState);
        if (!status)
        {
            printf("HeapFree failed: %u\n", GetLastError());
        }
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
        printf("Invalid parameters.\n\n");
        printf(SETHARDWAREBREAKPOINT_USAGE);
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

    status = DrvSetHardwareBreakpoint(
        ProcessId,
        DebugRegisterIndex,
        Address,
        Type,
        Size);
    if (!status)
    {
        printf("DrvSetHardwareBreakpoint failed: %u\n", GetLastError());
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
        printf("Invalid parameters.\n\n");
        printf(CLEARHARDWAREBREAKPOINT_USAGE);
        status = FALSE;
        goto exit;
    }

    status = ParseDebugRegisterIndexToken(ArgTokens[1], &DebugRegisterIndex);
    if (!status)
    {
        goto exit;
    }

    status = DrvClearHardwareBreakpoint(DebugRegisterIndex);
    if (!status)
    {
        printf("DrvClearHardwareBreakpoint failed: %u\n", GetLastError());
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
    PCEC_REGISTER_VALUES pCapturedCtx = NULL;
    BOOL status = TRUE;

    if (CEC_REGISTER_ARGC != ArgTokens.size())
    {
        printf("Invalid parameters.\n\n");
        printf(CEC_REGISTER_USAGE);
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

    // Allocate the captured context buffer.
    pCapturedCtx = (PCEC_REGISTER_VALUES)HeapAlloc(
        GetProcessHeap(),
        HEAP_ZERO_MEMORY,
        CEC_REGISTER_BUFFER_SIZE);
    if (!pCapturedCtx)
    {
        printf("HeapAlloc failed: %u\n", GetLastError());
        status = FALSE;
        goto exit;
    }

    status = DrvCaptureRegisterValues(
        ProcessId,
        DebugRegisterIndex,
        Address,
        Type,
        Size,
        Register,
        DurationInMilliseconds,
        pCapturedCtx,
        CEC_REGISTER_BUFFER_SIZE);
    if (!status)
    {
        printf("DrvCaptureRegisterValues failed: %u\n", GetLastError());
        goto exit;
    }

    // Log results.
    printf("Found %u unique values:\n", pCapturedCtx->NumberOfValues);

    for (ULONG i = 0; i < pCapturedCtx->NumberOfValues; ++i)
    {
        printf("    %u: 0x%IX\n", i, pCapturedCtx->Values[i]);
    }

exit:
    if (pCapturedCtx)
    {
        if (!HeapFree(GetProcessHeap(), 0, pCapturedCtx))
        {
            printf("HeapFree failed: %u\n", GetLastError());
            status = FALSE;
        }
    }

    return status;
}