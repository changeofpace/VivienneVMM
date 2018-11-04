#include "token_parser.h"

#include <algorithm>
#include <cstdio>
#include <sstream>

#include "ntdll.h"
#include "string_util.h"


//=============================================================================
// Token Parsing and Sanitization
//=============================================================================

//
// IsBreakpointAddressAligned
//
_Use_decl_annotations_
BOOL
IsBreakpointAddressAligned(
    ULONG_PTR Address,
    HWBP_TYPE Type,
    HWBP_SIZE Size
)
{
    ULONG cbCondition = 0;
    BOOL status = TRUE;

    // Skip non-data breakpoints.
    if (HWBP_TYPE::Access != Type &&
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
_Use_decl_annotations_
BOOL
ParseDebugRegisterIndexToken(
    const std::string& Token,
    PULONG pDebugRegisterIndex
)
{
    ULONG DebugRegisterIndex = 0;
    BOOL status = TRUE;

    // Zero out parameters.
    *pDebugRegisterIndex = 0;

    status = StrUnsignedLongFromString(Token, FALSE, &DebugRegisterIndex);
    if (!status)
    {
        printf("Invalid DebugRegisterIndex: %s.\n", Token.c_str());
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
_Use_decl_annotations_
BOOL
ParseProcessIdToken(
    const std::string& Token,
    PULONG_PTR pProcessId
)
{
    ULONG_PTR ProcessId = 0;
    BOOL status = TRUE;

    // Zero out parameters.
    *pProcessId = 0;

    status = StrUnsignedLongLongFromString(Token, FALSE, &ProcessId);
    if (!status)
    {
        printf("Invalid ProcessId: %s\n.", Token.c_str());
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
_Use_decl_annotations_
BOOL
ParseAddressToken(
    const std::string& Token,
    PULONG_PTR pAddress
)
{
    ULONG_PTR Address = 0;
    BOOL status = TRUE;

    // Zero out parameters.
    *pAddress = 0;

    status = StrUnsignedLongLongFromString(Token, TRUE, &Address);
    if (!status)
    {
        printf("Invalid ProcessId: %s\n.", Token.c_str());
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
_Use_decl_annotations_
BOOL
ParseAccessSizeToken(
    const std::string& Token,
    PHWBP_TYPE pType,
    PHWBP_SIZE pSize
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
            printf("Invalid Access: use 'e,r,w'.\n");
            status = FALSE;
            goto exit;
    }

    switch (Token[1])
    {
        case '1': Size = HWBP_SIZE::Byte;  break;
        case '2': Size = HWBP_SIZE::Word;  break;
        case '4': Size = HWBP_SIZE::Dword; break;
        case '8': Size = HWBP_SIZE::Qword; break;
        default:
            printf("Invalid Size: use '1,2,4,8'.\n");
            status = FALSE;
            goto exit;
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
_Use_decl_annotations_
BOOL
ParseRegisterToken(
    const std::string& Token,
    PX64_REGISTER pRegister
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

    if (LowercaseToken == "rip") Register = REGISTER_RIP;
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


#define MEMORY_DATA_TYPE_TOKEN_CCH 1

//
// ParseMemoryDataTypeToken
//
//      b       byte
//      w       word
//      d       dword
//      q       qword
//      f       float
//      o       double
//
_Use_decl_annotations_
BOOL
ParseMemoryDataTypeToken(
    const std::string& Token,
    PMEMORY_DATA_TYPE pMemoryDataType
)
{
    std::string LowercaseToken(Token);
    MEMORY_DATA_TYPE MemoryDataType = {};
    BOOL status = TRUE;

    // Zero out parameters.
    *pMemoryDataType = {};

    if (MEMORY_DATA_TYPE_TOKEN_CCH != Token.size())
    {
        printf("Invalid data type token size: %Iu.\n", Token.size());
        status = FALSE;
        goto exit;
    }

    // Convert the token to lowercase.
    std::transform(
        LowercaseToken.begin(),
        LowercaseToken.end(),
        LowercaseToken.begin(),
        ::tolower);

    switch (LowercaseToken[0])
    {
        case 'b': MemoryDataType = MDT_BYTE; break;
        case 'w': MemoryDataType = MDT_WORD; break;
        case 'd': MemoryDataType = MDT_DWORD; break;
        case 'q': MemoryDataType = MDT_QWORD; break;
        case 'f': MemoryDataType = MDT_FLOAT; break;
        case 'o': MemoryDataType = MDT_DOUBLE; break;
        default:
            printf("Invalid data type token: %s.\n", LowercaseToken.c_str());
            status = FALSE;
            goto exit;
    }

    // Set out parameters.
    *pMemoryDataType = MemoryDataType;

exit:
    return status;
}


//
// ParseScaleFactorToken
//
_Use_decl_annotations_
BOOL
ParseScaleFactorToken(
    const std::string& Token,
    PSCALE_FACTOR pScaleFactor
)
{
    ULONG Value = 0;
    SCALE_FACTOR ScaleFactor = {};
    BOOL status = TRUE;

    // Zero out parameters.
    *pScaleFactor = {};

    status = StrUnsignedLongFromString(Token, FALSE, &Value);
    if (!status)
    {
        printf("Invalid scale factor: %s\n", Token.c_str());
        goto exit;
    }

    switch (Value)
    {
        case SCALE_BYTE:  ScaleFactor = SCALE_BYTE; break;
        case SCALE_WORD:  ScaleFactor = SCALE_WORD; break;
        case SCALE_DWORD: ScaleFactor = SCALE_DWORD; break;
        case SCALE_QWORD: ScaleFactor = SCALE_QWORD; break;
        default:
            printf("Invalid scale factor value: %u\n", Value);
            status = FALSE;
            goto exit;
    }

    // Set out parameters.
    *pScaleFactor = ScaleFactor;

exit:
    return status;
}


//
// Uncomment for verbose indirect address token prints.
//
//#define DBG_INDIRECT_ADDRESS_TOKEN_PARSER

//
// ParseIndirectAddressToken
//
_Use_decl_annotations_
BOOL
ParseIndirectAddressToken(
    const std::string& Token,
    PINDIRECT_ADDRESS pIndirectAddress
)
{
    std::vector<std::string> ExpressionTokens = {};
    SIZE_T cExpressionTokens = 0;
    std::string Base = {};
    std::string Index = {};
    std::string ScaleFactor = {};
    std::string Displacement = {};
    INDIRECT_ADDRESS IndirectAddress = {};
    BOOL status = TRUE;

    // Zero out parameters.
    RtlSecureZeroMemory(pIndirectAddress, sizeof(*pIndirectAddress));

    cExpressionTokens = StrSplitStringByDelimiter('*', Token, ExpressionTokens);
    if (2 == cExpressionTokens)
    {
        //
        // Form: (BASE +) INDEX * SCALE_FACTOR (+- DISPLACEMENT)
        //
        std::string BaseIndex = ExpressionTokens[0];
        std::string ScaleFactorDisplacement = ExpressionTokens[1];

        //
        // Parse: (BASE +) INDEX
        //
        cExpressionTokens = StrSplitStringByDelimiter(
            '+',
            BaseIndex,
            ExpressionTokens);
        if (2 == cExpressionTokens)
        {
            //
            // BASE + INDEX
            //
            Base = ExpressionTokens[0];
            Index = ExpressionTokens[1];
        }
        else if (1 == cExpressionTokens)
        {
            //
            // INDEX
            //
            Index = BaseIndex;
        }
        else
        {
            printf(
                "Invalid memory description: %s (base/index)\n",
                BaseIndex.c_str());
            status = FALSE;
            goto exit;
        }

        //
        // Parse: SCALE_FACTOR (+- DISPLACEMENT)
        //
        cExpressionTokens = StrSplitStringByDelimiter(
            '+',
            ScaleFactorDisplacement,
            ExpressionTokens);
        if (2 == cExpressionTokens)
        {
            //
            // SCALE_FACTOR + DISPLACEMENT
            //
            ScaleFactor = ExpressionTokens[0];
            Displacement = ExpressionTokens[1];
        }
        else if (1 == cExpressionTokens)
        {
            cExpressionTokens = StrSplitStringByDelimiter(
                '-',
                ScaleFactorDisplacement,
                ExpressionTokens);
            if (2 == cExpressionTokens)
            {
                //
                // SCALE_FACTOR - DISPLACEMENT
                //
                ScaleFactor = ExpressionTokens[0];
                Displacement = "-" + ExpressionTokens[1];
            }
            else if (1 == cExpressionTokens)
            {
                //
                // SCALE_FACTOR
                //
                ScaleFactor = ScaleFactorDisplacement;
            }
            else
            {
                printf(
                    "Invalid memory description: '%s' (scale factor/displacement -)\n",
                    ScaleFactorDisplacement.c_str());
                status = FALSE;
                goto exit;
            }
        }
        else
        {
            printf(
                "Invalid memory description: '%s' (scale factor/displacement +)\n",
                ScaleFactorDisplacement.c_str());
            status = FALSE;
            goto exit;
        }

        //
        // If the token contains '*' then it must contain a scale factor.
        //
        if (ScaleFactor.empty())
        {
            printf("Tokens containing an '*' must specify a scale factor.\n");
            status = FALSE;
            goto exit;
        }
    }
    else if (1 == cExpressionTokens)
    {
        //
        // Form: BASE (+ INDEX) (+- DISPLACEMENT)
        //
        cExpressionTokens = StrSplitStringByDelimiter(
            '+',
            Token,
            ExpressionTokens);
        if (3 == cExpressionTokens)
        {
            //
            // BASE + INDEX + DISPLACEMENT
            //
            Base = ExpressionTokens[0];
            Index = ExpressionTokens[1];
            Displacement = ExpressionTokens[2];
        }
        else if (2 == cExpressionTokens)
        {
            //
            // Forms:
            //  BASE (+ INDEX)
            //      rbx+rdx
            //  BASE (+ DISPLACEMENT)
            //      rbx+20
            //  BASE (+ INDEX - DISPLACEMENT)
            //      rbx+rdx-20
            //
            std::string IndexDisplacement = ExpressionTokens[1];

            Base = ExpressionTokens[0];

            cExpressionTokens = StrSplitStringByDelimiter(
                '-',
                IndexDisplacement,
                ExpressionTokens);
            if (2 == cExpressionTokens)
            {
                //
                // INDEX - DISPLACEMENT
                //
                Index = ExpressionTokens[0];
                Displacement = "-" + ExpressionTokens[1];
            }
            else if (1 == cExpressionTokens)
            {
                LONG_PTR Temp = 0;

                try
                {
                    //
                    // BASE + DISPLACEMENT
                    //
                    Temp = std::stoll(IndexDisplacement, nullptr, 16);
                    Displacement = IndexDisplacement;
                }
                catch (const std::exception&)
                {
                    //
                    // BASE + INDEX
                    //
                    Index = IndexDisplacement;
                }
            }
            else
            {
                printf(
                    "Invalid memory description: %s (index/displacement)\n",
                    IndexDisplacement.c_str());
                status = FALSE;
                goto exit;
            }
        }
        else if (1 == cExpressionTokens)
        {
            //
            // Form: BASE (- DISPLACEMENT)
            //
            cExpressionTokens = StrSplitStringByDelimiter(
                '-',
                Token,
                ExpressionTokens);
            if (2 == cExpressionTokens)
            {
                //
                // BASE - DISPLACEMENT
                //
                Base = ExpressionTokens[0];
                Displacement = "-" + ExpressionTokens[1];
            }
            else
            {
                //
                // BASE
                //
                Base = ExpressionTokens[0];
            }
        }
        else
        {
            printf(
                "Invalid memory description: %s (base/index/displacement)\n",
                Token.c_str());
            status = FALSE;
            goto exit;
        }
    }
    else
    {
        printf("Invalid memory description: %s\n", Token.c_str());
        status = FALSE;
        goto exit;
    }

#if defined(_DEBUG) && defined(DBG_INDIRECT_ADDRESS_TOKEN_PARSER)
    printf("token: '%s'\n", Token.c_str());
    printf("    Base:           '%s'\n", Base.c_str());
    printf("    Index:          '%s'\n", Index.c_str());
    printf("    ScaleFactor:    '%s'\n", ScaleFactor.c_str());
    printf("    Displacement:   '%s'\n", Displacement.c_str());
    printf("\n");
#endif

    //
    // Filter invalid combinations.
    //
    if (Base.empty() && Index.empty())
    {
        printf("Null base and index.\n");
        status = FALSE;
        goto exit;
    }

    if (Index.empty() && !ScaleFactor.empty())
    {
        printf(
            "Invalid index (%s) / scale factor (%s).\n",
            Index.c_str(),
            ScaleFactor.c_str());
        status = FALSE;
        goto exit;
    }

    //
    // Convert strings into value representations.
    //
    if (!Base.empty())
    {
        status = ParseRegisterToken(Base, &IndirectAddress.BaseRegister);
        if (!status)
        {
            printf("Invalid base register.\n");
            goto exit;
        }
    }

    if (!Index.empty())
    {
        status = ParseRegisterToken(Index, &IndirectAddress.IndexRegister);
        if (!status)
        {
            printf("Invalid index register.\n");
            goto exit;
        }

        if (!ScaleFactor.empty())
        {
            status = ParseScaleFactorToken(
                ScaleFactor,
                &IndirectAddress.ScaleFactor);
            if (!status)
            {
                printf("Invalid scale factor.\n");
                goto exit;
            }
        }
    }

    if (!Displacement.empty())
    {
        try
        {
            IndirectAddress.Displacement =
                std::stoll(Displacement, nullptr, 16);
        }
        catch (const std::exception&)
        {
            printf("Invalid displacement: %s\n", Displacement.c_str());
            status = FALSE;
            goto exit;
        }
    }

    // Set out parameters.
    RtlCopyMemory(
        pIndirectAddress,
        &IndirectAddress,
        sizeof(INDIRECT_ADDRESS));

exit:
    return status;
}


//
// ParseMemoryDescriptionToken
//
// Valid input examples:
//
//  14FF20
//  rbx+rsi
//  rbx+rsi+FFFF
//  rbx+rsi*8-77777
//
_Use_decl_annotations_
BOOL
ParseMemoryDescriptionToken(
    const std::string& Token,
    MEMORY_DATA_TYPE MemoryDataType,
    PCEC_MEMORY_DESCRIPTION pMemoryDescription
)
{
    ULONG_PTR VirtualAddress = 0;
    CEC_MEMORY_DESCRIPTION MemoryDescription = {};
    BOOL status = TRUE;

    // Zero out parameters.
    RtlSecureZeroMemory(pMemoryDescription, sizeof(*pMemoryDescription));

    //
    // Try interpreting the token as a simple hex address.
    //
    status = StrUnsignedLongLongFromString(Token, TRUE, &VirtualAddress);
    if (status)
    {
        //
        // Reject null addresses.
        //
        if (!VirtualAddress)
        {
            SetLastError(ERROR_INVALID_ADDRESS);
            status = FALSE;
            goto exit;
        }

        //
        // Initialize the description as an absolute virtual address and return
        //  success.
        //
        pMemoryDescription->DataType = MemoryDataType;
        pMemoryDescription->IsIndirectAddress = FALSE;
        pMemoryDescription->u.VirtualAddress = VirtualAddress;
        goto exit;
    }

    status = ParseIndirectAddressToken(
        Token,
        &MemoryDescription.u.IndirectAddress);
    if (!status)
    {
        printf("ParseIndirectAddressToken failed.\n");
        goto exit;
    }

    //
    // Set remaining fields.
    //
    MemoryDescription.DataType = MemoryDataType;
    MemoryDescription.IsIndirectAddress = TRUE;

    // Set out parameters.
    RtlCopyMemory(
        pMemoryDescription,
        &MemoryDescription,
        sizeof(CEC_MEMORY_DESCRIPTION));

exit:
    return status;
}


//
// ParseDurationToken
//
_Use_decl_annotations_
BOOL
ParseDurationToken(
    const std::string& Token,
    PULONG pDurationInMilliseconds
)
{
    ULONG DurationInMilliseconds = 0;
    BOOL status = TRUE;

    // Zero out parameters.
    *pDurationInMilliseconds = 0;

    status = StrUnsignedLongFromString(Token, FALSE, &DurationInMilliseconds);
    if (!status)
    {
        printf("Invalid DurationInMilliseconds: %s.\n", Token.c_str());
        goto exit;
    }

    // Set out parameters.
    *pDurationInMilliseconds = DurationInMilliseconds;

exit:
    return status;
}
