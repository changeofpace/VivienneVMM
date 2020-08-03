/*++

Copyright (c) 2019-2020 changeofpace. All rights reserved.

Use of this source code is governed by the MIT license. See the 'LICENSE' file
for more information.

--*/

#include "token_parser.h"

#include <algorithm>
#include <sstream>

#include "log.h"
#include "ntdll.h"
#include "string_util.h"


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

    //
    // Skip non-data breakpoints.
    //
    if (HWBP_TYPE::Access != Type &&
        HWBP_TYPE::Write != Type)
    {
        goto exit;
    }

    cbCondition = HwBpSizeToBytes(Size);

    if (!IS_ALIGNED(Address, cbCondition))
    {
        ERR_PRINT(
            "Misaligned breakpoint address: actual = 0x%IX, expected = 0x%IX",
            Address,
            (ULONG_PTR)(ALIGN_DOWN_POINTER_BY(Address, cbCondition)));
        status = FALSE;
        goto exit;
    }

exit:
    return status;
}


_Use_decl_annotations_
BOOL
ParseUnsignedLongToken(
    const std::string& Token,
    BOOLEAN IsHex,
    PULONG pValue
)
{
    ULONG Value = 0;
    BOOL status = TRUE;

    //
    // Zero out parameters.
    //
    *pValue = 0;

    status = StrUnsignedLongFromString(Token, IsHex, &Value);
    if (!status)
    {
        ERR_PRINT("Invalid ulong value: %s.", Token.c_str());
        goto exit;
    }

    //
    // Set out parameters.
    //
    *pValue = Value;

exit:
    return status;
}


_Use_decl_annotations_
BOOL
ParseUnsignedLongLongToken(
    const std::string& Token,
    BOOLEAN IsHex,
    PULONGLONG pValue
)
{
    ULONGLONG Value = 0;
    BOOL status = TRUE;

    //
    // Zero out parameters.
    //
    *pValue = 0;

    status = StrUnsignedLongLongFromString(Token, IsHex, &Value);
    if (!status)
    {
        ERR_PRINT("Invalid ulonglong value: %s.", Token.c_str());
        goto exit;
    }

    //
    // Set out parameters.
    //
    *pValue = Value;

exit:
    return status;
}


_Use_decl_annotations_
BOOL
ParseUnsignedLongPtrToken(
    const std::string& Token,
    BOOLEAN IsHex,
    PULONG_PTR pValue
)
{
    ULONG_PTR Value = 0;
    BOOL status = TRUE;

    //
    // Zero out parameters.
    //
    *pValue = 0;

    status = StrUnsignedLongPtrFromString(Token, IsHex, &Value);
    if (!status)
    {
        ERR_PRINT("Invalid ulong_ptr value: %s.", Token.c_str());
        goto exit;
    }

    //
    // Set out parameters.
    //
    *pValue = Value;

exit:
    return status;
}


_Use_decl_annotations_
BOOL
ParseDebugRegisterIndexToken(
    const std::string& Token,
    PULONG pDebugRegisterIndex
)
{
    ULONG DebugRegisterIndex = 0;
    BOOL status = TRUE;

    //
    // Zero out parameters.
    //
    *pDebugRegisterIndex = 0;

    status = StrUnsignedLongFromString(Token, FALSE, &DebugRegisterIndex);
    if (!status)
    {
        ERR_PRINT("Invalid DebugRegisterIndex: %s.", Token.c_str());
        goto exit;
    }

    if (DAR_COUNT <= DebugRegisterIndex)
    {
        ERR_PRINT("Invalid DebugRegisterIndex: %s.", Token.c_str());
        status = FALSE;
        goto exit;
    }

    //
    // Set out parameters.
    //
    *pDebugRegisterIndex = DebugRegisterIndex;

exit:
    return status;
}


_Use_decl_annotations_
BOOL
ParseProcessIdToken(
    const std::string& Token,
    PULONG_PTR pProcessId
)
{
    ULONG_PTR ProcessId = 0;
    BOOL status = TRUE;

    //
    // Zero out parameters.
    //
    *pProcessId = 0;

    status = StrUnsignedLongLongFromString(Token, FALSE, &ProcessId);
    if (!status)
    {
        ERR_PRINT("Invalid ProcessId: %s.", Token.c_str());
        goto exit;
    }

    //
    // Set out parameters.
    //
    *pProcessId = ProcessId;

exit:
    return status;
}


_Use_decl_annotations_
BOOL
ParseAddressToken(
    const std::string& Token,
    PULONG_PTR pAddress
)
{
    ULONG_PTR Address = 0;
    BOOL status = TRUE;

    //
    // Zero out parameters.
    //
    *pAddress = 0;

    status = StrUnsignedLongLongFromString(Token, TRUE, &Address);
    if (!status)
    {
        ERR_PRINT("Invalid address: %s.", Token.c_str());
        goto exit;
    }

    //
    // Set out parameters.
    //
    *pAddress = Address;

exit:
    return status;
}


#define ACCESS_SIZE_TOKEN_CCH 2

_Use_decl_annotations_
BOOL
ParseHardwareBreakpointAccessSizeToken(
    const std::string& Token,
    PHWBP_TYPE pType,
    PHWBP_SIZE pSize
)
{
    HWBP_TYPE Type = {};
    HWBP_SIZE Size = {};
    BOOL status = TRUE;

    //
    // Zero out parameters.
    //
    *pType = {};
    *pSize = {};

    if (ACCESS_SIZE_TOKEN_CCH != Token.size())
    {
        ERR_PRINT("Invalid access|size: %s.", Token.c_str());
        status = FALSE;
        goto exit;
    }

    switch (Token[0])
    {
        case 'e': Type = HWBP_TYPE::Execute; break;
        case 'w': Type = HWBP_TYPE::Write;   break;
        case 'r': Type = HWBP_TYPE::Access;  break;
        default:
            ERR_PRINT("Invalid access: use 'e,r,w'.");
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
            ERR_PRINT("Invalid size: use '1,2,4,8'.");
            status = FALSE;
            goto exit;
    }

    //
    // Execution breakpoints must have size 1.
    //
    if (HWBP_TYPE::Execute == Type &&
        HWBP_SIZE::Byte != Size)
    {
        ERR_PRINT("Invalid execution breakpoint size.");
        status = FALSE;
        goto exit;
    }

    //
    // Set out parameters.
    //
    *pType = Type;
    *pSize = Size;

exit:
    return status;
}


_Use_decl_annotations_
BOOL
ParseEptBreakpointAccessSizeToken(
    const std::string& Token,
    PEPT_BREAKPOINT_TYPE pType,
    PEPT_BREAKPOINT_SIZE pSize
)
{
    EPT_BREAKPOINT_TYPE Type = {};
    EPT_BREAKPOINT_SIZE Size = {};
    BOOL status = TRUE;

    //
    // Zero out parameters.
    //
    *pType = {};
    *pSize = {};

    if (ACCESS_SIZE_TOKEN_CCH != Token.size())
    {
        ERR_PRINT("Invalid access|size: %s.", Token.c_str());
        status = FALSE;
        goto exit;
    }

    switch (Token[0])
    {
        case 'r': Type = EptBreakpointTypeRead;     break;
        case 'w': Type = EptBreakpointTypeWrite;    break;
        case 'e': Type = EptBreakpointTypeExecute;  break;
        default:
            ERR_PRINT("Invalid access: use 'r,w,e'.");
            status = FALSE;
            goto exit;
    }

    switch (Token[1])
    {
        case '1': Size = EptBreakpointSizeByte;  break;
        case '2': Size = EptBreakpointSizeWord;  break;
        case '4': Size = EptBreakpointSizeDword; break;
        case '8': Size = EptBreakpointSizeQword; break;
        default:
            ERR_PRINT("Invalid size: use '1,2,4,8'.");
            status = FALSE;
            goto exit;
    }

    //
    // Execution breakpoints must have size 1.
    //
    if (EptBreakpointTypeExecute == Type &&
        EptBreakpointSizeByte != Size)
    {
        ERR_PRINT("Invalid execution breakpoint size.");
        status = FALSE;
        goto exit;
    }

    //
    // Set out parameters.
    //
    *pType = Type;
    *pSize = Size;

exit:
    return status;
}


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

    //
    // Zero out parameters.
    //
    *pRegister = REGISTER_INVALID;

    //
    // Convert the token to lowercase.
    //
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
        ERR_PRINT("Invalid register: %s.", LowercaseToken.c_str());
        status = FALSE;
        goto exit;
    }

    //
    // Set out parameters.
    //
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

    //
    // Zero out parameters.
    //
    *pMemoryDataType = {};

    if (MEMORY_DATA_TYPE_TOKEN_CCH != Token.size())
    {
        ERR_PRINT("Invalid data type token size: %Iu.", Token.size());
        status = FALSE;
        goto exit;
    }

    //
    // Convert the token to lowercase.
    //
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
            ERR_PRINT("Invalid data type token: %s.",
                LowercaseToken.c_str());
            status = FALSE;
            goto exit;
    }

    //
    // Set out parameters.
    //
    *pMemoryDataType = MemoryDataType;

exit:
    return status;
}


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

    //
    // Zero out parameters.
    //
    *pScaleFactor = {};

    status = StrUnsignedLongFromString(Token, FALSE, &Value);
    if (!status)
    {
        ERR_PRINT("Invalid scale factor: %s", Token.c_str());
        goto exit;
    }

    switch (Value)
    {
        case SCALE_BYTE:  ScaleFactor = SCALE_BYTE; break;
        case SCALE_WORD:  ScaleFactor = SCALE_WORD; break;
        case SCALE_DWORD: ScaleFactor = SCALE_DWORD; break;
        case SCALE_QWORD: ScaleFactor = SCALE_QWORD; break;
        default:
            ERR_PRINT("Invalid scale factor value: %u", Value);
            status = FALSE;
            goto exit;
    }

    //
    // Set out parameters.
    //
    *pScaleFactor = ScaleFactor;

exit:
    return status;
}


//
// Uncomment for verbose indirect address token prints.
//
//#define DBG_INDIRECT_ADDRESS_TOKEN_PARSER

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

    //
    // Zero out parameters.
    //
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
            ERR_PRINT(
                "Invalid memory description: %s (base/index)",
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
                ERR_PRINT(
                    "Invalid memory description: '%s' (scale factor/displacement -)",
                    ScaleFactorDisplacement.c_str());
                status = FALSE;
                goto exit;
            }
        }
        else
        {
            ERR_PRINT(
                "Invalid memory description: '%s' (scale factor/displacement +)",
                ScaleFactorDisplacement.c_str());
            status = FALSE;
            goto exit;
        }

        //
        // If the token contains '*' then it must contain a scale factor.
        //
        if (ScaleFactor.empty())
        {
            ERR_PRINT(
                "Tokens containing an '*' must specify a scale factor.");
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
                ERR_PRINT(
                    "Invalid memory description: %s (index/displacement)",
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
            ERR_PRINT(
                "Invalid memory description: %s (base/index/displacement)",
                Token.c_str());
            status = FALSE;
            goto exit;
        }
    }
    else
    {
    ERR_PRINT("Invalid memory description: %s", Token.c_str());
        status = FALSE;
        goto exit;
    }

#if defined(_DEBUG) && defined(DBG_INDIRECT_ADDRESS_TOKEN_PARSER)
    DBG_PRINT("token: '%s'", Token.c_str());
    DBG_PRINT("    Base:           '%s'", Base.c_str());
    DBG_PRINT("    Index:          '%s'", Index.c_str());
    DBG_PRINT("    ScaleFactor:    '%s'", ScaleFactor.c_str());
    DBG_PRINT("    Displacement:   '%s'", Displacement.c_str());
    DBG_PRINT("");
#endif

    //
    // Filter invalid combinations.
    //
    if (Base.empty() && Index.empty())
    {
        ERR_PRINT("Null base and index.");
        status = FALSE;
        goto exit;
    }

    if (Index.empty() && !ScaleFactor.empty())
    {
        ERR_PRINT(
            "Invalid index (%s) / scale factor (%s).",
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
            ERR_PRINT("Invalid base register.");
            goto exit;
        }
    }

    if (!Index.empty())
    {
        status = ParseRegisterToken(Index, &IndirectAddress.IndexRegister);
        if (!status)
        {
            ERR_PRINT("Invalid index register.");
            goto exit;
        }

        if (!ScaleFactor.empty())
        {
            status = ParseScaleFactorToken(
                ScaleFactor,
                &IndirectAddress.ScaleFactor);
            if (!status)
            {
                ERR_PRINT("Invalid scale factor.");
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
            ERR_PRINT("Invalid displacement: %s", Displacement.c_str());
            status = FALSE;
            goto exit;
        }
    }

    //
    // Set out parameters.
    //
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

    //
    // Zero out parameters.
    //
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
        ERR_PRINT("ParseIndirectAddressToken failed.");
        goto exit;
    }

    //
    // Set remaining fields.
    //
    MemoryDescription.DataType = MemoryDataType;
    MemoryDescription.IsIndirectAddress = TRUE;

    //
    // Set out parameters.
    //
    RtlCopyMemory(
        pMemoryDescription,
        &MemoryDescription,
        sizeof(CEC_MEMORY_DESCRIPTION));

exit:
    return status;
}
