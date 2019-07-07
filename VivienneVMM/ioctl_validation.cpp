#include "ioctl_validation.h"

#include "log.h"


//=============================================================================
// Internal Prototypes
//=============================================================================
_Check_return_
static
NTSTATUS
IviValidateMemoryDataType(
    _In_ MEMORY_DATA_TYPE MemoryDataType
);

_Check_return_
static
NTSTATUS
IviValidateScaleFactor(
    _In_ SCALE_FACTOR ScaleFactor
);

_Check_return_
static
NTSTATUS
IviValidateIndirectAddress(
    _In_ PINDIRECT_ADDRESS pIndirectAddress
);


//=============================================================================
// Public Interface
//=============================================================================

//
// IvValidateGeneralPurposeRegister
//
_Use_decl_annotations_
NTSTATUS
IvValidateGeneralPurposeRegister(
    X64_REGISTER Register
)
{
    NTSTATUS ntstatus = STATUS_SUCCESS;

    switch (Register)
    {
        case REGISTER_RIP:
        case REGISTER_RAX:
        case REGISTER_RCX:
        case REGISTER_RDX:
        case REGISTER_RDI:
        case REGISTER_RSI:
        case REGISTER_RBX:
        case REGISTER_RBP:
        case REGISTER_RSP:
        case REGISTER_R8:
        case REGISTER_R9:
        case REGISTER_R10:
        case REGISTER_R11:
        case REGISTER_R12:
        case REGISTER_R13:
        case REGISTER_R14:
        case REGISTER_R15:
            break;
        default:
            ntstatus = STATUS_INVALID_PARAMETER;
            goto exit;
    }

exit:
    return ntstatus;
}


//
// IvValidateDebugRegisterIndex
//
_Use_decl_annotations_
NTSTATUS
IvValidateDebugRegisterIndex(
    ULONG DebugRegisterIndex
)
{
    NTSTATUS ntstatus = STATUS_SUCCESS;

    if (DAR_COUNT <= DebugRegisterIndex)
    {
        ntstatus = STATUS_INVALID_PARAMETER;
        goto exit;
    }

exit:
    return ntstatus;
}


//
// IvValidateMemoryDescription
//
_Use_decl_annotations_
NTSTATUS
IvValidateMemoryDescription(
    PCEC_MEMORY_DESCRIPTION pMemoryDescription
)
{
    NTSTATUS ntstatus = STATUS_SUCCESS;

    ntstatus = IviValidateMemoryDataType(pMemoryDescription->DataType);
    if (!NT_SUCCESS(ntstatus))
    {
        ERR_PRINT("IviValidateMemoryDataType failed: 0x%X", ntstatus);
        goto exit;
    }

    if (pMemoryDescription->IsIndirectAddress)
    {
        ntstatus = IviValidateIndirectAddress(
            &pMemoryDescription->u.IndirectAddress);
        if (!NT_SUCCESS(ntstatus))
        {
            ERR_PRINT("IviValidateIndirectAddress failed: 0x%X", ntstatus);
            goto exit;
        }
    }
    else
    {
        //
        // Reject null addresses.
        //
        if (!pMemoryDescription->u.VirtualAddress)
        {
            ERR_PRINT(
                "IV: Invalid virtual address: 0x%IX",
                pMemoryDescription->u.VirtualAddress);
            ntstatus = STATUS_INVALID_ADDRESS;
            goto exit;
        }

        //
        // NOTE Restrict absolute virtual addresses to user space for now.
        //
        if ((ULONG_PTR)MM_HIGHEST_USER_ADDRESS <=
                pMemoryDescription->u.VirtualAddress)
        {
            ERR_PRINT(
                "IV: Invalid virtual address: 0x%IX",
                pMemoryDescription->u.VirtualAddress);
            ntstatus = STATUS_INVALID_ADDRESS;
            goto exit;
        }
    }

exit:
    return ntstatus;
}


//=============================================================================
// Internal Interface
//=============================================================================

//
// IviValidateMemoryDataType
//
_Use_decl_annotations_
static
NTSTATUS
IviValidateMemoryDataType(
    MEMORY_DATA_TYPE MemoryDataType
)
{
    NTSTATUS ntstatus = STATUS_SUCCESS;

    switch (MemoryDataType)
    {
        case MDT_BYTE:
        case MDT_WORD:
        case MDT_DWORD:
        case MDT_QWORD:
        case MDT_FLOAT:
        case MDT_DOUBLE:
            break;
        default:
            ntstatus = STATUS_INVALID_PARAMETER;
            goto exit;
    }

exit:
    return ntstatus;
}


//
// IviValidateScaleFactor
//
_Use_decl_annotations_
static
NTSTATUS
IviValidateScaleFactor(
    SCALE_FACTOR ScaleFactor
)
{
    NTSTATUS ntstatus = STATUS_SUCCESS;

    switch (ScaleFactor)
    {
        case SCALE_BYTE:
        case SCALE_WORD:
        case SCALE_DWORD:
        case SCALE_QWORD:
            break;
        default:
            ntstatus = STATUS_INVALID_PARAMETER;
            goto exit;
    }

exit:
    return ntstatus;
}


//
// IviValidateIndirectAddress
//
_Use_decl_annotations_
static
NTSTATUS
IviValidateIndirectAddress(
    PINDIRECT_ADDRESS pIndirectAddress
)
{
    NTSTATUS ntstatus = STATUS_SUCCESS;

    //
    // Base register must be a valid register.
    //
    ntstatus = IvValidateGeneralPurposeRegister(
        pIndirectAddress->BaseRegister);
    if (!NT_SUCCESS(ntstatus))
    {
        ERR_PRINT(
            "IvValidateGeneralPurposeRegister failed: 0x%X (base register)",
            ntstatus);
        goto exit;
    }

    //
    // The index register and scale factor are optional.
    //
    if (REGISTER_INVALID != pIndirectAddress->IndexRegister)
    {
        ntstatus = IvValidateGeneralPurposeRegister(
            pIndirectAddress->IndexRegister);
        if (!NT_SUCCESS(ntstatus))
        {
            ERR_PRINT(
                "IvValidateGeneralPurposeRegister failed: 0x%X (index register)",
                ntstatus);
            goto exit;
        }

        if (SCALE_INVALID != pIndirectAddress->ScaleFactor)
        {
            ntstatus = IviValidateScaleFactor(pIndirectAddress->ScaleFactor);
            if (!NT_SUCCESS(ntstatus))
            {
                ERR_PRINT("IviValidateScaleFactor failed: 0x%X", ntstatus);
                goto exit;
            }
        }
    }
    else if (SCALE_INVALID != pIndirectAddress->ScaleFactor)
    {
        //
        // Scale factors must be paired with a valid index register.
        //
        ERR_PRINT(
            "IV: Invalid index register (%d) / scale factor (%d).",
            pIndirectAddress->IndexRegister,
            pIndirectAddress->ScaleFactor);
        ntstatus = STATUS_INVALID_PARAMETER_2;
        goto exit;
    }

exit:
    return ntstatus;
}
