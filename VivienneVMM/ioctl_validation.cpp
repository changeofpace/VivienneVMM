#include "ioctl_validation.h"


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
            break;
    }

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
