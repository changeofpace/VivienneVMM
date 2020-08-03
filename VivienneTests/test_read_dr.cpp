#include "tests.h"

#include <intrin.h>

#include <cstdio>

#include "test_util.h"

#include "..\common\arch_x64.h"


//
// ReadDebugRegister
//
_Check_return_
static
BOOL
ReadDebugRegister(
    _In_ ULONG Index
)
{
    ULONG_PTR Value = 0;
    BOOL ExceptionCaught = FALSE;
    BOOL status = TRUE;

    //
    // Validate the index parameter.
    //
    switch (Index)
    {
        case 0:
        case 1:
        case 2:
        case 3:
        case 4:
        case 5:
        case 6:
        case 7:
            break;
        default:
            printf("Invalid debug register index: %u\n", Index);
            status = FALSE;
            goto exit;
    }

    __try
    {
        //
        // Attempt to read a debug register. This should throw an
        //  STATUS_PRIVILEGED_INSTRUCTION exception under normal circumstances.
        //
        switch (Index)
        {
            case 0: Value = __readdr(0); break;
            case 1: Value = __readdr(1); break;
            case 2: Value = __readdr(2); break;
            case 3: Value = __readdr(3); break;
            case 4: Value = __readdr(4); break;
            case 5: Value = __readdr(5); break;
            case 6: Value = __readdr(6); break;
            case 7: Value = __readdr(7); break;
            default:
                printf("Unexpected debug register index: %u\n", Index);
                status = FALSE;
                goto exit;
        }

        //
        // Execution should never reach here.
        //
        printf("Unexpected state.");
        status = FALSE;
        goto exit;
    }
    __except (
        GetExceptionCode() == STATUS_PRIVILEGED_INSTRUCTION
        ? EXCEPTION_EXECUTE_HANDLER
        : EXCEPTION_CONTINUE_SEARCH)
    {
        ExceptionCaught = TRUE;
    }

    //
    // Verify that Value is still zero.
    //
    if (0 != Value)
    {
        printf("Unexpected Value: 0x%IX\n", Value);
        status = FALSE;
        goto exit;
    }

    //
    // Verify that the __readdr instruction caused the expected exception.
    //
    if (!ExceptionCaught)
    {
        printf("__readdr exception not handled.\n");
        status = FALSE;
        goto exit;
    }

exit:
    return status;
}


//=============================================================================
// Test Interface
//=============================================================================

//
// TestReadDebugRegister
//
VOID
TestReadDebugRegister()
{
    BOOL status = TRUE;

    PRINT_TEST_HEADER;

    for (ULONG i = 0; i < DR_COUNT; ++i)
    {
        status = ReadDebugRegister(i);
        if (!status)
        {
            FAIL_TEST("ReadDebugRegister failed for DR%u\n", i);
        }
    }

    PRINT_TEST_FOOTER;
}
