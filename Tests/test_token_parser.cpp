#include <Windows.h>

#include <cstdio>

#include "test_util.h"

#include "..\common\arch_x64.h"
#include "..\common\driver_io_types.h"

#include "..\VivienneCL\token_parser.h"


//=============================================================================
// Token Parser Test Cases
//=============================================================================

//
// TestParseMemoryDescriptionToken
//
_Check_return_
static
BOOL
TestParseMemoryDescriptionToken(
    _In_z_ PCSTR pszToken
)
{
    MEMORY_DATA_TYPE MemoryDataType = MDT_BYTE;
    CEC_MEMORY_DESCRIPTION MemoryDescription = {};
    BOOL status = TRUE;

    status = ParseMemoryDescriptionToken(
        pszToken,
        MemoryDataType,
        &MemoryDescription);
    if (!status)
    {
        goto exit;
    }

exit:
    return status;
}


#define ASSERT_VALID_MEMORY_DESCRIPTION(pszToken)                           \
    if (!TestParseMemoryDescriptionToken(pszToken))                         \
    {                                                                       \
        FAIL_TEST("ParseMemoryDescriptionToken failed (v): '%s'", pszToken);\
    }

#define ASSERT_INVALID_MEMORY_DESCRIPTION(pszToken)                           \
    if (TestParseMemoryDescriptionToken(pszToken))                            \
    {                                                                         \
        FAIL_TEST("ParseMemoryDescriptionToken failed (inv): '%s'", pszToken);\
    }


//
// TestVirtualAddressMemoryDescriptions
//
static
VOID
TestVirtualAddressMemoryDescriptions()
{
    //
    // Valid
    //
    ASSERT_VALID_MEMORY_DESCRIPTION("14FF20");
    ASSERT_VALID_MEMORY_DESCRIPTION("0x14FF20");
    ASSERT_VALID_MEMORY_DESCRIPTION("FFFFFFFF");
    ASSERT_VALID_MEMORY_DESCRIPTION("0xFFFFFFFF");

    //
    // Invalid
    //
    ASSERT_INVALID_MEMORY_DESCRIPTION("raxf");
    ASSERT_INVALID_MEMORY_DESCRIPTION("0xzzZ");
}


//
// TestIndirectAddressMemoryDescriptions
//
static
VOID
TestIndirectAddressMemoryDescriptions()
{
    //
    // BASE
    //

    // Valid
    ASSERT_VALID_MEMORY_DESCRIPTION("rbx");

    // Invalid
    ASSERT_INVALID_MEMORY_DESCRIPTION(" rbx ");
    ASSERT_INVALID_MEMORY_DESCRIPTION("rc");

    //
    // BASE +- DISPLACEMENT
    //

    // Valid
    ASSERT_VALID_MEMORY_DESCRIPTION("rip+1");
    ASSERT_VALID_MEMORY_DESCRIPTION("rip+956759");
    ASSERT_VALID_MEMORY_DESCRIPTION("rip+0x956759");
    ASSERT_VALID_MEMORY_DESCRIPTION("rip+DEEEED");
    ASSERT_VALID_MEMORY_DESCRIPTION("rip+0xDEEEED");
    ASSERT_VALID_MEMORY_DESCRIPTION("rip+ab12FFF3cd");
    ASSERT_VALID_MEMORY_DESCRIPTION("rip+0xab12FFF3cd");

    ASSERT_VALID_MEMORY_DESCRIPTION("rax-1");
    ASSERT_VALID_MEMORY_DESCRIPTION("rax-123123132");
    ASSERT_VALID_MEMORY_DESCRIPTION("rax-0x123123132");
    ASSERT_VALID_MEMORY_DESCRIPTION("rax-AAbb");
    ASSERT_VALID_MEMORY_DESCRIPTION("rax-0xAAbb");
    ASSERT_VALID_MEMORY_DESCRIPTION("rax-1100FfFf");
    ASSERT_VALID_MEMORY_DESCRIPTION("rax-0x1100FfFf");

    // Invalid
    ASSERT_INVALID_MEMORY_DESCRIPTION("rax + 1");
    ASSERT_INVALID_MEMORY_DESCRIPTION("rax - 1");
    ASSERT_INVALID_MEMORY_DESCRIPTION("rax-f+f");

    //
    // BASE + INDEX
    //

    // Valid
    ASSERT_VALID_MEMORY_DESCRIPTION("rip+rip");
    ASSERT_VALID_MEMORY_DESCRIPTION("rip+rax");

    // Invalid
    ASSERT_INVALID_MEMORY_DESCRIPTION("rip-rip");
    ASSERT_INVALID_MEMORY_DESCRIPTION("rip-rax");

    //
    // BASE + INDEX +- DISPLACEMENT
    //

    // Valid
    ASSERT_VALID_MEMORY_DESCRIPTION("rbx+rsi+1");
    ASSERT_VALID_MEMORY_DESCRIPTION("rbx+rsi+323520");
    ASSERT_VALID_MEMORY_DESCRIPTION("rbx+rsi+0x323520");
    ASSERT_VALID_MEMORY_DESCRIPTION("rbx+rsi+AAAA");
    ASSERT_VALID_MEMORY_DESCRIPTION("rbx+rsi+0xAAAA");
    ASSERT_VALID_MEMORY_DESCRIPTION("rbx+rsi+5AA3AA");
    ASSERT_VALID_MEMORY_DESCRIPTION("rbx+rsi+0x5AA3AA");

    ASSERT_VALID_MEMORY_DESCRIPTION("rdi+rsi-1");
    ASSERT_VALID_MEMORY_DESCRIPTION("rdi+rsi-100101");
    ASSERT_VALID_MEMORY_DESCRIPTION("rdi+rsi-0x100101");
    ASSERT_VALID_MEMORY_DESCRIPTION("rdi+rsi-ABCDEF");
    ASSERT_VALID_MEMORY_DESCRIPTION("rdi+rsi-0xABCDEF");
    ASSERT_VALID_MEMORY_DESCRIPTION("rdi+rsi-111ABCDEF");
    ASSERT_VALID_MEMORY_DESCRIPTION("rdi+rsi-1110xABCDEF");

    // Invalid
    ASSERT_INVALID_MEMORY_DESCRIPTION("rdi+rsi+rax");
    ASSERT_INVALID_MEMORY_DESCRIPTION("rdi+rsi-rax");
    ASSERT_INVALID_MEMORY_DESCRIPTION("rdi+1-2");

    //
    // INDEX * SCALE_FACTOR
    //

    // Valid
    ASSERT_VALID_MEMORY_DESCRIPTION("rsi*1");
    ASSERT_VALID_MEMORY_DESCRIPTION("rsi*2");
    ASSERT_VALID_MEMORY_DESCRIPTION("rsi*4");
    ASSERT_VALID_MEMORY_DESCRIPTION("rsi*8");

    // Invalid
    ASSERT_INVALID_MEMORY_DESCRIPTION("rsi*0");
    ASSERT_INVALID_MEMORY_DESCRIPTION("rsi*3");
    ASSERT_INVALID_MEMORY_DESCRIPTION("rsi*16");
    ASSERT_INVALID_MEMORY_DESCRIPTION("rsi*+1");
    ASSERT_INVALID_MEMORY_DESCRIPTION("rsi*-1");
    ASSERT_INVALID_MEMORY_DESCRIPTION("rsi*+2");
    ASSERT_INVALID_MEMORY_DESCRIPTION("rsi*-2");

    //
    // INDEX * SCALE_FACTOR +- DISPLACEMENT
    //

    // Valid
    ASSERT_VALID_MEMORY_DESCRIPTION("rsp*2+1");
    ASSERT_VALID_MEMORY_DESCRIPTION("rsp*2+86821");
    ASSERT_VALID_MEMORY_DESCRIPTION("rsp*2+0x86821");
    ASSERT_VALID_MEMORY_DESCRIPTION("rsp*2+FFFF");
    ASSERT_VALID_MEMORY_DESCRIPTION("rsp*2+0xFFFF");
    ASSERT_VALID_MEMORY_DESCRIPTION("rsp*2+1FF531FF");
    ASSERT_VALID_MEMORY_DESCRIPTION("rsp*2+0x1FF531FF");

    ASSERT_VALID_MEMORY_DESCRIPTION("rdx*2-1");
    ASSERT_VALID_MEMORY_DESCRIPTION("rdx*2-12151");
    ASSERT_VALID_MEMORY_DESCRIPTION("rdx*2-0x12151");
    ASSERT_VALID_MEMORY_DESCRIPTION("rdx*2-ABaCE");
    ASSERT_VALID_MEMORY_DESCRIPTION("rdx*2-0xABaCE");
    ASSERT_VALID_MEMORY_DESCRIPTION("rdx*2-382ff2aB");
    ASSERT_VALID_MEMORY_DESCRIPTION("rdx*2-0x382ff2aB");

    // Invalid
    ASSERT_INVALID_MEMORY_DESCRIPTION("rdx*2+rax");
    ASSERT_INVALID_MEMORY_DESCRIPTION("rdx*2-rax");
    ASSERT_INVALID_MEMORY_DESCRIPTION("rdx*2+0xABaCE+rax");

    //
    // BASE + INDEX * SCALE_FACTOR +- DISPLACEMENT
    //

    // Valid
    ASSERT_VALID_MEMORY_DESCRIPTION("rbx+rdi*8+1");
    ASSERT_VALID_MEMORY_DESCRIPTION("rbx+rdi*8+323520");
    ASSERT_VALID_MEMORY_DESCRIPTION("rbx+rdi*8+0x323520");
    ASSERT_VALID_MEMORY_DESCRIPTION("rbx+rdi*8+0EEEEEF");
    ASSERT_VALID_MEMORY_DESCRIPTION("rbx+rdi*8+0xEEEEEF");
    ASSERT_VALID_MEMORY_DESCRIPTION("rbx+rdi*8+EEEEEF333");
    ASSERT_VALID_MEMORY_DESCRIPTION("rbx+rdi*8+0xEEEEEF333");

    ASSERT_VALID_MEMORY_DESCRIPTION("rcx+rbp*8-1");
    ASSERT_VALID_MEMORY_DESCRIPTION("rcx+rbp*8-323520");
    ASSERT_VALID_MEMORY_DESCRIPTION("rcx+rbp*8-0x323520");
    ASSERT_VALID_MEMORY_DESCRIPTION("rcx+rbp*8-BBDDFF");
    ASSERT_VALID_MEMORY_DESCRIPTION("rcx+rbp*8-0xBBDDFF");
    ASSERT_VALID_MEMORY_DESCRIPTION("rcx+rbp*8-B2BDDF3F");
    ASSERT_VALID_MEMORY_DESCRIPTION("rcx+rbp*8-0xB2BDDF3F");

    // Invalid
    ASSERT_INVALID_MEMORY_DESCRIPTION("rsp+rdx*2+rax");
    ASSERT_INVALID_MEMORY_DESCRIPTION("rsp-rdx*2+rax");
    ASSERT_INVALID_MEMORY_DESCRIPTION("rsp+rdx*2+0xABaCE+rax");
    ASSERT_INVALID_MEMORY_DESCRIPTION("rsp-rdx*2+0xABaCE+rax");
}


//=============================================================================
// Test Interface
//=============================================================================

//
// TestTokenParser
//
VOID
TestTokenParser()
{
    PRINT_TEST_HEADER;

    TestVirtualAddressMemoryDescriptions();
    TestIndirectAddressMemoryDescriptions();

    PRINT_TEST_FOOTER;
}
