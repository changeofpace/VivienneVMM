/*++

Copyright (c) 2019-2020 changeofpace. All rights reserved.

Use of this source code is governed by the MIT license. See the 'LICENSE' file
for more information.

--*/

#pragma once

#include <ntddk.h>

#include "log.h"

/*++

Macro Name:

    DEBUG_BREAK

Macro Description:

    A software breakpoint which is only executed if all of the following
    conditions are true:

        1. Debug build configuration.

        2. Debugging was enabled on the machine at boot time.

        3. A kernel debugger is currently attached to the machine.

--*/
#if defined(DBG)
#define DEBUG_BREAK()               \
    if (!(KD_DEBUGGER_NOT_PRESENT)) \
    {                               \
        DbgBreakPoint();            \
    }
#else
#define DEBUG_BREAK()
#endif

/*++

Macro Name:

    VERIFY_NTSTATUS

Macro Description:

    A validation macro which logs failures and executes a DEBUG_BREAK() in
    debug builds.

Remarks:

    NT_VERIFY and RTL_SOFT_ASSERT are similar utility macros.

--*/
#if defined(VERIFY_NTSTATUS)
#error "Unexpected identifier conflict. (VERIFY_NTSTATUS)"
#endif

#if defined(DBG)
#define VERIFY_NTSTATUS(Expression)                                     \
{                                                                       \
    NTSTATUS Verify_NtStatus_ = (Expression);                           \
    if (!NT_SUCCESS(Verify_NtStatus_))                                  \
    {                                                                   \
        ERR_PRINT("\'" #Expression "\' failed: 0x%X", Verify_NtStatus_);\
        DEBUG_BREAK();                                                  \
    }                                                                   \
}
#else
#define VERIFY_NTSTATUS(Expression)                                     \
{                                                                       \
    NTSTATUS Verify_NtStatus_ = (Expression);                           \
    if (!NT_SUCCESS(Verify_NtStatus_))                                  \
    {                                                                   \
        ERR_PRINT("\'" #Expression "\' failed: 0x%X", Verify_NtStatus_);\
    }                                                                   \
}
#endif

/*++

Macro Name:

    VERIFY_BOOLEAN

Macro Description:

A validation macro which logs failures and executes a DEBUG_BREAK() in
debug builds.

Remarks:

    NT_VERIFY and RTL_SOFT_ASSERT are similar utility macros.

--*/
#if defined(VERIFY_BOOLEAN)
#error "Unexpected identifier conflict. (VERIFY_BOOLEAN)"
#endif

#if defined(DBG)
#define VERIFY_BOOLEAN(Expression)                          \
{                                                           \
    if (!(Expression))                                      \
    {                                                       \
        ERR_PRINT("\'" #Expression "\' assertion failed."); \
        DEBUG_BREAK();                                      \
    }                                                       \
}
#else
#define VERIFY_BOOLEAN(Expression)                          \
{                                                           \
    if (!(Expression))                                      \
    {                                                       \
        ERR_PRINT("\'" #Expression "\' assertion failed."); \
    }                                                       \
}
#endif

/*++

Macro Name:

    VIVIENNE_ASSERT

Macro Description:

    An alternative to the 'NT_ASSERT' macro which logs failures and executes a
    DEBUG_BREAK() in debug builds.

--*/
#if defined(VIVIENNE_ASSERT)
#error "Unexpected identifier conflict. (VIVIENNE_ASSERT)"
#endif

#if defined(DBG)
#define VIVIENNE_ASSERT VERIFY_BOOLEAN
#else
#define VIVIENNE_ASSERT(Expression)
#endif
