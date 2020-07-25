/*++

Copyright (c) 2019 changeofpace. All rights reserved.

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
#define DEBUG_BREAK                 \
    if (!(KD_DEBUGGER_NOT_PRESENT)) \
    {                               \
        DbgBreakPoint();            \
    }
#else
#define DEBUG_BREAK
#endif

/*++

Macro Name:

    VERIFY

Macro Description:

    A validation macro which ASSERTs in debug build configurations and logs
    failures in release build configurations.

Remarks:

    NT_VERIFY and RTL_SOFT_ASSERT are similar utility macros.

--*/
#if defined(VERIFY)
#error "Unexpected identifier conflict. (VERIFY)"
#endif

#if defined(DBG)
#define VERIFY(NtExpression)    (NT_ASSERT(NT_SUCCESS(NtExpression)))
#else
#define VERIFY(NtExpression)                                                \
{                                                                           \
    NTSTATUS Verify_NtStatus_ = (NtExpression);                             \
    if (!NT_SUCCESS(Verify_NtStatus_))                                      \
    {                                                                       \
        ERR_PRINT("\'" #NtExpression "\' failed: 0x%X", Verify_NtStatus_);  \
    }                                                                       \
}
#endif
