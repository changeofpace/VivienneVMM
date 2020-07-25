/*++

Copyright (c) 2019 changeofpace. All rights reserved.

Use of this source code is governed by the MIT license. See the 'LICENSE' file
for more information.

Module Name:

    driver_io_types.h

Abstract:

    This header defines the names, constants, and types used by the client to
     communicate with the VivienneVMM driver.

Author:

    changeofpace

Environment:

    Kernel and user mode.

--*/

#pragma once

#ifdef _KERNEL_MODE
#include <ntddk.h>
#else
#include <Windows.h>
#endif

#include <devioctl.h>

#include "arch_x64.h"

//=============================================================================
// Environment
//=============================================================================
C_ASSERT(sizeof(HANDLE) == sizeof(ULONG_PTR));

//
// Parsing LONG_PTR displacement input using std::stoll.
//
C_ASSERT(sizeof(LONG_PTR) == sizeof(long long));

//
// Assert floating point type sizes because we cannot use float/double in
//  kernel code.
//
C_ASSERT(sizeof(UINT32) == sizeof(float));
C_ASSERT(sizeof(UINT64) == sizeof(double));

//=============================================================================
// Names
//=============================================================================
#define VVMM_DRIVER_NAME_W          L"vivienne"
#define VVMM_LOCALDEVICE_PATH_W     (L"\\\\.\\" VVMM_DRIVER_NAME_W)
#define VVMM_NT_DEVICE_NAME_W       (L"\\Device\\" VVMM_DRIVER_NAME_W)
#define VVMM_SYMLINK_NAME_W         (L"\\DosDevices\\" VVMM_DRIVER_NAME_W)

//=============================================================================
// Ioctls
//=============================================================================

//
// Valid device type value range: 32768 - 65535.
//
#define FILE_DEVICE_VVMM    38775ul

//
// Valid function code range: 2048 - 4095.
//
#define IOCTL_QUERYSYSTEMDEBUGSTATE \
    CTL_CODE(                       \
        FILE_DEVICE_VVMM,           \
        3100,                       \
        METHOD_BUFFERED,            \
        FILE_ANY_ACCESS)

#define IOCTL_SETHARDWAREBREAKPOINT \
    CTL_CODE(                       \
        FILE_DEVICE_VVMM,           \
        3200,                       \
        METHOD_BUFFERED,            \
        FILE_ANY_ACCESS)

#define IOCTL_CLEARHARDWAREBREAKPOINT   \
    CTL_CODE(                           \
        FILE_DEVICE_VVMM,               \
        3201,                           \
        METHOD_BUFFERED,                \
        FILE_ANY_ACCESS)

#define IOCTL_CEC_REGISTER  \
    CTL_CODE(               \
        FILE_DEVICE_VVMM,   \
        3300,               \
        METHOD_BUFFERED,    \
        FILE_ANY_ACCESS)

#define IOCTL_CEC_MEMORY    \
    CTL_CODE(               \
        FILE_DEVICE_VVMM,   \
        3301,               \
        METHOD_BUFFERED,    \
        FILE_ANY_ACCESS)


//=============================================================================
// IOCTL_QUERYSYSTEMDEBUGSTATE
//=============================================================================
typedef struct _DEBUG_REGISTER_STATE {
    ULONG_PTR ProcessId;
    ULONG_PTR Address;
    HWBP_TYPE Type;
    HWBP_SIZE Size;
} DEBUG_REGISTER_STATE, *PDEBUG_REGISTER_STATE;

typedef struct _PROCESSOR_DEBUG_STATE {
    DEBUG_REGISTER_STATE DebugRegisters[DAR_COUNT];
} PROCESSOR_DEBUG_STATE, *PPROCESSOR_DEBUG_STATE;

typedef struct _SYSTEM_DEBUG_STATE {
    ULONG Size; // Required size of this struct.
    ULONG NumberOfProcessors;
    PROCESSOR_DEBUG_STATE Processors[ANYSIZE_ARRAY];
} SYSTEM_DEBUG_STATE, *PSYSTEM_DEBUG_STATE;

typedef SYSTEM_DEBUG_STATE QUERYSYSTEMDEBUGSTATE_REPLY;
typedef PSYSTEM_DEBUG_STATE PQUERYSYSTEMDEBUGSTATE_REPLY;

//=============================================================================
// IOCTL_SETHARDWAREBREAKPOINT
//=============================================================================
typedef struct _SETHARDWAREBREAKPOINT_REQUEST {
    ULONG_PTR ProcessId;
    ULONG Index;
    ULONG_PTR Address;
    HWBP_TYPE Type;
    HWBP_SIZE Size;
} SETHARDWAREBREAKPOINT_REQUEST, *PSETHARDWAREBREAKPOINT_REQUEST;

//=============================================================================
// IOCTL_CLEARHARDWAREBREAKPOINT
//=============================================================================
typedef struct _CLEARHARDWAREBREAKPOINT_REQUEST {
    ULONG Index;
} CLEARHARDWAREBREAKPOINT_REQUEST, *PCLEARHARDWAREBREAKPOINT_REQUEST;

//=============================================================================
// IOCTL_CEC_REGISTER
//=============================================================================
typedef struct _CEC_REGISTER_REQUEST {
    ULONG_PTR ProcessId;
    ULONG Index;
    ULONG_PTR Address;
    HWBP_TYPE Type;
    HWBP_SIZE Size;
    X64_REGISTER Register;
    ULONG DurationInMilliseconds; // How long the breakpoint will last.
} CEC_REGISTER_REQUEST, *PCEC_REGISTER_REQUEST;

typedef struct _CEC_REGISTER_VALUES {
    ULONG Size; // Size of this struct.
    ULONG MaxIndex; // Exclusive bound.
    ULONG NumberOfValues;

    // NOTE Values must be the last defined field.
    ULONG_PTR Values[ANYSIZE_ARRAY];

} CEC_REGISTER_VALUES, *PCEC_REGISTER_VALUES;

typedef CEC_REGISTER_VALUES CEC_REGISTER_REPLY;
typedef PCEC_REGISTER_VALUES PCEC_REGISTER_REPLY;

//=============================================================================
// IOCTL_CEC_MEMORY
//=============================================================================
typedef enum _MEMORY_DATA_TYPE {
    MDT_INVALID = 0,
    MDT_BYTE,
    MDT_WORD,
    MDT_DWORD,
    MDT_QWORD,
    MDT_FLOAT,
    MDT_DOUBLE,
} MEMORY_DATA_TYPE, *PMEMORY_DATA_TYPE;

typedef union _MEMORY_DATA_VALUE {
    UINT8 Byte;
    UINT16 Word;
    UINT32 Dword;
    UINT64 Qword;
#if defined(_KERNEL_MODE)
    UINT32 Float;
    UINT64 Double;
#else
    FLOAT Float;
    DOUBLE Double;
#endif
} MEMORY_DATA_VALUE, *PMEMORY_DATA_VALUE;

typedef struct _CEC_MEMORY_DESCRIPTION {
    MEMORY_DATA_TYPE DataType;
    BOOLEAN IsIndirectAddress;
    union {
        ULONG_PTR VirtualAddress;
        INDIRECT_ADDRESS IndirectAddress;
    } u;
} CEC_MEMORY_DESCRIPTION, *PCEC_MEMORY_DESCRIPTION;

typedef struct _CEC_MEMORY_REQUEST {
    ULONG_PTR ProcessId;
    ULONG Index;
    ULONG_PTR Address;
    HWBP_TYPE Type;
    HWBP_SIZE Size;
    CEC_MEMORY_DESCRIPTION MemoryDescription;
    ULONG DurationInMilliseconds;
} CEC_MEMORY_REQUEST, *PCEC_MEMORY_REQUEST;

typedef struct _CEC_MEMORY_STATISTICS {
    //
    // Breakpoint callback execution count for this request.
    //
    SIZE_T HitCount;

    //
    // The number of skipped (i.e., may or may not be unique) values due to the
    //   values buffer being full.
    //
    SIZE_T SkipCount;

    //
    // Incremented whenever the effective address specified by the memory
    //  expression is invalid (MMPTE.u.Hard.Valid == 0).
    //
    SIZE_T InvalidPteErrors;

    //
    // Incremented whenever we attempt to read memory in a page which has not
    //  been accessed (MMPTE.u.Hard.Accessed == 0).
    //
    SIZE_T UntouchedPageErrors;

    //
    // Incremented whenever we attempt to read from an address that spans two
    //  pages.
    //
    SIZE_T SpanningAddressErrors;

    //
    // Incremented whenever an effective address evaluates to a system space
    //  address.
    //
    SIZE_T SystemAddressErrors;

    //
    // Incremented whenever a parameter fails a type validation check after
    //  input validation. A non-zero value indicates there is a logic bug in
    //  the input validation code.
    //
    SIZE_T ValidationErrors;

} CEC_MEMORY_STATISTICS, *PCEC_MEMORY_STATISTICS;

typedef struct _CEC_MEMORY_VALUES {
    MEMORY_DATA_TYPE DataType;

    CEC_MEMORY_STATISTICS Statistics;

    ULONG Size; // Size of this struct.
    ULONG MaxIndex; // Exclusive bound.
    ULONG NumberOfValues;

    // NOTE Values must be the last defined field.
    ULONG_PTR Values[ANYSIZE_ARRAY];

} CEC_MEMORY_VALUES, *PCEC_MEMORY_VALUES;

typedef CEC_MEMORY_VALUES CEC_MEMORY_REPLY;
typedef PCEC_MEMORY_VALUES PCEC_MEMORY_REPLY;

//=============================================================================
// Utilities
//=============================================================================
FORCEINLINE
ULONG
GetMemoryDataTypeSize(
    _In_ MEMORY_DATA_TYPE DataType
)
{
    switch (DataType)
    {
        case MDT_BYTE:   return sizeof(unsigned __int8);
        case MDT_WORD:   return sizeof(unsigned __int16);
        case MDT_DWORD:  return sizeof(unsigned __int32);
        case MDT_QWORD:  return sizeof(unsigned __int64);
        case MDT_FLOAT:  return sizeof(float);
        case MDT_DOUBLE: return sizeof(double);
        default:
            break;
    }

    return 0;
}
