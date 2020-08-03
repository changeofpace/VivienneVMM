/*++

Copyright (c) 2019-2020 changeofpace. All rights reserved.

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
#include <fltKernel.h>
#else
#include <Windows.h>
#endif

#include <devioctl.h>

#include "arch_x64.h"
#include "config.h"

//=============================================================================
// Names
//=============================================================================
#define VVMM_DRIVER_NAME_W          CFG_VIVIENNE_DEVICE_NAME
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
#define IOCTL_GET_PROCESS_INFORMATION           \
    CTL_CODE(                                   \
        FILE_DEVICE_VVMM,                       \
        3000,                                   \
        METHOD_BUFFERED,                        \
        FILE_READ_ACCESS | FILE_WRITE_ACCESS)

#define IOCTL_QUERYSYSTEMDEBUGSTATE             \
    CTL_CODE(                                   \
        FILE_DEVICE_VVMM,                       \
        3100,                                   \
        METHOD_BUFFERED,                        \
        FILE_READ_ACCESS | FILE_WRITE_ACCESS)

#define IOCTL_SETHARDWAREBREAKPOINT             \
    CTL_CODE(                                   \
        FILE_DEVICE_VVMM,                       \
        3200,                                   \
        METHOD_BUFFERED,                        \
        FILE_READ_ACCESS | FILE_WRITE_ACCESS)

#define IOCTL_CLEARHARDWAREBREAKPOINT           \
    CTL_CODE(                                   \
        FILE_DEVICE_VVMM,                       \
        3201,                                   \
        METHOD_BUFFERED,                        \
        FILE_READ_ACCESS | FILE_WRITE_ACCESS)

#define IOCTL_CEC_REGISTER                      \
    CTL_CODE(                                   \
        FILE_DEVICE_VVMM,                       \
        3300,                                   \
        METHOD_BUFFERED,                        \
        FILE_READ_ACCESS | FILE_WRITE_ACCESS)

#define IOCTL_CEC_MEMORY                        \
    CTL_CODE(                                   \
        FILE_DEVICE_VVMM,                       \
        3301,                                   \
        METHOD_BUFFERED,                        \
        FILE_READ_ACCESS | FILE_WRITE_ACCESS)

#define IOCTL_QUERY_EPT_BREAKPOINT_INFORMATION_SIZE \
    CTL_CODE(                                       \
        FILE_DEVICE_VVMM,                           \
        3400,                                       \
        METHOD_BUFFERED,                            \
        FILE_READ_ACCESS | FILE_WRITE_ACCESS)

#define IOCTL_QUERY_EPT_BREAKPOINT_INFORMATION  \
    CTL_CODE(                                   \
        FILE_DEVICE_VVMM,                       \
        3401,                                   \
        METHOD_BUFFERED,                        \
        FILE_READ_ACCESS | FILE_WRITE_ACCESS)

#define IOCTL_SET_EPT_BREAKPOINT                \
    CTL_CODE(                                   \
        FILE_DEVICE_VVMM,                       \
        3420,                                   \
        METHOD_BUFFERED,                        \
        FILE_READ_ACCESS | FILE_WRITE_ACCESS)

#define IOCTL_DISABLE_EPT_BREAKPOINT            \
    CTL_CODE(                                   \
        FILE_DEVICE_VVMM,                       \
        3421,                                   \
        METHOD_BUFFERED,                        \
        FILE_READ_ACCESS | FILE_WRITE_ACCESS)

#define IOCTL_CLEAR_EPT_BREAKPOINT              \
    CTL_CODE(                                   \
        FILE_DEVICE_VVMM,                       \
        3422,                                   \
        METHOD_BUFFERED,                        \
        FILE_READ_ACCESS | FILE_WRITE_ACCESS)

//=============================================================================
// IOCTL_GET_PROCESS_INFORMATION
//=============================================================================
typedef struct _GET_PROCESS_INFORMATION_REQUEST {
    ULONG_PTR ProcessId;
} GET_PROCESS_INFORMATION_REQUEST, *PGET_PROCESS_INFORMATION_REQUEST;

typedef struct _VIVIENNE_PROCESS_INFORMATION {
    PVOID BaseAddress;
} VIVIENNE_PROCESS_INFORMATION, *PVIVIENNE_PROCESS_INFORMATION;

typedef struct _GET_PROCESS_INFORMATION_REPLY {
    VIVIENNE_PROCESS_INFORMATION Info;
} GET_PROCESS_INFORMATION_REPLY, *PGET_PROCESS_INFORMATION_REPLY;

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
    _Field_size_(NumberOfProcessors)
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
    _Field_size_(NumberOfValues)
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
    _Field_size_(NumberOfValues)
    ULONG_PTR Values[ANYSIZE_ARRAY];
} CEC_MEMORY_VALUES, *PCEC_MEMORY_VALUES;

typedef CEC_MEMORY_VALUES CEC_MEMORY_REPLY;
typedef PCEC_MEMORY_VALUES PCEC_MEMORY_REPLY;

//=============================================================================
// IOCTL_QUERY_EPT_BREAKPOINT_INFORMATION_SIZE
//=============================================================================
typedef struct _QUERY_EPT_BREAKPOINT_INFORMATION_SIZE_REPLY {
    ULONG RequiredSize;
} QUERY_EPT_BREAKPOINT_INFORMATION_SIZE_REPLY,
*PQUERY_EPT_BREAKPOINT_INFORMATION_SIZE_REPLY;

//=============================================================================
// IOCTL_QUERY_EPT_BREAKPOINT_INFORMATION
//=============================================================================
typedef enum _EPT_BREAKPOINT_STATUS {
    EptBreakpointStatusInvalid = 0,
    EptBreakpointStatusInstalling,
    EptBreakpointStatusActive,
    EptBreakpointStatusInactive
} EPT_BREAKPOINT_STATUS, *PEPT_BREAKPOINT_STATUS;

typedef enum _EPT_BREAKPOINT_TYPE {
    EptBreakpointTypeInvalid = 0,
    EptBreakpointTypeRead,
    EptBreakpointTypeWrite,
    EptBreakpointTypeExecute
} EPT_BREAKPOINT_TYPE, *PEPT_BREAKPOINT_TYPE;

typedef enum _EPT_BREAKPOINT_SIZE {
    EptBreakpointSizeInvalid = 0,
    EptBreakpointSizeByte = 1,
    EptBreakpointSizeWord = 2,
    EptBreakpointSizeDword = 4,
    EptBreakpointSizeQword = 8
} EPT_BREAKPOINT_SIZE, *PEPT_BREAKPOINT_SIZE;

typedef enum _EPT_BREAKPOINT_LOG_TYPE {
    EptBreakpointLogTypeInvalid = 0,
    EptBreakpointLogTypeBasic,
    EptBreakpointLogTypeGeneralRegisterContext,
    EptBreakpointLogTypeKeyedRegisterContext
} EPT_BREAKPOINT_LOG_TYPE, *PEPT_BREAKPOINT_LOG_TYPE;

typedef struct _EPT_BREAKPOINT_LOG_HEADER {
    ULONG_PTR ProcessId;
    ULONG_PTR Address;
    EPT_BREAKPOINT_STATUS BreakpointStatus;
    EPT_BREAKPOINT_TYPE BreakpointType;
    EPT_BREAKPOINT_SIZE BreakpointSize;
    EPT_BREAKPOINT_LOG_TYPE LogType;
    X64_REGISTER RegisterKey;
    ULONG MaxIndex;
    ULONG NumberOfElements;
} EPT_BREAKPOINT_LOG_HEADER, *PEPT_BREAKPOINT_LOG_HEADER;

typedef struct _EPT_BREAKPOINT_INFORMATION_ELEMENT {
    HANDLE Handle;
    EPT_BREAKPOINT_LOG_HEADER Header;
} EPT_BREAKPOINT_INFORMATION_ELEMENT, *PEPT_BREAKPOINT_INFORMATION_ELEMENT;

typedef struct _EPT_BREAKPOINT_INFORMATION {
    ULONG NumberOfActiveBreakpoints;
    ULONG NumberOfInactiveBreakpoints;
    ULONG NumberOfLockedPages;
    ULONG NumberOfHookedPages;
    ULONG NumberOfElements;
    EPT_BREAKPOINT_INFORMATION_ELEMENT Elements[ANYSIZE_ARRAY];
} EPT_BREAKPOINT_INFORMATION, *PEPT_BREAKPOINT_INFORMATION;

typedef EPT_BREAKPOINT_INFORMATION QUERY_EPT_BREAKPOINT_INFORMATION_REPLY;
typedef PEPT_BREAKPOINT_INFORMATION PQUERY_EPT_BREAKPOINT_INFORMATION_REPLY;

//=============================================================================
// IOCTL_SET_EPT_BREAKPOINT
//=============================================================================

//
// Ept Breakpoint Log Element (EBLE) Types
//
typedef struct _EBLE_BASIC {
    ULONG_PTR TriggerAddress;
    ULONG HitCount;
} EBLE_BASIC, *PEBLE_BASIC;

typedef struct _EBLE_GENERAL_REGISTER_CONTEXT {
    ULONG_PTR TriggerAddress;
    GENERAL_PURPOSE_REGISTERS Registers;
    ULONG_PTR Flags;
} EBLE_GENERAL_REGISTER_CONTEXT,
*PEBLE_GENERAL_REGISTER_CONTEXT;

typedef struct _EBLE_KEYED_REGISTER_CONTEXT {
    ULONG_PTR KeyValue;
    ULONG_PTR TriggerAddress;
    ULONG HitCount;
    GENERAL_PURPOSE_REGISTERS Registers;
    ULONG_PTR Flags;
} EBLE_KEYED_REGISTER_CONTEXT,
*PEBLE_KEYED_REGISTER_CONTEXT;

typedef struct _EPT_BREAKPOINT_LOG {
    EPT_BREAKPOINT_LOG_HEADER Header;
    union {
        struct {
            EBLE_BASIC Elements[ANYSIZE_ARRAY];
        } Basic;
        struct {
            EBLE_GENERAL_REGISTER_CONTEXT Elements[ANYSIZE_ARRAY];
        } GeneralRegisterContext;
        struct {
            EBLE_KEYED_REGISTER_CONTEXT Elements[ANYSIZE_ARRAY];
        } KeyedRegisterContext;
    } u;
} EPT_BREAKPOINT_LOG, *PEPT_BREAKPOINT_LOG;

typedef struct _SET_EPT_BREAKPOINT_REQUEST {
    ULONG_PTR ProcessId;
    ULONG_PTR Address;
    EPT_BREAKPOINT_TYPE BreakpointType;
    EPT_BREAKPOINT_SIZE BreakpointSize;
    EPT_BREAKPOINT_LOG_TYPE LogType;
    SIZE_T LogSize;
    BOOLEAN MakePageResident;
    X64_REGISTER RegisterKey;
} SET_EPT_BREAKPOINT_REQUEST, *PSET_EPT_BREAKPOINT_REQUEST;

typedef struct _SET_EPT_BREAKPOINT_REPLY {
    HANDLE Handle;
    PEPT_BREAKPOINT_LOG Log;
} SET_EPT_BREAKPOINT_REPLY, *PSET_EPT_BREAKPOINT_REPLY;

//=============================================================================
// IOCTL_DISABLE_EPT_BREAKPOINT
//=============================================================================
typedef struct _DISABLE_EPT_BREAKPOINT_REQUEST {
    HANDLE Handle;
} DISABLE_EPT_BREAKPOINT_REQUEST, *PDISABLE_EPT_BREAKPOINT_REQUEST;

//=============================================================================
// IOCTL_CLEAR_EPT_BREAKPOINT
//=============================================================================
typedef struct _CLEAR_EPT_BREAKPOINT_REQUEST {
    HANDLE Handle;
} CLEAR_EPT_BREAKPOINT_REQUEST, *PCLEAR_EPT_BREAKPOINT_REQUEST;

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
