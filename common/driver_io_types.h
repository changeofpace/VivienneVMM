/*++

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

static_assert(sizeof(HANDLE) == sizeof(ULONG_PTR), "Size check");

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
#define FILE_DEVICE_VVMM    38775

//
// Valid function code range: 2048 - 4095.
//
#define IOCTL_QUERYSYSTEMDEBUGSTATE     CTL_CODE(FILE_DEVICE_VVMM, 3100, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_SETHARDWAREBREAKPOINT     CTL_CODE(FILE_DEVICE_VVMM, 3200, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_CLEARHARDWAREBREAKPOINT   CTL_CODE(FILE_DEVICE_VVMM, 3201, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_CEC_REGISTER              CTL_CODE(FILE_DEVICE_VVMM, 3300, METHOD_BUFFERED, FILE_ANY_ACCESS)

//=============================================================================
// IOCTL_QUERYSYSTEMDEBUGSTATE
//=============================================================================
typedef struct _DEBUG_REGISTER_STATE
{
    ULONG_PTR ProcessId;
    ULONG_PTR Address;
    HWBP_TYPE Type;
    HWBP_SIZE Size;
} DEBUG_REGISTER_STATE, *PDEBUG_REGISTER_STATE;

typedef struct _PROCESSOR_DEBUG_STATE
{
    DEBUG_REGISTER_STATE DebugRegisters[DAR_COUNT];
} PROCESSOR_DEBUG_STATE, *PPROCESSOR_DEBUG_STATE;

typedef struct _SYSTEM_DEBUG_STATE
{
    ULONG Size; // Required size of this struct.
    ULONG NumberOfProcessors;
    PROCESSOR_DEBUG_STATE Processors[ANYSIZE_ARRAY];
} SYSTEM_DEBUG_STATE, *PSYSTEM_DEBUG_STATE;

typedef SYSTEM_DEBUG_STATE QUERYSYSTEMDEBUGSTATE_REPLY;
typedef PSYSTEM_DEBUG_STATE PQUERYSYSTEMDEBUGSTATE_REPLY;

//=============================================================================
// IOCTL_SETHARDWAREBREAKPOINT
//=============================================================================
typedef struct _SETHARDWAREBREAKPOINT_REQUEST
{
    ULONG_PTR ProcessId;
    ULONG Index;
    ULONG_PTR Address;
    HWBP_TYPE Type;
    HWBP_SIZE Size;
} SETHARDWAREBREAKPOINT_REQUEST, *PSETHARDWAREBREAKPOINT_REQUEST;

//=============================================================================
// IOCTL_CLEARHARDWAREBREAKPOINT
//=============================================================================
typedef struct _CLEARHARDWAREBREAKPOINT_REQUEST
{
    ULONG Index;
} CLEARHARDWAREBREAKPOINT_REQUEST, *PCLEARHARDWAREBREAKPOINT_REQUEST;

//=============================================================================
// IOCTL_CEC_REGISTER
//=============================================================================
typedef struct _CEC_REGISTER_REQUEST
{
    ULONG_PTR ProcessId;
    ULONG Index;
    ULONG_PTR Address;
    HWBP_TYPE Type;
    HWBP_SIZE Size;
    X64_REGISTER Register;
    ULONG DurationInMilliseconds; // How long the breakpoint will last.
} CEC_REGISTER_REQUEST, *PCEC_REGISTER_REQUEST;

typedef struct _CEC_REGISTER_VALUES
{
    ULONG Size; // Size of this struct.
    ULONG MaxIndex;
    ULONG NumberOfValues;

    // NOTE Values must be the last defined field .
    ULONG_PTR Values[ANYSIZE_ARRAY];

} CEC_REGISTER_VALUES, *PCEC_REGISTER_VALUES;

typedef CEC_REGISTER_VALUES CEC_REGISTER_REPLY;
typedef PCEC_REGISTER_VALUES PCEC_REGISTER_REPLY;