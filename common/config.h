/*++

Copyright (c) 2019-2020 changeofpace. All rights reserved.

Use of this source code is governed by the MIT license. See the 'LICENSE' file
for more information.

Module Name:

    config.h

Abstract:

    This header defines names and constants which can be modified to enable or
     disable VVMM features.

Author:

    changeofpace

Environment:

    Kernel and user mode.

--*/

#pragma once

//=============================================================================
// Names
//=============================================================================
/*
    The device and symbolic link name for the VivienneVMM driver.
*/
#define CFG_VIVIENNE_DEVICE_NAME        L"vivienne"

/*
    A sentinel value returned from cpuid which is used to determine if
    VivienneVMM is already running on the local machine.
*/
#define CFG_NAME_VIVIENNE_SIGNATURE     ((int)'mmvv')

#if defined(_KERNEL_MODE)
//=============================================================================
// Logging
//=============================================================================
/*
    The NT file path for the driver log file.
*/
#define CFG_LOG_NT_PATH_W    L"\\SystemRoot\\vivienne.log"

/*
    The number of pages used for the driver log buffer.
*/
#if defined(DBG)
#define CFG_LOG_NUMBER_OF_PAGES     16
#else
#define CFG_LOG_NUMBER_OF_PAGES     64
#endif

/*
    The interval in milliseconds for flushing buffered log entries to the
    driver log file.
*/
#if defined(DBG)
#define CFG_LOG_FLUSH_INTERVAL_MS   50
#else
#define CFG_LOG_FLUSH_INTERVAL_MS   50
#endif

/*
    Append driver log file data to an existing log file if it exists.
*/
///#define CFG_LOG_APPEND_DATA_TO_EXISTING_LOG_FILE
#endif

//=============================================================================
// Breakpoint Manager
//=============================================================================
/*
    The breakpoint control interface.
*/
///#define CFG_BPM_HARDWARE_BREAKPOINT_MANAGER
#define CFG_BPM_EPT_BREAKPOINT_MANAGER

#if defined(CFG_BPM_EPT_BREAKPOINT_MANAGER)
//=============================================================================
// Ept Breakpoint Manager
//=============================================================================
/*
    The maximum size in bytes for an ept breakpoint log.
*/
#define CFG_EBM_LOG_SIZE_MAX    (0x1000 * 50)
#endif

#if defined(CFG_BPM_HARDWARE_BREAKPOINT_MANAGER)
//=============================================================================
// Hardware Breakpoint Manager
//=============================================================================
/*
    Prevent the guest from modifying debug registers.

    WARNING Disabling this can result in corrupt hardware breakpoint manager
    state if the guest writes to the debug registers.
*/
///#define CFG_HBM_ENABLE_DEBUG_REGISTER_FACADE
#endif

//-----------------------------------------------------------------------------
// End of user-controlled options.
//-----------------------------------------------------------------------------

//=============================================================================
// Asserts
//=============================================================================
#if !(defined(CFG_BPM_HARDWARE_BREAKPOINT_MANAGER) ^ defined(CFG_BPM_EPT_BREAKPOINT_MANAGER))
#error Define one breakpoint manager.
#endif

#if defined(CFG_HBM_ENABLE_DEBUG_REGISTER_FACADE) && !defined(CFG_BPM_HARDWARE_BREAKPOINT_MANAGER)
#error The Debug Register Facade module is only valid for the hardware breakpoint manager.
#endif
