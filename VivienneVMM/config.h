/*++

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
// General
//=============================================================================

/*
 * A sentinel value returned from cpuid which is used to determine if
 *   VivienneVMM is already running on the local machine.
 */
#define CFG_VVMM_SENTINEL ((int)'mmvv')

//=============================================================================
// Features
//=============================================================================

/*
 * Prevent the guest from modifying debug registers.
 *
 * WARNING Disabling this can result in corrupt breakpoint manager state if
 *  the guest writes to the debug registers.
 */
#define CFG_ENABLE_DR_FACADE

 /*
 * Convenience option to enable or disable the initialization and termination
 *  of EPT support. This project currently does not utilize EPT so this option
 *  is disabled by default.
 */
 //#define CFG_ENABLE_EPT

//=============================================================================
// Logging
//=============================================================================

/*
 * An NT file path used to store the log file.
 */
#define CFG_LOGFILE_NTPATH_W L"\\SystemRoot\\vivienne.log"

/*
 * Log buffer size in pages. (see HyperPlatform.log!kLogpBufferSizeInPages)
 */
#ifdef DBG
#define CFG_LOG_BUFFER_SIZE_PAGES 32ul
#else
#define CFG_LOG_BUFFER_SIZE_PAGES 16ul
#endif

/*
 * Convenience option to toggle the execution of breakpoints on abnormal log
 *  events. (see HyperPlatform.log!LogpDbgBreak)
 */
//#define CFG_ENABLE_LOG_ERROR_BREAKS

/*
 * Enable verbose logging for the breakpoint manager.
 */
//#define CFG_VERBOSE_BREAKPOINTMANAGER

/*
 * Enable logging of MovDr VM exit events.
 *
 * WARNING This can generate an excessive amount of prints and degrade
 *  performance. If a thread installs a thread-local breakpoint then the debug
 *  registers must be saved and loaded whenever a context switch occurs in the
 *  owning thread. Attached kernel debuggers may cause a constant stream of
 *  prints.
 *
 * TODO Determine if MovDr logging causes an infinite, recursive loop because
 *  file logging occurs outside of VMX root mode.
 */
#ifdef CFG_ENABLE_DR_FACADE
//#define CFG_LOG_MOVDR_EVENTS
#endif

/*
 * Enable verbose logging for capture execution context requests.
 */
//#define CFG_VERBOSE_CAPTUREEXECUTIONCONTEXT