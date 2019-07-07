// Copyright (c) 2015-2017, Satoshi Tanda. All rights reserved.
// Use of this source code is governed by a MIT-style license that can be
// found in the LICENSE file.

/// @file
/// Implements an entry point of the driver.

#ifndef POOL_NX_OPTIN
#define POOL_NX_OPTIN 1
#endif
#include "driver.h"
#include "common.h"
#include "global_object.h"
#include "hotplug_callback.h"
#include "log.h"
#include "power_callback.h"
#include "util.h"
#include "vm.h"
#include "performance.h"

#include "..\..\config.h"
#include "..\..\debug_register_facade.h"
#include "..\..\log.h"
#include "..\..\vivienne.h"

extern "C" {
////////////////////////////////////////////////////////////////////////////////
//
// macro utilities
//

////////////////////////////////////////////////////////////////////////////////
//
// constants and macros
//

////////////////////////////////////////////////////////////////////////////////
//
// types
//

////////////////////////////////////////////////////////////////////////////////
//
// prototypes
//

DRIVER_INITIALIZE DriverEntry;

static DRIVER_UNLOAD DriverpDriverUnload;

_IRQL_requires_max_(PASSIVE_LEVEL) bool DriverpIsSuppoetedOS();

#if defined(ALLOC_PRAGMA)
#pragma alloc_text(INIT, DriverEntry)
#pragma alloc_text(PAGE, DriverpDriverUnload)
#pragma alloc_text(INIT, DriverpIsSuppoetedOS)
#endif

////////////////////////////////////////////////////////////////////////////////
//
// variables
//

////////////////////////////////////////////////////////////////////////////////
//
// implementations
//

// A driver entry point
_Use_decl_annotations_ NTSTATUS DriverEntry(PDRIVER_OBJECT driver_object,
                                            PUNICODE_STRING registry_path) {
  UNREFERENCED_PARAMETER(registry_path);
  PAGED_CODE();

  static const wchar_t kLogFilePath[] = CFG_LOGFILE_NTPATH_W;
  static const auto kLogLevel =
      (IsReleaseBuild())
        ? kLogPutLevelInfo | kLogOptDisableFunctionName | kLogOptDisableDbgPrint
        : kLogPutLevelDebug | kLogOptDisableFunctionName;

  auto status = STATUS_UNSUCCESSFUL;
  driver_object->DriverUnload = DriverpDriverUnload;
  //HYPERPLATFORM_COMMON_DBG_BREAK();

  // Request NX Non-Paged Pool when available
  ExInitializeDriverRuntime(DrvRtPoolNxOptIn);

  // Initialize log functions
  bool need_reinitialization = false;
  status = LogInitialization(kLogLevel, kLogFilePath);
  if (status == STATUS_REINITIALIZATION_NEEDED) {
    need_reinitialization = true;
  } else if (!NT_SUCCESS(status)) {
    return status;
  }

  // Test if the system is supported
  if (!DriverpIsSuppoetedOS()) {
    LogTermination();
    return STATUS_CANCELLED;
  }

  // Initialize global variables
  status = GlobalObjectInitialization();
  if (!NT_SUCCESS(status)) {
    LogTermination();
    return status;
  }

  // Initialize perf functions
  status = PerfInitialization();
  if (!NT_SUCCESS(status)) {
    GlobalObjectTermination();
    LogTermination();
    return status;
  }

  // Initialize utility functions
  status = UtilInitialization(driver_object);
  if (!NT_SUCCESS(status)) {
    PerfTermination();
    GlobalObjectTermination();
    LogTermination();
    return status;
  }

  // Initialize power callback
  status = PowerCallbackInitialization();
  if (!NT_SUCCESS(status)) {
    UtilTermination();
    PerfTermination();
    GlobalObjectTermination();
    LogTermination();
    return status;
  }

  // Initialize hot-plug callback
  status = HotplugCallbackInitialization();
  if (!NT_SUCCESS(status)) {
    PowerCallbackTermination();
    UtilTermination();
    PerfTermination();
    GlobalObjectTermination();
    LogTermination();
    return status;
  }

  // Initialize VivienneVMM
  status = VvmmInitialization(driver_object, registry_path);
  if (!NT_SUCCESS(status))
  {
    ERR_PRINT("VvmmInitialization failed: 0x%X", status);
    HotplugCallbackTermination();
    PowerCallbackTermination();
    UtilTermination();
    PerfTermination();
    GlobalObjectTermination();
    LogTermination();
    return status;
  }

#ifdef CFG_ENABLE_DEBUGREGISTERFACADE
  // Initialize DebugRegisterFacade
  status = FcdInitialization();
  if (!NT_SUCCESS(status))
  {
    ERR_PRINT("FcdInitialization failed: 0x%X", status);
    (VOID)VvmmTermination(driver_object);
    HotplugCallbackTermination();
    PowerCallbackTermination();
    UtilTermination();
    PerfTermination();
    GlobalObjectTermination();
    LogTermination();
    return status;
  }
#endif

  // Virtualize all processors
  status = VmInitialization();
  if (!NT_SUCCESS(status)) {
#ifdef CFG_ENABLE_DEBUGREGISTERFACADE
    (VOID)FcdTermination();
#endif
    (VOID)VvmmTermination(driver_object);
    HotplugCallbackTermination();
    PowerCallbackTermination();
    UtilTermination();
    PerfTermination();
    GlobalObjectTermination();
    LogTermination();
    return status;
  }

  // Register re-initialization for the log functions if needed
  if (need_reinitialization) {
    LogRegisterReinitialization(driver_object);
  }

  HYPERPLATFORM_LOG_INFO("The VMM has been installed.");
  return status;
}

// Unload handler
_Use_decl_annotations_ static void DriverpDriverUnload(
    PDRIVER_OBJECT driver_object) {

  NTSTATUS ntstatus = STATUS_SUCCESS;

  UNREFERENCED_PARAMETER(driver_object);
  PAGED_CODE();

  HYPERPLATFORM_COMMON_DBG_BREAK();

  //
  // We must terminate VivienneVMM before devirtualization because we must be
  //  able to enter VMX root mode to perform cleanup.
  //
  ntstatus = VvmmTermination(driver_object);
  if (!NT_SUCCESS(ntstatus))
  {
    ERR_PRINT("VvmmTermination failed: 0x%X", ntstatus);
  }

  VmTermination();

#ifdef CFG_ENABLE_DEBUGREGISTERFACADE
  //
  // We must terminate the DebugRegisterFacade after devirtualization because
  //  the DebugRegisterFacade performs internal cleanup in VMX root mode during
  //  VM teardown.
  //
  ntstatus = FcdTermination();
  if (!NT_SUCCESS(ntstatus))
  {
    ERR_PRINT("FcdTermination failed: 0x%X", ntstatus);
  }
#endif

  HotplugCallbackTermination();
  PowerCallbackTermination();
  UtilTermination();
  PerfTermination();
  GlobalObjectTermination();
  LogTermination();
}

// Test if the system is one of supported OS versions
_Use_decl_annotations_ bool DriverpIsSuppoetedOS() {
  PAGED_CODE();

  RTL_OSVERSIONINFOW os_version = {};
  auto status = RtlGetVersion(&os_version);
  if (!NT_SUCCESS(status)) {
    return false;
  }
  if (os_version.dwMajorVersion != 6 && os_version.dwMajorVersion != 10) {
    return false;
  }
  // 4-gigabyte tuning (4GT) should not be enabled
  if (!IsX64() &&
      reinterpret_cast<ULONG_PTR>(MmSystemRangeStart) != 0x80000000) {
    return false;
  }
  return true;
}

}  // extern "C"
