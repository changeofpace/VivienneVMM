/*++

Module Name:
    
    log_util.h

Abstract:

    This header defines the VivienneVMM logging interface.

Author:

    changeofpace

Environment:

    Kernel mode only.

--*/

#pragma once

#include "..\common\arch_x64.h"

#include "HyperPlatform\log.h"

//=============================================================================
// Logging Interface
//=============================================================================
#ifdef DBG
#define dbg_print(Format, ...)              \
    LogpPrint(                              \
        kLogpLevelDebug | kLogpLevelOptSafe,\
        __FUNCTION__,                       \
        (Format),                           \
        __VA_ARGS__)
#else
// Debug level messages are disabled in release builds.
#define dbg_print(Format, ...) ((VOID)0)
#endif

#define info_print(Format, ...)             \
    LogpPrint(                              \
        kLogpLevelInfo | kLogpLevelOptSafe, \
        __FUNCTION__,                       \
        (Format),                           \
        __VA_ARGS__)

#define warn_print(Format, ...)             \
    LogpPrint(                              \
        kLogpLevelWarn | kLogpLevelOptSafe, \
        __FUNCTION__,                       \
        (Format),                           \
        __VA_ARGS__)

#define err_print(Format, ...)              \
    LogpPrint(                              \
        kLogpLevelError | kLogpLevelOptSafe,\
        __FUNCTION__,                       \
        (Format),                           \
        __VA_ARGS__)

// Log message without prefix text.
#define raw_dbg_print(Format, ...)                                  \
    LogpPrint(                                                      \
        kLogpLevelDebug | kLogpLevelOptSafe | kLogpLevelNoPrefix,   \
        __FUNCTION__,                                               \
        (Format),                                                   \
        __VA_ARGS__)

#define raw_info_print(Format, ...)                                 \
    LogpPrint(                                                      \
        kLogpLevelInfo | kLogpLevelOptSafe | kLogpLevelNoPrefix,    \
        __FUNCTION__,                                               \
        (Format),                                                   \
        __VA_ARGS__)

//
// HwBpTypeToChar
//
FORCEINLINE
CHAR
HwBpTypeToChar(
    _In_ HWBP_TYPE Type
)
{
    switch (Type)
    {
        case HWBP_TYPE::Execute: return 'X';
        case HWBP_TYPE::Write:   return 'W';
        case HWBP_TYPE::Io:      return 'I';
        case HWBP_TYPE::Access:  return 'R';
        default:                 return '?';
    }
}

//
// HwBpSizeToChar
//
FORCEINLINE
CHAR
HwBpSizeToChar(
    _In_ HWBP_SIZE Size
)
{
    switch (Size)
    {
        case HWBP_SIZE::Byte:   return 'B';
        case HWBP_SIZE::Word:   return 'W';
        case HWBP_SIZE::Qword:  return 'Q';
        case HWBP_SIZE::Dword:  return 'D';
        default:                return '?';
    }
}