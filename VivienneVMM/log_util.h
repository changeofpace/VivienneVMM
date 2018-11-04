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
#include "..\common\driver_io_types.h"

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

//=============================================================================
// Utilities
//=============================================================================

#define LOG_UTIL_UNKNOWN_CHARACTER  '?'
#define LOG_UTIL_UNKNOWN_STRING     "(UNK)"

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
        default:
            break;
    }

    return LOG_UTIL_UNKNOWN_CHARACTER;
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
        default:
            break;
    }

    return LOG_UTIL_UNKNOWN_CHARACTER;
}

//
// GpRegToString
//
FORCEINLINE
PCSTR
GpRegToString(
    _In_ X64_REGISTER Register
)
{
    switch (Register)
    {
        case REGISTER_RIP: return "rip";
        case REGISTER_RAX: return "rax";
        case REGISTER_RCX: return "rcx";
        case REGISTER_RDX: return "rdx";
        case REGISTER_RDI: return "rdi";
        case REGISTER_RSI: return "rsi";
        case REGISTER_RBX: return "rbx";
        case REGISTER_RBP: return "rbp";
        case REGISTER_RSP: return "rsp";
        case REGISTER_R8:  return "r8";
        case REGISTER_R9:  return "r9";
        case REGISTER_R10: return "r10";
        case REGISTER_R11: return "r11";
        case REGISTER_R12: return "r12";
        case REGISTER_R13: return "r13";
        case REGISTER_R14: return "r14";
        case REGISTER_R15: return "r15";
        default:
            break;
    }

    return LOG_UTIL_UNKNOWN_STRING;
}

//
// MemoryDataTypeToChar
//
FORCEINLINE
CHAR
MemoryDataTypeToChar(
    _In_ MEMORY_DATA_TYPE MemoryDataType
)
{
    switch (MemoryDataType)
    {
        case MDT_BYTE:   return 'B';
        case MDT_WORD:   return 'W';
        case MDT_DWORD:  return 'D';
        case MDT_QWORD:  return 'Q';
        case MDT_FLOAT:  return 'F';
        case MDT_DOUBLE: return 'O';
        default:
            break;
    }

    return LOG_UTIL_UNKNOWN_CHARACTER;
}
