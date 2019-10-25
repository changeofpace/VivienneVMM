/*++

Copyright (c) 2019 changeofpace. All rights reserved.

Use of this source code is governed by the MIT license. See the 'LICENSE' file
for more information.

--*/

#pragma once

#include <Windows.h>

//=============================================================================
// Constants
//=============================================================================
#define LOG_CONFIG_STDOUT               0x00000001
#define LOG_CONFIG_DEBUGGER             0x00000002
#define LOG_CONFIG_TIMESTAMP_PREFIX     0x00000004

#define LOG_OPTION_APPEND_CRLF          0x00000001

//=============================================================================
// Enumerations
//=============================================================================
typedef enum _LOG_LEVEL {
    LogLevelDebug,
    LogLevelInfo,
    LogLevelWarning,
    LogLevelError,
} LOG_LEVEL, *PLOG_LEVEL;

//=============================================================================
// Meta Interface
//=============================================================================
_Check_return_
BOOL
LogInitialization(
    _In_ ULONG Config
);

//=============================================================================
// Public Interface
//=============================================================================
HRESULT
LogPrintDirect(
    _In_z_ PCSTR pszMessage
);

HRESULT
LogPrint(
    _In_ LOG_LEVEL Level,
    _In_ ULONG Options,
    _In_z_ _Printf_format_string_ PCSTR pszFormat,
    ...
);

#if defined(_DEBUG)
#define DBG_PRINT(Format, ...) \
    LogPrint(LogLevelDebug, LOG_OPTION_APPEND_CRLF, (Format), __VA_ARGS__)
#else
//
// Debug level messages are disabled in release builds.
//
#define DBG_PRINT(Format, ...)
#endif

#define INF_PRINT(Format, ...) \
    LogPrint(LogLevelInfo, LOG_OPTION_APPEND_CRLF, (Format), __VA_ARGS__)

#define WRN_PRINT(Format, ...)  \
    LogPrint(                   \
        LogLevelWarning,        \
        LOG_OPTION_APPEND_CRLF, \
        (Format),               \
        __VA_ARGS__)

#define ERR_PRINT(Format, ...) \
    LogPrint(LogLevelError, LOG_OPTION_APPEND_CRLF, (Format), __VA_ARGS__)
