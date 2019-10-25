/*++

Copyright (c) 2019 changeofpace. All rights reserved.

Use of this source code is governed by the MIT license. See the 'LICENSE' file
for more information.

--*/

#include "log.h"

#define NTSTRSAFE_NO_CB_FUNCTIONS

#include <cstdio>
#include <strsafe.h>

#include "debug.h"
#include "ntdll.h"


//=============================================================================
// Constants
//=============================================================================
#define OUTPUT_BUFFER_CCH_MAX       512
#define TIME_BUFFER_CCH             25
#define MESSAGE_BUFFER_CCH_MAX \
    (OUTPUT_BUFFER_CCH_MAX - TIME_BUFFER_CCH - 80)

#define VALID_CONFIG_OUTPUT_MASK \
    (LOG_CONFIG_STDOUT | LOG_CONFIG_DEBUGGER | LOG_CONFIG_TIMESTAMP_PREFIX)


//=============================================================================
// Private Types
//=============================================================================
typedef struct _LOG_CONTEXT {
    ULONG Config;
} LOG_CONTEXT, *PLOG_CONTEXT;


//=============================================================================
// Module Globals
//=============================================================================
static LOG_CONTEXT g_LogContext = {};


//=============================================================================
// Meta Interface
//=============================================================================
_Use_decl_annotations_
BOOL
LogInitialization(
    ULONG Config
)
{
    BOOL status = TRUE;

    if ((~VALID_CONFIG_OUTPUT_MASK) & Config)
    {
        SetLastError(ERROR_INVALID_PARAMETER);
        status = FALSE;
        goto exit;
    }

    //
    // Initialize the global context.
    //
    g_LogContext.Config = Config;

exit:
    return status;
}


_Use_decl_annotations_
HRESULT
LogPrintDirect(
    PCSTR pszMessage
)
{
    int printstatus = 0;
    HRESULT hresult = S_OK;

    if (LOG_CONFIG_DEBUGGER & g_LogContext.Config)
    {
        OutputDebugStringA(pszMessage);
    }

    if (LOG_CONFIG_STDOUT & g_LogContext.Config)
    {
        printstatus = printf("%s", pszMessage);
        if (0 > printstatus)
        {
            hresult = E_FAIL;
            DEBUG_BREAK;
            goto exit;
        }
    }

exit:
    return hresult;
}


_Use_decl_annotations_
HRESULT
LogPrint(
    LOG_LEVEL Level,
    ULONG Options,
    PCSTR pszFormat,
    ...
)
{
    va_list VarArgs = {};
    CHAR szMessageBuffer[MESSAGE_BUFFER_CCH_MAX] = {};
    CHAR szTimeBuffer[TIME_BUFFER_CCH] = {};
    SYSTEMTIME LocalTime = {};
    BOOL fAppendCrLf = FALSE;
    CHAR szOutputBuffer[OUTPUT_BUFFER_CCH_MAX] = {};
    int printstatus = 0;
    HRESULT hresult = S_OK;

    UNREFERENCED_PARAMETER(Level);

    va_start(VarArgs, pszFormat);
    hresult = StringCchVPrintfA(
        szMessageBuffer,
        RTL_NUMBER_OF(szMessageBuffer),
        pszFormat,
        VarArgs);
    va_end(VarArgs);
    if (FAILED(hresult))
    {
        DEBUG_BREAK;
        goto exit;
    }

    if (LOG_CONFIG_TIMESTAMP_PREFIX & g_LogContext.Config)
    {
        GetLocalTime(&LocalTime);

        hresult = StringCchPrintfA(
            szTimeBuffer,
            RTL_NUMBER_OF(szTimeBuffer),
            "%02hd:%02hd:%02hd.%03hd    ",
            LocalTime.wHour,
            LocalTime.wMinute,
            LocalTime.wSecond,
            LocalTime.wMilliseconds);
        if (FAILED(hresult))
        {
            DEBUG_BREAK;
            goto exit;
        }
    }

    if (LOG_OPTION_APPEND_CRLF & Options)
    {
        fAppendCrLf = TRUE;
    }

    hresult = StringCchPrintfA(
        szOutputBuffer,
        RTL_NUMBER_OF(szOutputBuffer),
        "%s%s%s",
        szTimeBuffer,
        szMessageBuffer,
        fAppendCrLf ? "\r\n" : "");
    if (FAILED(hresult))
    {
        DEBUG_BREAK;
        goto exit;
    }

    if (LOG_CONFIG_DEBUGGER & g_LogContext.Config)
    {
        OutputDebugStringA(szOutputBuffer);
    }

    if (LOG_CONFIG_STDOUT & g_LogContext.Config)
    {
        printstatus = printf("%s", szOutputBuffer);
        if (0 > printstatus)
        {
            hresult = E_FAIL;
            DEBUG_BREAK;
            goto exit;
        }
    }

exit:
    return hresult;
}
