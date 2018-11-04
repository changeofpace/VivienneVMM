#pragma once

#include <Windows.h>

#include <string>
#include <vector>

//=============================================================================
// Constants
//=============================================================================
#define STR_ADDRESS_SIZE 50

//=============================================================================
// To String Interface
//=============================================================================
_Check_return_
BOOL
StrUnsignedLongToString(
    _In_ BOOLEAN PrependHexPrefix,
    _In_ ULONG Value,
    _Out_ PCHAR pszValue,
    _In_ SIZE_T cbValue
);

_Check_return_
BOOL
StrUnsignedLongLongToString(
    _In_ BOOLEAN PrependHexPrefix,
    _In_ ULONGLONG Value,
    _Out_ PCHAR pszValue,
    _In_ SIZE_T cbValue
);

//=============================================================================
// From String Interface
//=============================================================================
_Check_return_
BOOL
StrUnsignedLongFromString(
    _In_ const std::string& Token,
    _In_ BOOLEAN IsHex,
    _Out_ PULONG pValue
);

_Check_return_
BOOL
StrUnsignedLongLongFromString(
    _In_ const std::string& Token,
    _In_ BOOLEAN IsHex,
    _Out_ PULONGLONG pValue
);

//=============================================================================
// Tokenizer Interface
//=============================================================================
_Check_return_
SIZE_T
StrSplitStringByDelimiter(
    _In_ CHAR Delimiter,
    _In_ const std::string& Input,
    _Out_ std::vector<std::string>& Output
);

_Check_return_
SIZE_T
StrSplitStringByWhitespace(
    _In_ std::string& Input,
    _Out_ std::vector<std::string>& Output
);
