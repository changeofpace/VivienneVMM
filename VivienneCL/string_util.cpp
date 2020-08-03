/*++

Copyright (c) 2019-2020 changeofpace. All rights reserved.

Use of this source code is governed by the MIT license. See the 'LICENSE' file
for more information.

--*/

#include "string_util.h"

#include <strsafe.h>

#include <iostream>
#include <iterator>
#include <sstream>


//=============================================================================
// To String Interface
//=============================================================================
_Use_decl_annotations_
BOOL
StrUnsignedLongToString(
    BOOLEAN PrependHexPrefix,
    ULONG Value,
    PCHAR pszValue,
    SIZE_T cbValue
)
{
    PCSTR pszFormat = PrependHexPrefix ? "0x%X" : "%X";
    HRESULT hresult = S_OK;
    BOOL status = TRUE;

    hresult = StringCbPrintfA(
        pszValue,
        cbValue,
        pszFormat,
        Value);
    if (FAILED(hresult))
    {
        status = FALSE;
        goto exit;
    }

exit:
    return status;
}


_Use_decl_annotations_
BOOL
StrUnsignedLongLongToString(
    BOOLEAN PrependHexPrefix,
    ULONGLONG Value,
    PCHAR pszValue,
    SIZE_T cbValue
)
{
    PCSTR pszFormat = PrependHexPrefix ? "0x%llX" : "%llX";
    HRESULT hresult = S_OK;
    BOOL status = TRUE;

    hresult = StringCbPrintfA(
        pszValue,
        cbValue,
        pszFormat,
        Value);
    if (FAILED(hresult))
    {
        status = FALSE;
        goto exit;
    }

exit:
    return status;
}


//=============================================================================
// From String Interface
//=============================================================================
_Use_decl_annotations_
BOOL
StrUnsignedLongFromString(
    const std::string& Token,
    BOOLEAN IsHex,
    PULONG pValue
)
{
    int Base = IsHex ? 16 : 10;
    ULONG Value = 0;
    BOOL status = TRUE;

    //
    // Zero out parameters.
    //
    *pValue = 0;

    try
    {
        Value = std::stoul(Token, nullptr, Base);
    }
    catch (const std::exception&)
    {
        status = FALSE;
        goto exit;
    }

    //
    // Set out parameters.
    //
    *pValue = Value;

exit:
    return status;
}


_Use_decl_annotations_
BOOL
StrUnsignedLongLongFromString(
    const std::string& Token,
    BOOLEAN IsHex,
    PULONGLONG pValue
)
{
    int Base = IsHex ? 16 : 10;
    ULONGLONG Value = 0;
    BOOL status = TRUE;

    //
    // Zero out parameters.
    //
    *pValue = 0;

    try
    {
        Value = std::stoull(Token, nullptr, Base);
    }
    catch (const std::exception&)
    {
        status = FALSE;
        goto exit;
    }

    //
    // Set out parameters.
    //
    *pValue = Value;

exit:
    return status;
}


_Use_decl_annotations_
BOOL
StrUnsignedLongPtrFromString(
    const std::string& Token,
    BOOLEAN IsHex,
    PULONG_PTR pValue
)
{
#if defined(_WIN64)
    return StrUnsignedLongLongFromString(Token, IsHex, pValue);
#else
    return StrUnsignedLongFromString(Token, IsHex, pValue);
#endif
}


//=============================================================================
// Tokenizer Interface
//=============================================================================
_Use_decl_annotations_
SIZE_T
StrSplitStringByDelimiter(
    CHAR Delimiter,
    const std::string& Input,
    std::vector<std::string>& Output
)
{
    std::string Token = {};
    std::stringstream Stream(Input);

    //
    // Zero out parameters.
    //
    Output.clear();

    while (std::getline(Stream, Token, Delimiter))
    {
        Output.emplace_back(Token);
    }

    return Output.size();
}


_Use_decl_annotations_
SIZE_T
StrSplitStringByWhitespace(
    std::string& Input,
    std::vector<std::string>& Output
)
{
    std::string Token;
    std::stringstream Stream(Input);

    Output = {
        std::istream_iterator<std::string>{Stream},
        std::istream_iterator<std::string>{}
    };

    return Output.size();
}
