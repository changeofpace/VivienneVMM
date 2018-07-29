#pragma once

#include <Windows.h>

#include <intrin.h>

#ifdef _DEBUG
#define DEBUGBREAK                                          \
__try                                                       \
{                                                           \
    __debugbreak();                                         \
}                                                           \
__except (EXCEPTION_BREAKPOINT == GetExceptionCode() ?      \
    EXCEPTION_EXECUTE_HANDLER : EXCEPTION_CONTINUE_SEARCH)  \
{                                                           \
    /* Fall through. */                                     \
}
#else
#define DEBUGBREAK ((void)0)
#endif