#pragma once

#include <Windows.h>

typedef HINTERNET(WINAPI* InOpenW)(
    LPCWSTR lpszAgent,
    DWORD   dwAccessType,
    LPCWSTR lpszProxy,
    LPCWSTR lpszProxyBypass,
    DWORD   dwFlags
);

typedef BOOL(WINAPI* InClH)(
    HINTERNET hInternet
);

typedef HINTERNET(WINAPI* InOpUrlW)(
    HINTERNET hInternet,
    LPCWSTR lpszUrl,
    LPCWSTR lpszHeaders,
    DWORD dwHeadersLength,
    DWORD dwFlags,
    DWORD_PTR dwContext
);

typedef BOOL(WINAPI* InReadFile)(
    HINTERNET hFile,
    LPVOID lpBuffer,
    DWORD dwNumberOfBytesToRead,
    LPDWORD lpdwNumberOfBytesRead
);

typedef BOOL(WINAPI* InSetOpt)(
    HINTERNET hInternet,
    DWORD     dwOption,
    LPVOID    lpBuffer,
    DWORD     dwBufferLength
);