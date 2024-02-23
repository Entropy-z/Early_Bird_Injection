#include <windows.h>

#pragma once

PCHAR strcpyA(_Inout_ PCHAR String1, _In_ LPCSTR String2)
{
	PCHAR p = String1;

	while ((*p++ = *String2++) != 0);

	return String1;
}

PWCHAR strcpyW(_Inout_ PWCHAR String1, _In_ LPCWSTR String2)
{
	PWCHAR p = String1;

	while ((*p++ = *String2++) != 0);

	return String1;
}