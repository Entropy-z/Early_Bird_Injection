#pragma once

#include <Windows.h>
#include "strcpy.h"
#include "strlen.h"

PWCHAR strcatW(_Inout_ PWCHAR String, _In_ LPCWSTR String2)
{
	strcpyW(&String[strlenW(String)], String2);

	return String;
}

PCHAR strcatA(_Inout_ PCHAR String, _In_ LPCSTR String2)
{
	strcpyA(&String[strlenA(String)], String2);

	return String;
}