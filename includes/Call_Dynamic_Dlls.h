#pragma once

#include <winternl.h>
#include <Windows.h>
#include <stdio.h>
#include "crc32h.h"

FARPROC GetProcAddressR(IN HMODULE hModule, IN LPCSTR lpApiName) {

	// We do this to avoid casting at each time we use 'hModule'
	PBYTE pBase = (PBYTE)hModule;

	// Getting the dos header and doing a signature check
	PIMAGE_DOS_HEADER	pImgDosHdr		= (PIMAGE_DOS_HEADER)pBase;
	if (pImgDosHdr->e_magic != IMAGE_DOS_SIGNATURE)
		return NULL;

	// Getting the nt headers and doing a signature check
	PIMAGE_NT_HEADERS	pImgNtHdrs		= (PIMAGE_NT_HEADERS)(pBase + pImgDosHdr->e_lfanew);
	if (pImgNtHdrs->Signature != IMAGE_NT_SIGNATURE)
		return NULL;

	// Getting the optional header
	IMAGE_OPTIONAL_HEADER	ImgOptHdr	= pImgNtHdrs->OptionalHeader;

	// Getting the image export table
	PIMAGE_EXPORT_DIRECTORY pImgExportDir = (PIMAGE_EXPORT_DIRECTORY) (pBase + ImgOptHdr.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

	// Getting the function's names array pointer
	PDWORD FunctionNameArray = (PDWORD)(pBase + pImgExportDir->AddressOfNames);

	// Getting the function's addresses array pointer
	PDWORD FunctionAddressArray = (PDWORD)(pBase + pImgExportDir->AddressOfFunctions);

	// Getting the function's ordinal array pointer
	PWORD  FunctionOrdinalArray = (PWORD)(pBase + pImgExportDir->AddressOfNameOrdinals);


	// Looping through all the exported functions
	for (DWORD i = 0; i < pImgExportDir->NumberOfFunctions; i++){

		// Getting the name of the function
		CHAR* pFunctionName = (CHAR*)(pBase + FunctionNameArray[i]);

		// Getting the address of the function through its ordinal
		FARPROC pFunctionAddress = (FARPROC)(pBase + FunctionAddressArray[FunctionOrdinalArray[i]]);

		// Searching for the function specified
		if (strcmp(lpApiName, pFunctionName) == 0){
			//printf("[ %0.4d ] FOUND API -\t NAME: %s -\t ADDRESS: 0x%p  -\t ORDINAL: %d\n", i, pFunctionName, pFunctionAddress, FunctionOrdinalArray[i]);
			return pFunctionAddress;
		}
	}

	return NULL;
}

WCHAR toLower(WCHAR ch) {
    if (ch >= L'A' && ch <= L'Z') {
        // Converte caracteres mai�sculos para min�sculos
        return ch + (L'a' - L'A');
    }
    return ch;
}

BOOL IsStringEqual(IN LPCWSTR Str1, IN LPCWSTR Str2) {
    WCHAR lStr1[MAX_PATH], lStr2[MAX_PATH];

    int len1 = lstrlenW(Str1);
    int len2 = lstrlenW(Str2);

    int i, j;

    if (len1 >= MAX_PATH || len2 >= MAX_PATH)
        return FALSE;

    for (i = 0; i < len1; i++) {
        lStr1[i] = toLower(Str1[i]);
    }
    lStr1[i++] = L'\0';

    for (j = 0; j < len2; j++) {
        lStr2[j] = toLower(Str2[j]);
    }
    lStr2[j++] = L'\0';

    if (lstrcmpiW(lStr1, lStr2) == 0)
        return TRUE;

    return FALSE;
}

HMODULE GetModuleHandleR(IN LPCWSTR szModuleName) {

#ifdef _WIN64 // if compiling as x64
	PPEB					pPeb		= (PEB*)(__readgsqword(0x60));
#elif _WIN32 // if compiling as x32
	PPEB					pPeb		= (PEB*)(__readfsdword(0x30));
#endif
	PPEB_LDR_DATA			pLdr		= (PPEB_LDR_DATA)(pPeb->Ldr);

	PLDR_DATA_TABLE_ENTRY	pDte		= (PLDR_DATA_TABLE_ENTRY)(pLdr->InMemoryOrderModuleList.Flink);

	while (pDte) {


		if (pDte->FullDllName.Length != NULL) {


			if (IsStringEqual(pDte->FullDllName.Buffer, szModuleName)) {
				//wprintf(L"[+] Found Dll \"%s\" \n", pDte->FullDllName.Buffer);
#ifdef STRUCTSreturn (HMODULE)(pDte->InInitializationOrderLinks.Flink);
#elsereturn (HMODULE)pDte->Reserved2[0];
#endif // STRUCTS}

			// wprintf(L"[i] \"%s\" \n", pDte->FullDllName.Buffer);
		}
		else {
			break;
		}


		pDte = *(PLDR_DATA_TABLE_ENTRY*)(pDte);

	}

	return NULL;

	}
}
