#include <Windows.h>

#include "Structs.h"
#include "Utils.h"
#include "Syscalls.h"
#include "Debug.h"

//==============================================================================================================================================================================



BOOL InitializeDirectNtCalls() {
	HashStruct SyscallHashStruct = {

		.NtAllocateVirtualMemory_Hash	= NtAllocateVirtualMemory_StrHashed,
		.NtProtectVirtualMemory_Hash	= NtProtectVirtualMemory_StrHashed,
		.NtCreateSection_Hash			= NtCreateSection_StrHashed,
		.NtOpenSection_Hash				= NtOpenSection_StrHashed,
		.NtMapViewOfSection_Hash		= NtMapViewOfSection_StrHashed,
		.NtUnmapViewOfSection_Hash		= NtUnmapViewOfSection_StrHashed,
		.NtClose_Hash					= NtClose_StrHashed,

	};


	return InitializeStruct(SEED, &SyscallHashStruct);
}


//==============================================================================================================================================================================



//==============================================================================================================================================================================



LPVOID GetDllFromKnownDlls(PWSTR DllName) {

	PVOID pModule = NULL;
	HANDLE hSection = INVALID_HANDLE_VALUE;
	UNICODE_STRING UniStr;
	OBJECT_ATTRIBUTES ObjAtr;
	NTSTATUS STATUS;

	WCHAR FullName[MAX_PATH];
	WCHAR Buf[MAX_PATH] = { L'\\', L'K', L'n', L'o', L'w', L'n', L'D', L'l', L'l', L's', L'\\' };

	_strcpy(FullName, Buf);
	_strcat(FullName, DllName);
	_RtlInitUnicodeString(&UniStr, FullName);


	InitializeObjectAttributes(
		&ObjAtr,
		&UniStr,
		0x40L,
		NULL,
		NULL
	);


	hSection = NtOpenSection(SECTION_MAP_READ | SECTION_MAP_EXECUTE, &ObjAtr, &STATUS);
	if (!NT_SUCCESS(STATUS) || hSection == INVALID_HANDLE_VALUE) {
#ifdef DEBUG
		PRINT(L"[!] %s : NtOpenSection Failed : 0x%0.8X (Utils.c:63)\n", FullName, STATUS);
#endif // DEBUG
		return NULL;
	}


	pModule = NtMapViewOfSection(hSection, NULL, NULL, NULL, PAGE_READONLY, &STATUS);
	if (!NT_SUCCESS(STATUS)) {
#ifdef DEBUG
		PRINT(L"[!] %s : NtMapViewOfSection Failed : 0x%0.8X (Utils.c:72)\n", FullName, STATUS);
#endif // DEBUG
		return NULL;
	}

#ifdef DEBUG
	PRINT(L"[+] The module \"%s\" is successfully mapped to 0x%p \n", FullName, pModule);
#endif // DEBUG

	return pModule;
}




BOOL RefreshNtdll() {
	
	NTSTATUS	STATUS			= NULL;
	DWORD		OldProtection	= NULL;
	PVOID		pLocalAddress	= NULL, pRemoteAddress	= NULL;
	SIZE_T		sLocalSize		= NULL;

	LPVOID		KnownDllNtdllModule		= GetDllFromKnownDlls((PWSTR)NTDLLDLLW);
	LPVOID		CurrentNtdllModule		= GetModuleHandleH(NTDLLDLLA);

	if (KnownDllNtdllModule == NULL || CurrentNtdllModule == NULL) {
		return FALSE;
	}
	PIMAGE_DOS_HEADER		CurrentNtdllDosHdr = (PIMAGE_DOS_HEADER)CurrentNtdllModule;
	if (CurrentNtdllDosHdr->e_magic != IMAGE_DOS_SIGNATURE){
		return FALSE;
	}
	PIMAGE_NT_HEADERS		CurrentNtdllNtHdr = (PIMAGE_NT_HEADERS)((ULONG_PTR)CurrentNtdllModule + CurrentNtdllDosHdr->e_lfanew);
	if (CurrentNtdllNtHdr->Signature != IMAGE_NT_SIGNATURE) {
		return FALSE;
	}
	
	
	for (int i = 0; i < CurrentNtdllNtHdr->FileHeader.NumberOfSections; i++) {
		PIMAGE_SECTION_HEADER pImgSec = (PIMAGE_SECTION_HEADER)((DWORD_PTR)IMAGE_FIRST_SECTION(CurrentNtdllNtHdr) + ((DWORD_PTR)IMAGE_SIZEOF_SECTION_HEADER * i));
		if ((*(ULONG*)pImgSec->Name | 0x20202020) == 'xet.') {
			sLocalSize = pImgSec->Misc.VirtualSize;
			pLocalAddress = (PVOID)((ULONG_PTR)CurrentNtdllModule + pImgSec->VirtualAddress);
			pRemoteAddress = (PVOID)((ULONG_PTR)KnownDllNtdllModule + pImgSec->VirtualAddress);
		}
	}

	if (sLocalSize == NULL || pLocalAddress == NULL || pRemoteAddress == NULL) {
#ifdef DEBUG
		PRINT(L"[!] Failed To Get Details Of The Txt Section Of The Module To Replace (Utils.c:122)\n");
#endif // DEBUG
		return FALSE;
	}

	// change protection to start patching
	OldProtection = NtProtectVirtualMemory(NULL, pLocalAddress, sLocalSize, PAGE_EXECUTE_WRITECOPY, &STATUS);
	if (!NT_SUCCESS(STATUS)) {
#ifdef DEBUG
		PRINT(L"[!] NtProtectVirtualMemory [1] Failed : 0x%0.8X (Utils.c:130)\n", STATUS);
#endif
		return FALSE;
	}

#ifdef DEBUG
	PRINT(L"[i] Replacing 0x%p with 0x%p of size  %d \n", pLocalAddress, pRemoteAddress, sLocalSize);
#endif
	// replacing
	_memcpy(pLocalAddress, pRemoteAddress, sLocalSize);


	// re-fix the memory permissions to what it was
	NtProtectVirtualMemory(NULL, pLocalAddress, sLocalSize, OldProtection, &STATUS);
	if (!NT_SUCCESS(STATUS)) {
#ifdef DEBUG
		PRINT(L"[!] NtProtectVirtualMemory [2] Failed : 0x%0.8X (Utils.c:146)\n", STATUS);
#endif
		return FALSE;
	}

	NtUnmapViewOfSection(NULL, KnownDllNtdllModule, &STATUS);
	if (!NT_SUCCESS(STATUS)) {
#ifdef DEBUG
		PRINT(L"[!] NtUnmapViewOfSection  Failed : 0x%0.8X (Utils.c:154)\n", STATUS);
#endif
		return FALSE;
	}
	
	return TRUE;
}

//==============================================================================================================================================================================






//==============================================================================================================================================================================


HMODULE GetModuleHandleH(LPSTR ModuleName) {
	if (ModuleName == NULL)
		return NULL;
	
	PPEB pPeb = (PPEB)__readgsqword(0x60);
	PPEB_LDR_DATA pLdr = (PPEB_LDR_DATA)(pPeb->Ldr);
	PLDR_DATA_TABLE_ENTRY pDte = (PLDR_DATA_TABLE_ENTRY)(pLdr->InMemoryOrderModuleList.Flink);
	
	while (pDte) {
		if (pDte->FullDllName.Buffer != NULL) {
			if (pDte->FullDllName.Length < MAX_PATH - 1) {
				CHAR DllName[MAX_PATH] = { 0 };
				DWORD i = 0;
				while (pDte->FullDllName.Buffer[i] && i < sizeof(DllName) - 1) {
					DllName[i] = _ToUpper((char)pDte->FullDllName.Buffer[i]);
					i++;
				}
				DllName[i] = '\0';
				if (HASH(DllName) == HASH(ModuleName)) {
					return (HMODULE)(pDte->InInitializationOrderLinks.Flink);
				}
			}
		}
		else {
			break;
		}

		pDte = (PLDR_DATA_TABLE_ENTRY)DEREF_64(pDte);
	}
	return NULL;
}



HMODULE LoadLibraryH(LPSTR DllName) {

	NTSTATUS		STATUS				= NULL;
	UNICODE_STRING	Ustr				= { 0 };
	WCHAR			wDllName[MAX_PATH]	= { 0 };
	HMODULE			hModule				= NULL;

	_CharToWchar(wDllName, DllName, _StrlenA(DllName));

	USHORT DestSize = _StrlenW(wDllName) * sizeof(WCHAR);
	Ustr.Length = DestSize;
	Ustr.MaximumLength = DestSize + sizeof(WCHAR);
	Ustr.Buffer = wDllName;


	fnLdrLoadDll pLdrLoadDll = (fnLdrLoadDll)GetProcAddressH(GetModuleHandleH(NTDLLDLLA), LdrLoadDll_StrHashed);
	if(pLdrLoadDll != NULL && NT_SUCCESS((STATUS = pLdrLoadDll(NULL, 0, &Ustr, &hModule)))){
		return hModule;
	}
#ifdef DEBUG
	PRINT(L"[!] LdrLoadDll Faild To Load \"%s\" 0x%0.8X (Utils.c:224)\n", wDllName, STATUS);
#endif // DEBUG

	return NULL;
}



FARPROC GetProcAddressH (HMODULE hModule, DWORD Hash) {

	if (hModule == NULL || Hash == NULL)
		return NULL;

	HMODULE hModule2 = NULL;
	UINT64	DllBaseAddress = (UINT64)hModule;

	PIMAGE_NT_HEADERS NtHdr = (PIMAGE_NT_HEADERS)(DllBaseAddress + ((PIMAGE_DOS_HEADER)DllBaseAddress)->e_lfanew);
	PIMAGE_DATA_DIRECTORY pDataDir = (PIMAGE_DATA_DIRECTORY)&NtHdr->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
	PIMAGE_EXPORT_DIRECTORY ExportTable = (PIMAGE_EXPORT_DIRECTORY)(DllBaseAddress + pDataDir->VirtualAddress);

	UINT64 FunctionNameAddressArray = (DllBaseAddress + ExportTable->AddressOfNames);
	UINT64 FunctionAddressArray = (DllBaseAddress + ExportTable->AddressOfFunctions);
	UINT64 FunctionOrdinalAddressArray = (DllBaseAddress + ExportTable->AddressOfNameOrdinals);
	UINT64 pFunctionAddress = NULL;

	DWORD	dwCounter = ExportTable->NumberOfNames;

	while (dwCounter--) {
		char* FunctionName = (char*)(DllBaseAddress + DEREF_32(FunctionNameAddressArray));

		if (HASH(FunctionName) == Hash) {
			FunctionAddressArray += (DEREF_16(FunctionOrdinalAddressArray) * sizeof(DWORD));
			pFunctionAddress = (UINT64)(DllBaseAddress + DEREF_32(FunctionAddressArray));

			if (pDataDir->VirtualAddress <= DEREF_32(FunctionAddressArray) && (pDataDir->VirtualAddress + pDataDir->Size) >= DEREF_32(FunctionAddressArray)) {
				CHAR Library[MAX_PATH] = { 0 };
				CHAR Function[MAX_PATH] = { 0 };
				UINT32 Index = _CopyDotStr((PCHAR)pFunctionAddress);
				if (Index == 0) {
					return NULL;
				}
				_memcpy((PVOID)Library, (PVOID)pFunctionAddress, Index);
				_memcpy((PVOID)Function, (PVOID)((ULONG_PTR)pFunctionAddress + Index + 1), _StrlenA((LPCSTR)((ULONG_PTR)pFunctionAddress + Index + 1)));
				if ((hModule2 = LoadLibraryH(Library)) != NULL) {
					pFunctionAddress = (UINT64)GetProcAddressH(hModule2, HASH(Function));
				}
			}
			break;
		}
		FunctionNameAddressArray += sizeof(DWORD);
		FunctionOrdinalAddressArray += sizeof(WORD);
	}
	return (FARPROC)pFunctionAddress;
}





//==============================================================================================================================================================================





