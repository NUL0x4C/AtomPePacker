#include <Windows.h>
#include <stdio.h>

#include "Header.h"
#include "easylzma.h"
#pragma comment (lib, "easylzma_s.lib")

#define _64PE	0x064
#define _32PE	0x032
#define DllPE	0xD11
#define NotPE	0x000

#define _STORE		"Modules\\"
#define _x64DllStub	"DllPP64Stub.dll"
#define _x32DllStub	"DllPP32Stub.dll"	// working on it :)
#define _x64STUB	"PP64Stub.exe"
#define _x32STUB	"PP32Stub.exe"		// working on it :)

#define _x64STUB_H	"H_PP64Stub.exe"

BOOL ReportError(const char* ApiName) {
	printf("[!] \"%s\" [ FAILED ] \t%d \n", ApiName, GetLastError());
	return FALSE;
}


BOOL ReadPayloadFile(const char* FileInput, PDWORD sPayloadSize, unsigned char** pPayloadAddress) {

	HANDLE hFile = INVALID_HANDLE_VALUE;
	DWORD FileSize = NULL;
	DWORD lpNumberOfBytesRead = NULL;

	hFile = CreateFileA(FileInput, GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_READONLY, NULL);
	if (hFile == INVALID_HANDLE_VALUE) {
		return ReportError("CreateFileA");
	}

	FileSize = GetFileSize(hFile, NULL);

	unsigned char* Payload = (unsigned char*)malloc(FileSize);

	ZeroMemory(Payload, FileSize);

	if (!ReadFile(hFile, Payload, FileSize, &lpNumberOfBytesRead, NULL)) {
		return ReportError("ReadFile");
	}

	*pPayloadAddress = Payload;
	*sPayloadSize = lpNumberOfBytesRead;

	CloseHandle(hFile);

	if (*pPayloadAddress != NULL && *sPayloadSize != NULL)
		return TRUE;

	return FALSE;
}




INT CheckPeArch(PBYTE pPe) {

	PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)pPe;
	PIMAGE_NT_HEADERS nth = (PIMAGE_NT_HEADERS)(pPe + dos->e_lfanew);


	if (nth->FileHeader.Characteristics & IMAGE_FILE_DLL) {
		printf("[!] We Do Not Support Dll Files !");
		return DllPE;
	}
	if (nth->FileHeader.Characteristics & IMAGE_FILE_EXECUTABLE_IMAGE && nth->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
		return _64PE;
	}
	if (nth->FileHeader.Characteristics & IMAGE_FILE_EXECUTABLE_IMAGE && nth->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC) {
		printf("[!] We Do Not Support x32 Exe Files, Yet !");
		return _32PE;
	}

	printf("[!] Please Input A Valid x64 Pe File !\n");
	return NotPE;
}



BOOL MoveExeStubToDir() {
	char Module[MAX_PATH];
	sprintf(Module, "%s%s", _STORE, _x64STUB);
	return CopyFileA(Module, ".\\"_x64STUB, FALSE);
}

BOOL MoveDllStubToDir() {
	char Module[MAX_PATH];
	sprintf(Module, "%s%s", _STORE, _x64DllStub);
	return CopyFileA(Module, ".\\"_x64DllStub, FALSE);
}

BOOL MoveHExeStubToDir() {
	char Module[MAX_PATH];
	sprintf(Module, "%s%s", _STORE, _x64STUB_H);
	return CopyFileA(Module, ".\\"_x64STUB_H, FALSE);
}



INT main(INT argc, CHAR* argv[]) {

	BOOL IsDll = FALSE, IsExe = TRUE;
	BOOL NoConsole = FALSE;

	char* whoami;
	(whoami = strrchr(argv[0], '\\')) ? ++whoami : (whoami = argv[0]);

	if (argc < 2) {
		printf("[#] Usage : %s <Input x64 exe> <*Output*> <*Optional Features*>\n", whoami);
		printf("[#] Output : \n");
		printf("\t\t\b\b-d : Output The Packed Pe As A x64 Dll File \n");
		printf("\t\t\b\b-e : Output The Packed Pe As A x64 Exe File (Default) \n");
		printf("[#] Features : \n");
		printf("\t\t\b\b-h : Hide The Console - /SUBSYSTEM:WINDOWS \n");

		printf("\n");
		return -1;
	}

	if (argc > 2){
		if (strcmp(argv[2], "-e") == 0) {
			IsDll = FALSE;
			IsExe = TRUE;
		}
		else if (strcmp(argv[2], "-d") == 0){
			IsDll = TRUE;
			IsExe = FALSE;
		}
		else {
			printf("[i] \"%s\" Is Invalid Input, Defaulting To Outputting Exe File ... \n");
		}
	}

	if (argc > 3) {
		if (strcmp(argv[3], "-h") == 0) {
			NoConsole = TRUE;
		}
	
	}


	unsigned char*	PeFile;
	DWORD			dwSize;
	char			LoaderStub[MAX_PATH];
	
	printf("[i] Reading \" %s \" ... \n", argv[1]);

	if (!ReadPayloadFile(argv[1], &dwSize, &PeFile)) {
		return -1;
	}

	if (CheckPeArch(PeFile) != _64PE) {
		return -1;
	}

	switch (CheckPeArch(PeFile)){
		case _64PE: {
			printf("[i] 64-PE Input Detected ... [ SUPPORTED ]\n");
			
			if (IsDll){
				printf("[i] Generating Dll Output ... \n");
				strcpy(LoaderStub, _x64DllStub);
				if (!MoveDllStubToDir()) {
					return ReportError("CopyFileA");
				}
			}
			else if (IsExe && !NoConsole) {
				printf("[i] Generating Exe Output ... \n");
				strcpy(LoaderStub, _x64STUB);
				if (!MoveExeStubToDir()) {
					return ReportError("CopyFileA");
				}
			}
			
			else if (IsExe && NoConsole) {
				printf("[i] Generating No Console Exe Output ... \n");
				strcpy(LoaderStub, _x64STUB_H);
				if (!MoveHExeStubToDir()) {
					return ReportError("CopyFileA");
				}
			}

			break;
		}

		case _32PE: {
			// not supported yet ...
			printf("[i] 32-PE Input Detected ... [ NOT-SUPPORTED ]\n");
			strcpy(LoaderStub, _x32STUB);
			return -1;
		}

		default:
			return -1;
	}

	

	printf("[i] Reading The Loader \"%s\" ...", LoaderStub);
	HANDLE hFile = CreateFileA(LoaderStub, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hFile == INVALID_HANDLE_VALUE) {
		//error
		return -1;
	}
	printf(" [ DONE ] \n");

	// compression:
	printf("[i] Packing ... ");
	unsigned int	iError = ELZMA_E_OK;
	unsigned char*	OutputCompressedData = NULL;
	size_t			OutputCompressedSize = NULL;
	if ((iError = simpleCompress(ELZMA_lzma, PeFile, dwSize, &OutputCompressedData, &OutputCompressedSize)) != ELZMA_E_OK) {
		printf("[!]  Compression Failed With Error : %d \n", iError);
		return FALSE;
	}

	printf(" [ DONE ] \n");
	printf("[+] Compressed Ratio : %d%% \n", (OutputCompressedSize * 100) / dwSize);
	printf("[+] Final Pe Size : %d \n", OutputCompressedSize);

	if (!CreateNewSection(hFile, OutputCompressedSize, OutputCompressedData)) {
		printf("[!] Failed To Create A New Section \n");
		return -1;
	}

	printf("[+] Section .ATOM is Created Containing The Input Packed Pe \n");


	return 0;
}
