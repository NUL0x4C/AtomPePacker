#include <windows.h>
#include <stdio.h>

#include "Header.h"

//https://github.com/hMihaiDavid/addscn/blob/master/addscn/addscn.cpp

#define P2ALIGNDOWN(x, align) ((x) & -(align))
#define P2ALIGNUP(x, align) (-(-(x) & -(align)))

#ifdef _WIN64
#define MACHINE IMAGE_FILE_MACHINE_AMD64
#else
#define MACHINE IMAGE_FILE_MACHINE_I386
#endif

typedef struct MyStruct
{
	HANDLE hFile;
	HANDLE hFileMapping;
	PBYTE  pView;
};


struct MyStruct NewSection = { 0 };


PBYTE MapFileReadOnly() {

	NewSection.hFileMapping = CreateFileMapping(NewSection.hFile, NULL, PAGE_READONLY, 0, 0, NULL);

	if (NewSection.hFileMapping == INVALID_HANDLE_VALUE) {
		// error
	}

	NewSection.pView = (PBYTE)MapViewOfFile(NewSection.hFileMapping, FILE_MAP_READ, 0, 0, 0);
	if (NewSection.pView == NULL){
		// error
	}

	if (NewSection.hFileMapping == INVALID_HANDLE_VALUE) {
		CloseHandle(NewSection.hFile);
	}

	return NewSection.pView;

}



PBYTE MapFileRWNewSize(DWORD newSize) {

	NewSection.hFileMapping = CreateFileMapping(NewSection.hFile, NULL, PAGE_READWRITE, 0, newSize, NULL);

	if (NewSection.hFileMapping == INVALID_HANDLE_VALUE) {
		// error
	}

	NewSection.pView = (PBYTE)MapViewOfFile(NewSection.hFileMapping, FILE_MAP_READ | FILE_MAP_WRITE, 0, 0, 0);
	if (NewSection.pView == NULL) {
		// error
	}

	if (NewSection.hFileMapping == INVALID_HANDLE_VALUE) {
		CloseHandle(NewSection.hFile);
	}

	return NewSection.pView;

}

BOOL Unmap() {
	return (UnmapViewOfFile((PVOID)NewSection.pView) && CloseHandle(NewSection.hFileMapping));
}


BOOL AppendNewSectionHeader(DWORD dwFileSizeLow, PSTR name, DWORD VirtualSize, DWORD Characteristics, PBYTE pSectionData) {
	
	PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)NewSection.pView;
	PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)((UINT_PTR)NewSection.pView + dosHeader->e_lfanew);
	WORD sizeOfOptionalHeader = ntHeaders->FileHeader.SizeOfOptionalHeader;
	PIMAGE_FILE_HEADER fileHeader = &(ntHeaders->FileHeader);
	PIMAGE_SECTION_HEADER firstSectionHeader = (PIMAGE_SECTION_HEADER)(((UINT_PTR)fileHeader) + sizeof(IMAGE_FILE_HEADER) + sizeOfOptionalHeader);
	
	WORD numberOfSections = ntHeaders->FileHeader.NumberOfSections;
	DWORD sectionAlignment = ntHeaders->OptionalHeader.SectionAlignment;
	DWORD fileAlignment = ntHeaders->OptionalHeader.FileAlignment;

	PIMAGE_SECTION_HEADER newSectionHeader = &firstSectionHeader[numberOfSections];
	PIMAGE_SECTION_HEADER lastSectionHeader = &firstSectionHeader[numberOfSections - 1];


	memset(newSectionHeader, 0, sizeof(IMAGE_SECTION_HEADER));
	memcpy(&newSectionHeader->Name, name, min(strlen(name), 8));
	newSectionHeader->Misc.VirtualSize = VirtualSize;
	newSectionHeader->VirtualAddress = P2ALIGNUP(lastSectionHeader->VirtualAddress + lastSectionHeader->Misc.VirtualSize, sectionAlignment);
	newSectionHeader->SizeOfRawData = P2ALIGNUP(VirtualSize, fileAlignment);
	newSectionHeader->PointerToRawData = dwFileSizeLow;
	newSectionHeader->Characteristics = Characteristics;
	numberOfSections++;
	ntHeaders->FileHeader.NumberOfSections = numberOfSections;
	ntHeaders->OptionalHeader.SizeOfImage = P2ALIGNUP(newSectionHeader->VirtualAddress + newSectionHeader->Misc.VirtualSize, sectionAlignment);


	//memset((PVOID)((UINT_PTR)NewSection.pView + newSectionHeader->PointerToRawData), 0, newSectionHeader->SizeOfRawData);

	memcpy((PVOID)((UINT_PTR)NewSection.pView + newSectionHeader->PointerToRawData), pSectionData, newSectionHeader->SizeOfRawData);
}




BOOL CreateNewSection(HANDLE hFile, DWORD dwSectionSize, PBYTE pSectionData) {

	DWORD dwFileSizeLow, dwFileSizeHigh;
	PBYTE pView			= NULL;
	NewSection.hFile	= hFile;
	
	CHAR str_section_name[9] = ".ATOM";

	if (NewSection.hFile == NULL) {
		return FALSE;
	}

	dwFileSizeLow = GetFileSize(hFile, &dwFileSizeHigh);
	if (dwFileSizeHigh != NULL) {
		// error
		CloseHandle(hFile);
		return FALSE;
	}

	if ((pView = MapFileReadOnly()) == NULL) {
		CloseHandle(hFile);
		return FALSE;
	}

	PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)pView;
	if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
		// error
	}
	PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)((UINT_PTR)pView + dosHeader->e_lfanew);
	if (ntHeaders->Signature != IMAGE_NT_SIGNATURE || ntHeaders->FileHeader.Machine != MACHINE) {
		//error
	}


	WORD numberOfSections = ntHeaders->FileHeader.NumberOfSections;
	DWORD sectionAlignment = ntHeaders->OptionalHeader.SectionAlignment;
	DWORD fileAlignment = ntHeaders->OptionalHeader.FileAlignment;


	PIMAGE_FILE_HEADER fileHeader = &(ntHeaders->FileHeader);

	WORD sizeOfOptionalHeader = ntHeaders->FileHeader.SizeOfOptionalHeader;
	PIMAGE_SECTION_HEADER firstSectionHeader = (PIMAGE_SECTION_HEADER)(((UINT_PTR)fileHeader) + sizeof(IMAGE_FILE_HEADER) + sizeOfOptionalHeader);
	PIMAGE_SECTION_HEADER newSectionHeader = &firstSectionHeader[numberOfSections];
	PBYTE firstByteOfSectionData = (PBYTE)(((DWORD)firstSectionHeader->PointerToRawData) + (UINT_PTR)pView);

	SIZE_T available_space = ((UINT_PTR)firstByteOfSectionData) - ((UINT_PTR)newSectionHeader);
	if (available_space < sizeof(IMAGE_SECTION_HEADER)) {
		//error
	}

	if (!Unmap()) {
		//error
	}

	DWORD newSize = P2ALIGNUP(dwFileSizeLow + dwSectionSize, fileAlignment);
	if ((pView = MapFileRWNewSize(newSize)) == NULL) {
		CloseHandle(hFile);
		return FALSE;
	}

	if (!AppendNewSectionHeader(dwFileSizeLow, str_section_name, dwSectionSize, IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ, pSectionData)) {
		// error
	}

	if (!Unmap()) {
		//error
	}

	return CloseHandle(hFile);
}