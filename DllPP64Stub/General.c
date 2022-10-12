/*

    contains bunch of helper functions to replace the crt version 
    (vx-api and others for the credits ...)
*/

#include <Windows.h>

#include "Structs.h"
#include "Utils.h"


//-------------------------------------------------------------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------------------------------------------------------------

// https://github.com/rad9800/TamperingSyscalls/blob/master/TamperingSyscalls/entry.cpp#L329
VOID _RtlInitUnicodeString(PUNICODE_STRING target, PCWSTR source){

	if ((target->Buffer = (PWSTR)source)){

		unsigned int length = wcslen(source) * sizeof(WCHAR);
		if (length > 0xfffc)
			length = 0xfffc;

		target->Length = length;
		target->MaximumLength = target->Length + sizeof(WCHAR);
	}

	else target->Length = target->MaximumLength = 0;
}


//-------------------------------------------------------------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------------------------------------------------------------


// https://github.com/rad9800/WTSRM/blob/master/WTSRM/entry.cpp#L482
wchar_t* _strcatW(wchar_t* dest, const wchar_t* src){

    if ((dest == NULL) || (src == NULL))
        return dest;

    while (*dest != 0)
        dest++;

    while (*src != 0) {
        *dest = *src;
        dest++;
        src++;
    }

    *dest = 0;
    return dest;
}

char* _strcatA (char* dest, const char* src) {
    
    if ((dest == NULL) || (src == NULL))
        return dest;

    while (*dest != 0)
        dest++;

    while (*src != 0) {
        *dest = *src;
        dest++;
        src++;
    }

    *dest = 0;
    return dest;
}



//-------------------------------------------------------------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------------------------------------------------------------


// https://github.com/rad9800/WTSRM/blob/master/WTSRM/entry.cpp#L461
wchar_t* _strcpyW(wchar_t* dest, const wchar_t* src){

    wchar_t* p;

    if ((dest == NULL) || (src == NULL))
        return dest;

    if (dest == src)
        return dest;

    p = dest;
    while (*src != 0) {
        *p = *src;
        p++;
        src++;
    }

    *p = 0;
    return dest;
}


char* _strcpyA(char* dest, const char* src) {

    char* p;

    if ((dest == NULL) || (src == NULL))
        return dest;

    if (dest == src)
        return dest;

    p = dest;
    while (*src != 0) {
        *p = *src;
        p++;
        src++;
    }

    *p = 0;
    return dest;
}

//-------------------------------------------------------------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------------------------------------------------------------

// https://github.com/rad9800/WTSRM/blob/master/WTSRM/entry.cpp#L500
PVOID _memcpy(void* dst, const void* src, SIZE_T count) {
    for (volatile int i = 0; i < count; i++) {
        ((BYTE*)dst)[i] = ((BYTE*)src)[i];
    }
    return dst;
}

// https://github.com/vxunderground/VX-API/blob/main/VX-API/ZeroMemoryEx.cpp
VOID _ZeroMemory(PVOID Destination, SIZE_T Size){

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

//-------------------------------------------------------------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------------------------------------------------------------


CHAR _ToUpper (CHAR c) {
    
    if (c >= 'a' && c <= 'z') {
        return c - 'a' + 'A';
    }
    
    return c;
}


//-------------------------------------------------------------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------------------------------------------------------------

// https://github.com/vxunderground/VX-API/blob/main/VX-API/StringLength.cpp
SIZE_T _StrlenA(LPCSTR String){

    LPCSTR String2;

    for (String2 = String; *String2; ++String2);

    return (String2 - String);
}

SIZE_T _StrlenW(LPCWSTR String){

    LPCWSTR String2;

    for (String2 = String; *String2; ++String2);

    return (String2 - String);
}

//-------------------------------------------------------------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------------------------------------------------------------

// https://github.com/vxunderground/VX-API/blob/main/VX-API/HashStringRotr32.cpp
UINT32 _HashStringRotr32SubA(UINT32 Value, UINT Count)
{

    DWORD Mask = (CHAR_BIT * sizeof(Value) - 1);
    Count &= Mask;
#pragma warning( push )
#pragma warning( disable : 4146)
    return (Value >> Count) | (Value << ((-Count) & Mask));
#pragma warning( pop ) 
}

DWORD _HashStringRotr32A(PCHAR String)
{

    DWORD Value = 0;

    for (INT Index = 0; Index < _StrlenA(String); Index++)
        Value = String[Index] + _HashStringRotr32SubA(Value, SEED);

    return Value;
}


UINT32 _HashStringRotr32SubW(UINT32 Value, UINT Count)
{
    DWORD Mask = (CHAR_BIT * sizeof(Value) - 1);
    Count &= Mask;
#pragma warning( push )
#pragma warning( disable : 4146)
    return (Value >> Count) | (Value << ((-Count) & Mask));
#pragma warning( pop ) 
}

DWORD _HashStringRotr32W(PWCHAR String)
{
    DWORD Value = 0;

    for (INT Index = 0; Index < _StrlenW(String); Index++)
        Value = String[Index] + _HashStringRotr32SubW(Value, SEED);

    return Value;
}

//-------------------------------------------------------------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------------------------------------------------------------

// https://github.com/Cracked5pider/KaynLdr/blob/main/KaynLdr/src/Win32.c#L39
UINT32 _CopyDotStr(PCHAR String){

    for (UINT32 i = 0; i < _StrlenA(String); i++)
    {
        if (String[i] == '.')
            return i;
    }
}

//-------------------------------------------------------------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------------------------------------------------------------

// https://github.com/vxunderground/VX-API/blob/main/VX-API/CharStringToWCharString.cpp

SIZE_T _CharToWchar (PWCHAR Destination, PCHAR Source, SIZE_T MaximumAllowed){

    INT Length = (INT)MaximumAllowed;
    
    while (--Length >= 0){
        if (!(*Destination++ = *Source++))
            return MaximumAllowed - Length - 1;
    }

    return MaximumAllowed - Length;
}

//-------------------------------------------------------------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------------------------------------------------------------
