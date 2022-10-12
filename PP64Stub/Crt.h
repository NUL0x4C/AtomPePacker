/*

    since im using easylzma library, which is using some crt functions, i had to replace them here, using custom code, so yeah ...
    thats what these are :p

    ofc some of the code is from vx-api (for the credits)
*/

#pragma once
#include <Windows.h>


PVOID _malloc(SIZE_T Size)
{
    return HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, Size);
}

BOOL _free(PVOID ptr)
{
    return HeapFree(GetProcessHeap(), 0, ptr);
}


PVOID _realloc(PVOID ptr, SIZE_T new_size)
{

    byte* d = NULL; 
    byte* s = NULL;
    size_t size = NULL;

    if (new_size == NULL)
        return NULL;

    if (ptr == NULL)
        return _malloc(new_size);


    size_t old_size = HeapSize(GetProcessHeap(), 0, ptr);

    if (old_size == new_size) {
        return ptr;
    }
    
    // allocating new ptr and moving data to it (from ptr)
    void* new_ptr = _malloc(new_size);

    d = (byte*)new_ptr;
    s = (byte*)ptr;
    size = old_size;
    for (volatile int i = 0; i < size; i++) {
        ((BYTE*)d)[i] = ((BYTE*)s)[i];
    }

    // setting ptr to 0
    PULONG Dest = (PULONG)ptr;
    size = old_size / sizeof(ULONG);
    while (size > 0){
        *Dest = 0;
        Dest++;
        size--;
    }

    //freeing ptr
    _free(ptr);

    return new_ptr;
}



//       REPLACING MEMSET
extern void* __cdecl memset(void*, int, size_t);
#pragma intrinsic(memset)
#pragma function(memset)
void* __cdecl memset(void* pTarget, int value, size_t cbTarget) {
	unsigned char* p = (unsigned char*)pTarget;
	while (cbTarget-- > 0) {
		*p++ = (unsigned char)value;
	}
	return pTarget;
}

//      REPLACING MEMMOVE
extern void* __cdecl memmove(void* destination, const void* source, size_t num);
#pragma intrinsic(memmove)
#pragma function(memmove)
void* __cdecl memmove(void* destination, const void* source, size_t num) {
    for (volatile int i = 0; i < num; i++) {
        ((BYTE*)destination)[i] = ((BYTE*)source)[i];
    }
    return destination;
}

//      REPLACING FREE
extern void __cdecl free(void*);
#pragma intrinsic(free)
#pragma function(free)
void __cdecl free(void* pAddress) {
	_free(pAddress);
}

//      REPLACING MALLOC
extern void* __cdecl malloc(size_t);
#pragma intrinsic(malloc)
#pragma function(malloc)
void* __cdecl malloc(size_t Size) {
	return _malloc(Size);
}

//      REPLACING REALLOC
extern void* __cdecl realloc(void* ptr, size_t new_size);
#pragma intrinsic(realloc)
#pragma function(realloc)
void* __cdecl realloc(void* ptr, size_t new_size) {
    return _realloc(ptr, new_size);
}



//      REPLACING MEMCPY
extern void* __cdecl memcpy(void*, void const*, size_t);
#pragma intrinsic(memcpy)
#pragma function(memcpy)
void* __cdecl memcpy(void* dst, void const* src, size_t size) {
    for (volatile int i = 0; i < size; i++) {
        ((BYTE*)dst)[i] = ((BYTE*)src)[i];
    }
    return dst;
}


//      REPLACING STRNCMP
extern int __cdecl strncmp(char const*, char const*, size_t);
#pragma intrinsic(strncmp)
#pragma function(strncmp)
int __cdecl strncmp(char const* str1, char const* str2, size_t size) {

    for (; *str1 == *str2; str1++, str2++)
    {
        if (*str1 == '\0')
            return 0;
    }

    return ((*(LPCSTR)str1 < *(LPCSTR)str2) ? -1 : +1);
}

