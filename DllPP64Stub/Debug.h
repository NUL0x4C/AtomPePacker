#pragma once

//#define DEBUG


#ifndef DEBUG_H
#define DEBUG_H

#include <Windows.h>


#ifdef DEBUG



HANDLE GetConsole();

#define PRINT( STR, ... )                                                                   \
    if (1) {                                                                                \
        LPWSTR buf = (LPWSTR)HeapAlloc( GetProcessHeap(), HEAP_ZERO_MEMORY, 1024 );         \
        if ( buf != NULL ) {                                                                \
            int len = wsprintfW( buf, STR, __VA_ARGS__ );                                   \
            WriteConsoleW( GetConsole(), buf, len, NULL, NULL );			                    \
            HeapFree( GetProcessHeap(), 0, buf );                                           \
        }                                                                                   \
    }  


#define PRINTA( STR, ... )                                                                  \
    if (1) {                                                                                \
        LPSTR buf = (LPSTR)HeapAlloc( GetProcessHeap(), HEAP_ZERO_MEMORY, 1024 );           \
        if ( buf != NULL ) {                                                                \
            int len = wsprintfA( buf, STR, __VA_ARGS__ );                                   \
            WriteConsoleA( GetConsole(), buf, len, NULL, NULL );                                \
            HeapFree( GetProcessHeap(), 0, buf );                                           \
        }                                                                                   \
    }  





#endif // DEBUG






#endif // !DEBUG_H
