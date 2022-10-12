#pragma once


#ifndef _EASYLZMA_H
#define _EASYLZMA_H

#include "compress.h"
#include "decompress.h"


/* compress a chunk of memory and return a dynamically allocated buffer
 * if successful.  return value is an easylzma error code */
int simpleCompress(elzma_file_format format,
    const unsigned char* inData,
    size_t inLen,
    unsigned char** outData,
    size_t* outLen);

/* decompress a chunk of memory and return a dynamically allocated buffer
 * if successful.  return value is an easylzma error code */
int simpleDecompress(elzma_file_format format,
    const unsigned char* inData,
    size_t inLen,
    unsigned char** outData,
    size_t* outLen);


#endif // !_EASYLZMA_H
