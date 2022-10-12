#include <string.h>
#include <assert.h>
#include "easylzma.h"
#include "Crt.h"

struct dataStream
{
    const unsigned char* inData;
    size_t inLen;

    unsigned char* outData;
    size_t outLen;
};

static int
inputCallback(void* ctx, void* buf, size_t* size)
{
    size_t rd = 0;
    struct dataStream* ds = (struct dataStream*)ctx;
    assert(ds != NULL);

    rd = (ds->inLen < *size) ? ds->inLen : *size;

    if (rd > 0) {
        // memcpy replacement
        memcpy(buf, (void*)ds->inData, rd);
        ds->inData += rd;
        ds->inLen -= rd;
    }

    *size = rd;

    return 0;
}

static size_t
outputCallback(void* ctx, const void* buf, size_t size)
{
    struct dataStream* ds = (struct dataStream*)ctx;
    assert(ds != NULL);

    if (size > 0) {
        // realloc replacement 
        ds->outData = realloc((PVOID)ds->outData, (SIZE_T) ds->outLen + size);
        // memcpy replacement
        memcpy((void*)(ds->outData + ds->outLen), buf, size);
        ds->outLen += size;
    }

    return size;
}


int
simpleDecompress(elzma_file_format format, const unsigned char* inData,
    size_t inLen, unsigned char** outData,
    size_t* outLen)
{
    int rc;
    elzma_decompress_handle hand;

    hand = elzma_decompress_alloc();

    /* now run the compression */
    {
        struct dataStream ds;
        ds.inData = inData;
        ds.inLen = inLen;
        ds.outData = NULL;
        ds.outLen = 0;

        rc = elzma_decompress_run(hand, inputCallback, (void*)&ds,
            outputCallback, (void*)&ds, format);

        if (rc != ELZMA_E_OK) {
            // free replacment
            if (ds.outData != NULL) free(ds.outData);
            elzma_decompress_free(&hand);
            return rc;
        }

        elzma_decompress_free(&hand);
        *outData = ds.outData;
        *outLen = ds.outLen;
    }

    return rc;
}
