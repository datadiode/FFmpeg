/*
 * tempnam.c: tempnam implementation for WinCE.
 *
 * This file has no copyright assigned and is placed in the Public Domain.
 */

#include <windows.h>
#include <io.h>

char *_tempnam(const char *dirname, const char *prefix)
{
    char filename[MAX_PATH];
    wchar_t dirnamew[MAX_PATH];
    wchar_t prefixw[MAX_PATH];
    wchar_t filenamew[MAX_PATH];

    mbstowcs(prefixw, prefix, MAX_PATH);
    if (!GetTempPath(MAX_PATH, dirnamew))
        if (mbstowcs(dirnamew, dirname, MAX_PATH) > MAX_PATH)
            return NULL;

    if (!GetTempFileName(dirnamew, prefixw, 0, filenamew))
        if (wcstombs(filename, filenamew, MAX_PATH) > MAX_PATH)
            return NULL;

    return _strdup(filename);
}

char *tempnam(const char *dirname, const char *prefix)
{
    return _tempnam(dirname, prefix);
}
