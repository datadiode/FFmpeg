/*
 * stat.c: _stat implementations for WinCE.
 *
 * This file has no copyright assigned and is placed in the Public Domain.
 * This file is a part of the mingw-runtime package.
 * No warranty is given; refer to the file DISCLAIMER within the package.
 *
 * Written by Pedro Alves <pedro_alves@portugalmail.pt> 10 Feb 2007
 *
 */

#include <windows.h>
#include <time.h>
#include <fcntl.h>
#include <io.h>
#include <sys/stat.h>
#include <stdio.h>

#include "timeutil.h"

static int __stat_by_find_data (WIN32_FIND_DATAW *fi, struct _stat *st)
{
  int permission = _S_IREAD;

  memset (st, 0, sizeof (*st));

  st->st_size = fi->nFileSizeLow;
  st->st_mode = _S_IFREG;

  if((fi->dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0)
    st->st_mode = _S_IFDIR | _S_IEXEC;

  if((fi->dwFileAttributes & FILE_ATTRIBUTE_READONLY) == 0)
    permission |= _S_IWRITE;

  st->st_mode |= permission | (permission >> 3) | (permission >> 6);

  st->st_nlink = 1; /* always 1? */
  st->st_rdev = 1; /* Where to get drive info?  */
  st->st_ino = 0; /* always 0 on Windows */

  st->st_mtime = __FILETIME_to_time_t (&fi->ftLastWriteTime);
  st->st_ctime = __FILETIME_to_time_t (&fi->ftCreationTime);
  st->st_atime = __FILETIME_to_time_t (&fi->ftLastAccessTime);

  /* Looks like the code below is never triggered.
     Windows CE always only keeps the LastWriteTime, and
     copies it to the CreationTime and LastAccessTime fields.  */
  if (st->st_ctime == 0)
    st->st_ctime = st->st_mtime;
  if (st->st_atime == 0)
    {
      /* On XP, at least, the st_atime is always set to the same as
	 the st_mtime, except the hour/min/sec == 00:00:00.  */
      SYSTEMTIME s;
      FILETIME f = fi->ftLastWriteTime;
      FileTimeToSystemTime (&f, &s);
      s.wHour = 0; s.wMinute = 0;
      s.wSecond = 0; s.wMilliseconds = 0;
      SystemTimeToFileTime (&s, &f);
      st->st_atime = __FILETIME_to_time_t (&f);
      /* st->st_atime = st->st_mtime; */
    }
  return 0;
}

int _wstat (const wchar_t *pathw, struct _stat *st)
{
  WIN32_FIND_DATAW fd;
  HANDLE h;
  int ret;

  if((h = FindFirstFileW (pathw, &fd)) == INVALID_HANDLE_VALUE)
    return -1;

  ret = __stat_by_find_data (&fd, st);
  FindClose (h);
  return ret;
}

int _stat (const char *path, struct _stat *st)
{
  wchar_t pathw[MAX_PATH + 1];
  if (mbstowcs (pathw, path, MAX_PATH) >= MAX_PATH)
    return -1;
  return _wstat (pathw, st);
}
