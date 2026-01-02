// Copyright (c) Grzegorz Sołtysik
// Nazwa projektu: AESManager
// Nazwa pliku: MyVersion.h
// Data: 1.01.2026, 06:04

#ifndef MyVersionH
#define MyVersionH

#include <wtypes.h>
#include <tchar.h>
//---------------------------------------------------------------------------
struct MyVersion
{
	static TCHAR *GetInfo(TCHAR *InfoItem=const_cast<TCHAR *>(TEXT("FileVersion")));
};

//---------------------------------------------------------------------------
#endif
