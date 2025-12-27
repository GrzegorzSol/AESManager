// Copyright (c) Grzegorz Sołtysik
// Nazwa projektu: AESManager
// Nazwa pliku: MyVersion.h
// Data: 26.12.2025, 07:26

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
