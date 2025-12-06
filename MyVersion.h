// Copyright (c) Grzegorz Sołtysik
// Nazwa projektu: AESManager
// Nazwa pliku: MyVersion.h
// Data: 6.12.2025, 17:41

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
