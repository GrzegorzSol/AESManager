// Copyright (c) Grzegorz Sołtysik
// Nazwa projektu: AESManager
// Nazwa pliku: MyVersion.cpp
// Data: 6.12.2025, 17:41

/*
Biblioteka wspólnych metod dla wszystkich klas i modułów aplikacji. Główną klasą jest klasa Library całkowicie publiczna i statyczna.
Klasa ta jednak nie jest i nie bedzie jedynie wykorzystana do budowy aplikacji Moja Biblia NG, lecz będzie w przyszłości wykorzystywana
do innych projektów. Z tego powodu jej wszystkie funkcje i metody, musza być konstruowane jako uniwersalne.
*/
//---------------------------------------------------------------------------
#define UNICODE

#include <windows.h>
#include "MyVersion.h"
#include <Strsafe.h>

//---------------------------------------------------------------------------
TCHAR *MyVersion::GetInfo(TCHAR *InfoItem)
/*
	OPIS METOD(FUNKCJI): Stworzenie StatusBar
	OPIS ARGUMENTÓW: GetInfo("Comments");
									 GetInfo("CompanyName");
									 GetInfo("FileDescription");
									 GetInfo("FileVersion");
									 GetInfo("InternalName");
									 GetInfo("LegalCopyright");
									 GetInfo("LegalTrademarks");
									 GetInfo("OriginalFilename");
									 GetInfo("PrivateBuild");
									 GetInfo("ProductName");
									 GetInfo("ProductVersion");
	OPIS ZMIENNYCH:
	OPIS WYNIKU METODY(FUNKCJI):

*/
{
	static TCHAR szResult[256] = {0};
	TCHAR szFullPath[256];
	TCHAR szGetName[256];
	LPWSTR lpVersion;				 // String pointer to Item text
	DWORD dwVerInfoSize,		// Size of version information block
			dwVerHnd=0;				 // An 'ignored' parameter, always '0'
	UINT uVersionLen;
	BOOL bRetCode;

	GetModuleFileNameW(NULL, szFullPath, sizeof(szFullPath));
	dwVerInfoSize = GetFileVersionInfoSize(szFullPath, &dwVerHnd);

	if (dwVerInfoSize)
	{
		LPSTR		lpstrVffInfo;
		HANDLE	hMem;
		hMem = GlobalAlloc(GMEM_MOVEABLE, dwVerInfoSize);
		lpstrVffInfo	=	 (LPSTR)GlobalLock(hMem);

		GetFileVersionInfo(szFullPath, dwVerHnd, dwVerInfoSize, lpstrVffInfo);
		StringCchCopy(szGetName, 256, TEXT("\\VarFileInfo\\Translation"));
		uVersionLen = 0;
		lpVersion = NULL;
		bRetCode = VerQueryValue((LPVOID)lpstrVffInfo, (LPWSTR)szGetName, (void **)&lpVersion, (UINT *)&uVersionLen);

		if(bRetCode && uVersionLen && lpVersion)
		{
			StringCchPrintf(szResult, 256, TEXT("%04x%04x"), (WORD)(*((DWORD *)lpVersion)),(WORD)(*((DWORD *)lpVersion)>>16));
		}
		else
		{
			// 041904b0 is a very common one, because it means:
			//	 US English/Russia, Windows MultiLingual characterset
			// Or to pull it all apart:
			// 04------				 = SUBLANG_ENGLISH_USA
			// --09----				 = LANG_ENGLISH
			// --19----				 = LANG_RUSSIA
			// ----04b0 = 1200 = Codepage for Windows:Multilingual
			StringCchCopy(szResult, 256, TEXT("041904b0"));
		}
		// Add a codepage to base_file_info_sctructure
		StringCchPrintf(szGetName, 256, TEXT("\\StringFileInfo\\%s\\"), szResult);
		// Get a specific item
		StringCchCat(szGetName, 256, InfoItem);
		uVersionLen = 0;
		lpVersion = nullptr;
		bRetCode = VerQueryValue((LPVOID)lpstrVffInfo, (LPWSTR)szGetName, (void **)&lpVersion, (UINT *)&uVersionLen);

		if(bRetCode && uVersionLen && lpVersion)
		{
			StringCchCopy(szResult, 256, lpVersion);
		}
		else
		{
			StringCchCopy(szResult, 256, TEXT(""));
		}
		GlobalUnlock(hMem);
		GlobalFree(hMem);
	}
	 return szResult;
}
//---------------------------------------------------------------------------
