// Copyright (c) Grzegorz Sołtysik
// Nazwa projektu: AESManager
// Nazwa pliku: GsWinLibrary.h
// Data: 26.12.2025, 07:26

#ifndef GSWINLIBRARY_H
#define GSWINLIBRARY_H

//#define __MYDEBUG__

#include <windows.h>

/// Struktura: GsStoreData
/// Cel:			 Przechowuje wynik skrótu lub inny (bufor + długość)
/// Uwagi:		 Bufor należy zwolnić przez HeapFree po użyciu
//---------------------------------------------------------------------------
struct GsStoreData
{
	BYTE	*pBData=nullptr; // Wskaźnik na dane
	DWORD	DDataLen=0;	 // Długość
	#ifdef __MYDEBUG__
		inline static int isiCleanup;
	#endif

	__fastcall ~GsStoreData() // [24-12-2025]
	{
		if(this->pBData)
		{
			SecureZeroMemory(this->pBData, this->DDataLen);
			HeapFree(GetProcessHeap(), 0, this->pBData); this->pBData = nullptr;
			#ifdef __MYDEBUG__
				isiCleanup++;
			#endif
		}
	}
};

// Zmiana stany przycisku na toolbarze
extern __fastcall void GsSetStateToolBarButton(const HWND hToolBar, const int iCommand, const bool bStateEnabled=true);

// Odczyt systemowej czcionki.
extern HFONT GsGetSystemFont();

// Wybiera dialog do wyboru pliku
extern bool GsLoadFile(TCHAR *lpszOutFile, const size_t sizeOutFile);

// Otwiera okno dialogowe do wyboru katalogu
bool GsSelectProjectDirectory(TCHAR *lpszSelectDir, const TCHAR *lpszDefaultDir);

// Funkcja zwraca wymiary wzgledem kontrolki nadrzędnej
extern bool __fastcall GsGetControlSize(const HWND hControl, const HWND hParentControl, RECT &rRectControl);

// Funkcja przyporządkowywuje czcionki wszystkim kontrolkom
extern void __fastcall GsSetFontForAll(const HWND hParent, HFONT hFont);

// Funkcja sprawdzająca, czy ścieżka dostepu jest katalogiem
extern bool __fastcall GsIsDirectory(LPCTSTR lpszPath);

// Funkcja odczytująca cały plik do pamięci
extern bool __fastcall GsReadDataFromFile(LPCWSTR lpszFilePath, GsStoreData *pOut);

// Funkcja zapisująca okreslona pamięć do pliku
extern bool __fastcall GsWriteDataToFile(LPCWSTR lpszFilePath, const BYTE* pData, DWORD cbData);

#endif //GSWINLIBRARY_H