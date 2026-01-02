// Copyright (c) Grzegorz Sołtysik
// Nazwa projektu: AESManager
// Nazwa pliku: GsAboutLibrary.cpp
// Data: 1.01.2026, 06:04

//
// Created by GrzegorzS on 23.11.2025.
//

#include "GsAboutLibrary.h"
#include "AESManager_resource.h"
#include "MyVersion.h"
#include <pathcch.h>
#include <Strsafe.h>
#include <gdiplus.h>
#include <commctrl.h>
//#include "AESManager.h" // Błąd

extern ULONG_PTR GLOBAL_GDIPLUSTOKEN;
constexpr TCHAR GL_FILENAME_LOGO[] = TEXT("Logo.png");

void __fastcall OnInitDialog(HWND hDlg);
/*
	MessageBox(nullptr, TEXT("Tekst sprawdzający"), TEXT("Informacja"), MB_ICONINFORMATION);
*/

INT_PTR CALLBACK GsAboutDlgProc(const HWND cHDlg, const UINT cUIMessage, const WPARAM cwParam, const LPARAM cLParam)
/**
		OPIS METOD(FUNKCJI):
		OPIS ARGUMENTÓW:
		OPIS ZMIENNYCH:
		OPIS WYNIKU METODY(FUNKCJI):
*/
{
		switch(cUIMessage)
		{
				case WM_INITDIALOG:
				{
						OnInitDialog(cHDlg);
						return static_cast<INT_PTR>(TRUE);
				}
				//---
				case WM_DRAWITEM:
				{
						LPDRAWITEMSTRUCT LpDis = reinterpret_cast<LPDRAWITEMSTRUCT>(cLParam);
						if (LpDis->CtlID == IDC_LOGO)
						{
								TCHAR szDirApplic[MAX_PATH];
								// Aktualny katalog aplikacji
								GetModuleFileName(nullptr, szDirApplic, MAX_PATH);
								PathCchRemoveFileSpec(szDirApplic, MAX_PATH);
								// Stworzenie ścieżki do pliku konfiguracji
								PathCchCombine(szDirApplic, MAX_PATH, szDirApplic, GL_FILENAME_LOGO);

								Gdiplus::Graphics g(LpDis->hDC);
								g.SetSmoothingMode(Gdiplus::SmoothingModeHighQuality);

								Gdiplus::Image logo(szDirApplic); // plik PNG w katalogu aplikacji
								g.DrawImage(&logo,
										static_cast<Gdiplus::REAL>(LpDis->rcItem.left),
										static_cast<Gdiplus::REAL>(LpDis->rcItem.top),
								static_cast<Gdiplus::REAL>(LpDis->rcItem.right - LpDis->rcItem.left),
								static_cast<Gdiplus::REAL>(LpDis->rcItem.bottom - LpDis->rcItem.top));
						}
				}
				break;
				//---
				case WM_NOTIFY:
				{
						LPNMHDR pLNmh = reinterpret_cast<LPNMHDR>(cLParam);

						if (pLNmh->idFrom == IDC_ADDRESS && pLNmh->code == NM_CLICK)
						{
								ShellExecute(nullptr, TEXT("open"), TEXT("https://github.com/GrzegorzSol/AESManager"),
										nullptr, nullptr, SW_SHOWNORMAL);
						}
				}
				break;
				//---
				case WM_COMMAND:
						if(LOWORD(cwParam) == IDCANCEL)
						{
								EndDialog(cHDlg, LOWORD(cwParam));

								return (INT_PTR)TRUE;
						}
				break;
				//---
				default: break;
		}

		return static_cast<INT_PTR>(FALSE);
}
//---------------------------------------------------------------------------
void __fastcall OnInitDialog(HWND hDlg)
/**
		OPIS METOD(FUNKCJI):
		OPIS ARGUMENTÓW:
		OPIS ZMIENNYCH:
		OPIS WYNIKU METODY(FUNKCJI):
*/
{
	constexpr int ciTextInfoLen = 100;
	TCHAR *lpszInfoVersion=nullptr, lpszTextInfo[ciTextInfoLen],
					lpszTextFull[] = TEXT("Aplikacja przeznaczona jest do szyfrowania za pomocą metody AES. ")
												 TEXT("Można wybrać złożoność szyfrowania pomiędzy AES 128, albo 256 bitowym. ")
												 TEXT("Powyższa aplikacja ma status GNU z dostępnym kodem źródłowym. ")
												 TEXT("Adres repetytorium Gita to: ");

		// Półprzezroczyste tło
		// LONG exStyle = GetWindowLong(hDlg, GWL_EXSTYLE);
		// SetWindowLong(hDlg, GWL_EXSTYLE, exStyle | WS_EX_LAYERED);
		// SetLayeredWindowAttributes(hDlg, 0, 220, LWA_ALPHA);
		lpszInfoVersion = MyVersion::GetInfo(); // Informacja o wersji
		StringCchPrintf(lpszTextInfo, ciTextInfoLen, TEXT("AESManager v%s © Grzegorz Sołtysik [Oświęcim Date: %S Time: %S]"),
			lpszInfoVersion, __DATE__, __TIME__);
		// Modyfikacja kontrolki CTEXT (Autor).
		SetDlgItemText(hDlg, IDC_INFO_APP, lpszTextInfo);
		// Modyfikacja kontrolki LTEXT (Full).
		SetDlgItemText(hDlg, IDC_FULL_TEXT, lpszTextFull);
}
//---------------------------------------------------------------------------