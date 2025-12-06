// Copyright (c) Grzegorz Sołtysik
// Nazwa projektu: AESManager
// Nazwa pliku: GsAboutLibrary.cpp
// Data: 6.12.2025, 17:41

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

extern ULONG_PTR gdiplusToken;
constexpr TCHAR GL_FILENAME_LOGO[] = TEXT("Logo.png");

void __fastcall OnInitDialog(HWND hDlg);
/*
	MessageBox(nullptr, TEXT("Tekst sprawdzający"), TEXT("Informacja"), MB_ICONINFORMATION);
*/

INT_PTR CALLBACK GsAboutDlgProc(HWND hDlg, UINT message, WPARAM wParam, LPARAM lParam)
/**
		OPIS METOD(FUNKCJI):
		OPIS ARGUMENTÓW:
		OPIS ZMIENNYCH:
		OPIS WYNIKU METODY(FUNKCJI):
*/
{
		switch(message)
		{
				case WM_INITDIALOG:
				{
						OnInitDialog(hDlg);
						return static_cast<INT_PTR>(TRUE);
				}
				//---
				case WM_DRAWITEM:
				{
						LPDRAWITEMSTRUCT dis = reinterpret_cast<LPDRAWITEMSTRUCT>(lParam);
						if (dis->CtlID == IDC_LOGO)
						{
								TCHAR szDirApplic[MAX_PATH];
								// Aktualny katalog aplikacji
								GetModuleFileName(nullptr, szDirApplic, MAX_PATH);
								PathCchRemoveFileSpec(szDirApplic, MAX_PATH);
								// Stworzenie ścieżki do pliku konfiguracji
								PathCchCombine(szDirApplic, MAX_PATH, szDirApplic, GL_FILENAME_LOGO);

								Gdiplus::Graphics g(dis->hDC);
								g.SetSmoothingMode(Gdiplus::SmoothingModeHighQuality);

								Gdiplus::Image logo(szDirApplic); // plik PNG w katalogu aplikacji
								g.DrawImage(&logo,
										static_cast<Gdiplus::REAL>(dis->rcItem.left),
										static_cast<Gdiplus::REAL>(dis->rcItem.top),
								static_cast<Gdiplus::REAL>(dis->rcItem.right - dis->rcItem.left),
								static_cast<Gdiplus::REAL>(dis->rcItem.bottom - dis->rcItem.top));
						}
				}
				break;
				//---
				case WM_NOTIFY:
				{
						LPNMHDR pnmh = reinterpret_cast<LPNMHDR>(lParam);

						if (pnmh->idFrom == IDC_ADDRESS && pnmh->code == NM_CLICK)
						{
								ShellExecute(nullptr, TEXT("open"), TEXT("https://github.com/GrzegorzSol/AESManager"),
										nullptr, nullptr, SW_SHOWNORMAL);
						}
				}
				break;
				//---
				case WM_COMMAND:
						if(LOWORD(wParam) == IDCANCEL)
						{
								EndDialog(hDlg, LOWORD(wParam));

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
		TCHAR *lpszInfoVersion=nullptr, szpTextInfo[48],
					szTextFull[] = TEXT("Aplikacja przeznaczona jest do szyfrowania za pomocą metody AES. ")
												 TEXT("Można wybrać złożoność szyfrowania pomiędzy AES 128, albo 256 bitowym. ")
												 TEXT("Powyższa aplikacja ma status GNU z dostępnym kodem źródłowym. ")
												 TEXT("Adres repetytorium Gita to: ");

		// Półprzezroczyste tło
		// LONG exStyle = GetWindowLong(hDlg, GWL_EXSTYLE);
		// SetWindowLong(hDlg, GWL_EXSTYLE, exStyle | WS_EX_LAYERED);
		// SetLayeredWindowAttributes(hDlg, 0, 220, LWA_ALPHA);
		lpszInfoVersion = MyVersion::GetInfo(); // Informacja o wersji
		StringCchPrintf(szpTextInfo, 100, TEXT("AESManager v%s (c)Grzegorz Sołtysik"), lpszInfoVersion);
		// Modyfikacja kontrolki CTEXT (Autor).
		SetDlgItemText(hDlg, IDC_INFO_APP, szpTextInfo);
		// Modyfikacja kontrolki LTEXT (Full).
		SetDlgItemText(hDlg, IDC_FULL_TEXT, szTextFull);
}
//---------------------------------------------------------------------------