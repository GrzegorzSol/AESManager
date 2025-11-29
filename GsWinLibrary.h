// Copyright (c) Grzegorz Sołtysik
// Nazwa projektu: AESManager
// Nazwa pliku: GsWinLibrary.h
// Data: 28.11.2025, 19:40

#ifndef GSWINLIBRARY_H
#define GSWINLIBRARY_H

#include <windows.h>

// Zmiana stany przycisku na toolbarze
extern __fastcall void GsSetStateToolBarButton(HWND hToolBar, int iCommand, bool bStateEnabled=true);

// Odczyt systemowej czcionki.
extern HFONT GsGetSystemFont();

// Wybiera dialog do wyboru pliku
extern bool GsLoadFile(TCHAR *lpszOutFile, size_t sizeOutFile);

// Otwiera okno dialogowe do wyboru katalogu
bool GsSelectProjectDirectory(TCHAR *lpszSelectDir, const TCHAR *lpszDefaultDir);

// Funkcja zwraca wymiary wzgledem kontrolki nadrzędnej
extern bool __fastcall GsGetControlSize(HWND hControl, HWND hParentControl, RECT &rRectControl);

// Funkcja przyporządkowywuje czcionki wszystkim kontrolkom
extern void __fastcall SetFontForAll(HWND hParent, HFONT hFont);

// Odczyt tekstu z kontrolki EDIT
//extern void

#endif //GSWINLIBRARY_H