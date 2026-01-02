// Copyright (c) Grzegorz Sołtysik
// Nazwa projektu: AESManager
// Nazwa pliku: GsWinLibrary.cpp
// Data: 1.01.2026, 06:04

#define STRICT
#define NO_WIN32_LEAN_AND_MEAN
#define UNICODE

#include "GsWinLibrary.h"
#include <commctrl.h>
#include <shlobj.h>
#include <strsafe.h>   // Safe String Functions

int CALLBACK GsBrowseCallBackProc(const HWND hwnd, const UINT uMsg, LPARAM lParam, const LPARAM lpData);

__fastcall void	 GsSetStateToolBarButton(const HWND hToolBar, const int iCommand, const bool bStateEnabled)
/**
	OPIS METOD(FUNKCJI): Zmiana stany przycisku na toolbarze zależnie od argumentu bStateEnabled, domyślnie true.
	OPIS ARGUMENTÓW:
	OPIS ZMIENNYCH:
	OPIS WYNIKU METODY(FUNKCJI): Uchwyt na czcionkę.
*/
{
	TBBUTTONINFO tbi;

	SecureZeroMemory(&tbi, sizeof(TBBUTTONINFO));
	tbi.dwMask = TBIF_COMMAND | TBIF_STATE;
	tbi.cbSize = sizeof(TBBUTTONINFO);
	SendMessage(hToolBar, TB_GETBUTTONINFO, static_cast<WPARAM>(iCommand), reinterpret_cast<LPARAM>(&tbi));

	if(bStateEnabled) tbi.fsState = TBSTATE_ENABLED; else tbi.fsState = 0;
	SendMessage(hToolBar, TB_SETBUTTONINFO, static_cast<WPARAM>(iCommand), reinterpret_cast<LPARAM>(&tbi));
}
//---------------------------------------------------------------------------
HFONT GsGetSystemFont()
/**
	OPIS METOD(FUNKCJI): Odczyt systemowej czcionki.
	OPIS ARGUMENTÓW:
	OPIS ZMIENNYCH:
	OPIS WYNIKU METODY(FUNKCJI):
*/
{
	HFONT hFont=nullptr;

	//Odczyt domyślnej czcionki
	NONCLIENTMETRICS ncMetrics;
	size_t ncmSize = sizeof(NONCLIENTMETRICS);

#if _WIN32_WINNT >= 0x0600	//System równy lub nowszy od Windows Visty
	OSVERSIONINFOEX osvi;
	SecureZeroMemory(&osvi, sizeof(OSVERSIONINFOEX));
	osvi.dwOSVersionInfoSize = sizeof(OSVERSIONINFOEX);
	GetVersionEx(reinterpret_cast<OSVERSIONINFO *>(&osvi));

	if (osvi.dwMajorVersion < 6) ncmSize -= sizeof(ncMetrics.iPaddedBorderWidth);
#endif

	SecureZeroMemory(&ncMetrics, ncmSize);	//memset(&ncMetrics, 0, ncmSize);
	ncMetrics.cbSize = ncmSize;
	SystemParametersInfo(SPI_GETNONCLIENTMETRICS, ncmSize, &ncMetrics, 0);
	hFont = CreateFontIndirect(&ncMetrics.lfMessageFont);

	return hFont;
}
//---------------------------------------------------------------------------
bool GsLoadFile(TCHAR *lpszOutFile, const size_t sizeOutFile)
/**
	OPIS METOD(FUNKCJI): Wybiera dialog do wyboru pliku
	OPIS ARGUMENTÓW:
	OPIS ZMIENNYCH:
	OPIS WYNIKU METODY(FUNKCJI):
*/
{
	bool bRet=false;
	OPENFILENAME ofn;

	SecureZeroMemory(lpszOutFile, sizeOutFile);
	SecureZeroMemory(&ofn, sizeof(ofn));
	ofn.lStructSize = sizeof(ofn);
	ofn.lpstrFilter = TEXT("Wszystkie pliki\0*.*\0");
	ofn.nMaxFile = MAX_PATH;
	ofn.lpstrFile = lpszOutFile;
	ofn.lpstrFileTitle = const_cast<TCHAR *>(TEXT("Otwórz plik do zakodowanie lub odkodowania."));
	//ofn.lpstrDefExt = TEXT("py");
	ofn.lpstrInitialDir = nullptr;
	ofn.Flags = OFN_FILEMUSTEXIST | OFN_PATHMUSTEXIST | OFN_HIDEREADONLY;

	if(GetOpenFileName(&ofn))
	{
		bRet = true;
	}

	return bRet;
}
//---------------------------------------------------------------------------
bool GsSelectProjectDirectory(TCHAR *lpszSelectDir, const TCHAR *lpszDefaultDir)
/**
	OPIS METOD(FUNKCJI): Otwiera okno dialogowe do wyboru katalogu
	OPIS ARGUMENTÓW:
	OPIS ZMIENNYCH:
	OPIS WYNIKU METODY(FUNKCJI):
*/
{
	bool bRet=false;
	BROWSEINFO bi;

	//Wybieranie katalogu z projektem
	SecureZeroMemory(&bi, sizeof(BROWSEINFO));		//Zerowanie nowego rekordu
	bi.lpszTitle	= TEXT("Wybierz katalog do zaszyfrowania lub odszyfrowania...");
	bi.ulFlags		= BIF_USENEWUI | BIF_DONTGOBELOWDOMAIN | BIF_RETURNONLYFSDIRS | BIF_NEWDIALOGSTYLE | BIF_NONEWFOLDERBUTTON;
	bi.lpfn				= GsBrowseCallBackProc;
	bi.lParam = reinterpret_cast<LPARAM>(lpszDefaultDir);//Aktualny katalog

	LPITEMIDLIST pidl = SHBrowseForFolder(&bi);

	if(pidl != nullptr)
	{
		SHGetPathFromIDList(pidl, lpszSelectDir);

		//Zwolnienie pamięci utworzonego pidla, w funkcji SHBrowseForFolder.
		IMalloc *pImalloc=nullptr;
		if(SUCCEEDED(SHGetMalloc(&pImalloc)))
		{
			pImalloc->Free(pidl);
			pImalloc->Release();
		}
		bRet = true;
	}
	else bRet = false;

	return bRet;
}
//---------------------------------------------------------------------------
int CALLBACK GsBrowseCallBackProc(const HWND hwnd, const UINT uMsg, LPARAM lParam, const LPARAM lpData)
/**
	OPIS METOD(FUNKCJI):
	OPIS ARGUMENTÓW:
	OPIS ZMIENNYCH:
	OPIS WYNIKU METODY(FUNKCJI):
*/
{
	if(uMsg == BFFM_INITIALIZED)
	{
		SendMessage(hwnd, BFFM_SETSELECTION, TRUE, lpData);
	}
	return 0;
}
//---------------------------------------------------------------------------
bool __fastcall GsGetControlSize(const HWND hControl, const HWND hParentControl, RECT &rRectControl)
/**
	OPIS METOD(FUNKCJI): Funkcja zwraca wymiary wzgledem kontrolki nadrzędnej
	OPIS ARGUMENTÓW:
	OPIS ZMIENNYCH:
	OPIS WYNIKU METODY(FUNKCJI):
*/
{
	if (!IsWindow(hControl) || !IsWindow(hParentControl)) return false;

	RECT rcScreen;
	if(!GetWindowRect(hControl, &rcScreen)) return false;

	POINT pt = { rcScreen.left, rcScreen.top };
	if (!ScreenToClient(hParentControl, &pt)) return false;

	rRectControl.left		= pt.x;
	rRectControl.top		= pt.y;
	rRectControl.right	= pt.x + (rcScreen.right - rcScreen.left);
	rRectControl.bottom = pt.y + (rcScreen.bottom - rcScreen.top);

	return true;
}
//---------------------------------------------------------------------------
void __fastcall GsSetFontForAll(const HWND hParent, HFONT hFont)
/**
	OPIS METOD(FUNKCJI): Funkcja przyporządkowywuje czcionki wszystkim kontrolkom
	OPIS ARGUMENTÓW:
	OPIS ZMIENNYCH:
	OPIS WYNIKU METODY(FUNKCJI):
*/
{
	HWND hCtrl = GetWindow(hParent, GW_CHILD);
	while(hCtrl)
	{
		SendMessage(hCtrl, WM_SETFONT, reinterpret_cast<WPARAM>(hFont), TRUE);
		hCtrl = GetWindow(hCtrl, GW_HWNDNEXT);
	}
}
//---------------------------------------------------------------------------
bool __fastcall GsIsDirectory(LPCTSTR lpszPath)
/**
	OPIS METOD(FUNKCJI): Funkcja sprawdzająca, czy ścieżka dostepu jest katalogiem
	OPIS ARGUMENTÓW:
	OPIS ZMIENNYCH:
	OPIS WYNIKU METODY(FUNKCJI):
*/
{
	const DWORD attrs = GetFileAttributes(lpszPath);
	if(attrs == INVALID_FILE_ATTRIBUTES) return false;
	return (attrs & FILE_ATTRIBUTE_DIRECTORY);
}
//---------------------------------------------------------------------------
bool __fastcall GsReadDataFromFile(LPCWSTR lpszFilePath, GsStoreData *pOut)
/**
	OPIS METOD(FUNKCJI): Wczytanie całego pliku do bufora (HeapAlloc)
	OPIS ARGUMENTÓW:
	OPIS ZMIENNYCH:
	OPIS WYNIKU METODY(FUNKCJI): Zwraca true w przypadku sukcesu, false w przypadku błędu.
*/
{
	BOOL bResult=false;
	HANDLE hFile=INVALID_HANDLE_VALUE;
	LARGE_INTEGER liSizeInput;
	//LARGE_INTEGER liSize;
	BYTE* pBuf=nullptr;

	if (!lpszFilePath || !pOut) return false;

	auto CleanupRead = [&]()
	/**
		OPIS METOD(FUNKCJI): Funkcja zwalniająca zarezerwowane zasoby podczas błędu
												 lub zakończenia nadrzędnej funkcji typu lambda
	*/
	{
		if(hFile != INVALID_HANDLE_VALUE) {CloseHandle(hFile); hFile = INVALID_HANDLE_VALUE;}
		if(pBuf) {HeapFree(GetProcessHeap(), 0, pBuf); pBuf = nullptr;}
	};

	hFile = CreateFile(lpszFilePath, GENERIC_READ, FILE_SHARE_READ,
		nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
	if(hFile == INVALID_HANDLE_VALUE)
	{
		MessageBox(nullptr, TEXT("Błąd funkcji CreateFile!"), TEXT("Błąd"), MB_ICONERROR);
		CleanupRead(); return false;
	}

	if(!GetFileSizeEx(hFile, &liSizeInput)) {CleanupRead(); return false;}

	// Ograniczenie: plik musi zmieścić się w DWORD.
	if(liSizeInput.QuadPart <= 0 || liSizeInput.QuadPart > 0xFFFFFFFFULL) {{CleanupRead(); return false;}}

	const DWORD cbSize = liSizeInput.QuadPart;
	pBuf = static_cast<BYTE*>(HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, cbSize));
	if(!pBuf) {CleanupRead(); return false;}

	DWORD cbRead = 0;
	if(!ReadFile(hFile, pBuf, cbSize, &cbRead, nullptr) || cbRead != cbSize)
	{
		MessageBox(nullptr, TEXT("Błąd funkcji ReadFile!"), TEXT("Błąd"), MB_ICONERROR);
		CleanupRead(); return false;
	}

	pOut->pBData = pBuf;
	pOut->DDataLen = cbSize;
	bResult = true;

	if(hFile != INVALID_HANDLE_VALUE) {CloseHandle(hFile); hFile = INVALID_HANDLE_VALUE;}
	return bResult;
}
//---------------------------------------------------------------------------
bool __fastcall GsWriteDataToFile(LPCWSTR lpszFilePath, const BYTE* pData, DWORD cbData)
/**
	OPIS METOD(FUNKCJI): Zapis bufora do pliku (nadpisanie / utworzenie)
	OPIS ARGUMENTÓW:
	OPIS ZMIENNYCH:
	OPIS WYNIKU METODY(FUNKCJI): Zwraca true w przypadku sukcesu, false w przypadku błędu.
	UWAGI:
*/
	{
		bool bResult=false;
		HANDLE hFile=INVALID_HANDLE_VALUE;

		if (!lpszFilePath || !pData || cbData==0) return false;

		auto CleanupWrite = [&]()
		/**
			OPIS METOD(FUNKCJI): Funkcja zwalniająca zarezerwowane zasoby podczas błędu
													 lub zakończenia nadrzędnej funkcji typu lambda
		*/
		{if(hFile != INVALID_HANDLE_VALUE) {CloseHandle(hFile); hFile = INVALID_HANDLE_VALUE;}};

		hFile = CreateFile(lpszFilePath, GENERIC_WRITE, 0, nullptr,
			CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
		if(hFile == INVALID_HANDLE_VALUE)
		{
			MessageBox(nullptr, TEXT("Błąd funkcji CreateFile!"), TEXT("Błąd"), MB_ICONERROR);
			CleanupWrite(); return false;
		}

		DWORD cbWritten = 0;
		if(!WriteFile(hFile, pData, cbData, &cbWritten, nullptr) && cbWritten == cbData)
		{
			MessageBox(nullptr, TEXT("Błąd funkcji WriteFile!"), TEXT("Błąd"), MB_ICONERROR);
			CleanupWrite(); return false;
		}

		CleanupWrite();
		bResult = true;
		return bResult;
}
//---------------------------------------------------------------------------