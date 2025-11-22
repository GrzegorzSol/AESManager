// Copyright (c) Grzegorz Sołtysik
// Nazwa projektu: AESManager
// Nazwa pliku: main.cpp
// Data: 20.11.2025, 07:13

#define STRICT
#define NO_WIN32_LEAN_AND_MEAN
#define UNICODE

#include <windows.h>
#include <shlwapi.h>
#include <commctrl.h>
#include <pathcch.h>
//#include <shlobj.h>
//#include <commdlg.h>
#include "AESManager_resource.h"
#include "MyVersion.h"
#include <Strsafe.h>
#include "GsAES.h"
#include "GsWinLibrary.h"
#include "AESManager.h"

#define WM_TRAYICON (WM_USER + 1)

void __fastcall OnCreate(HWND hwnd, UINT message, WPARAM wParam, LPARAM lParam);	//Procedura wywoływana podczas tworzenia okna
void __fastcall OnDestroy(HWND hwnd, UINT message, WPARAM wParam, LPARAM lParam);//Procedura wywoływana podczas niszczenia okna
void __fastcall OnResize(HWND hwnd, UINT message, LPARAM lParam);//Procedura wywoływana podczas zmiany wymiarów okna
void __fastcall OnCommand(HWND hwnd, UINT message, WPARAM wParam, LPARAM lParam);//Procedura wywoływana podczas kliknięcia kontrolkę
void __fastcall OnNotify(HWND hwnd, UINT message, LPARAM lParam);//Procedura wywoływana podczas komunikatu WM_NOTIFY
void __fastcall OnPaint(HWND hwnd, UINT message, LPARAM lParam); // Procedura malowania po oknie
void __fastcall OnDrawItem(HWND hwnd, UINT message, WPARAM wParam, LPARAM lParam); // Procedura właśnego rysowania

void __fastcall CreateToolBar(HWND hwnd);	// Tworzenie Toolbara
void __fastcall CreateStatusBar(HWND hwnd);	// Tworzenie Statusbara
void __fastcall CreateOtherControls(HWND hwnd); // Tworzenie pozostałych kontrolek
void __fastcall AddTrayIcon(HWND hwnd);	// Tworzenie ikony traja oraz powiadomienia
void __fastcall ShowTrayMenu(HWND hwnd);	// Tworzenie i otwieranie popupmenu traja
void __fastcall ReadFileConfig(); // Odczyt konfiguracji
void __fastcall WriteFileConfig(); // Zapis konfiguracji
void __fastcall RunProcess(); // Wykonywanie mieszania hasła, a następnie szyfrowania lub deszyfrowania
bool __fastcall IsExistParamsEdit(); // Funkcja sprawdza, czy istnieje hasło, ścieżka wejściowa i wyjściowa
bool __fastcall SaveHistoryFile(); // Funkcja zapisująca plik historii.
bool __fastcall LoadHistoryFile(); // Funkcja, która wczytuje plik histori na początku.
void __fastcall AppendMemoInfos(LPCWSTR lpszTextAdd); // Dodanie nowej lini do historii.

NOTIFYICONDATA GLOBAL_NID;

static TCHAR *GLOBAL_STRVERSION=nullptr,
			  GLOBAL_PROJECTDIRECTORY[MAX_PATH],
			  //---
			  GLOBAL_GETEXEDIR[MAX_PATH],	// Ścieżka dostępu do katalogu aplikacji
			  GLOBAL_PATHCONFIG[MAX_PATH],
			  GLOBAL_INPUTFILE[MAX_PATH],	// Ścieżka dostępu do pliku wczytanego
			  GLOBAL_OUTPUTFILE[MAX_PATH];// Ścieżka dostępu do pliku po zaszyfrowaniu lub odszyfrowaniu
int constexpr GLOBAL_ICSTARTWIDTH = 1190,	//Domyślna szerokość okna
			  GLOBAL_ICSTARTHEIGHT = 520,	//Domyślna wysokość okna
			  GLOBAL_CIMAXLONGTEXTHINT = 100,
			  GLOBAL_WIDTH_BUTT_VIEW_PASS = 138, // Szerokość przycisku pokazywania hasła
			  GLOBAL_HEIGHT_BUTT_VIEW_PASS = 42;	// Wysokość przycisku pokazywania hasła

HFONT GLOBAL_HFONT=nullptr;//Główna czcionka
HICON GLOBAL_HICON_VIEWPASS=nullptr; // Ikona dla przycisku podglądu hasła

HIMAGELIST GLOBAL_HIMGLIST32=nullptr;	//ImageList globalna 32x32
HINSTANCE GLOBAL_HINSTANCE=nullptr;	//Uchwyt na aplikacje
HWND GLOBAL_MAINWINDOW=nullptr,	//Główne okno
		//--- Kontrolki
		GLOBAL_HTOOLBAR=nullptr,		// Kontrolka ToolBaru
		GLOBAL_HSTATUSBAR=nullptr,	// Kontrolka StatusBar
		GLOBAL_HMEMORYTEXTINFOS=nullptr, // Kontrolka memo text
		GLOBAL_PANEL=nullptr,	// Panel na przyciski
		GLOBAL_LABELPASS=nullptr, // Etykieta
		GLOBAL_EDITPASSWORD=nullptr,	// Kontrolka do wprowadzania hasła
		GLOBAL_BUTTON_VIEPASS=nullptr,	// Przycisk pokazywania hasła
		// Kontrolki ścieżek dostępu do pliku wejściowego i wyjściowego
		// razem z etykietami
		GLOBAL_PATH_EDITINPUT=nullptr,
		GLOBAL_PATH_LABEL_INPUT=nullptr,
		GLOBAL_PATH_EDITOUTPUT=nullptr,
		GLOBAL_PATH_LABEL_OUTPUT=nullptr,
		// Przyciski radiowe typu szyfrowania
		GLOBAL_RGROUP_AES128=nullptr,
		GLOBAL_RGROUP_AES256=nullptr;
RECT GLOBAL_RECT_BOTTPANEL,
	 GLOBAL_RECT_LEFTTOPPANEL,
	 GLOBAL_RECT_RIGHTTOPPANEL;
bool GLOBAL_TOGGLE_STATE_PASS=false; // Stan przycisku pokazywania stanu hasła

GsAES *GLOBAL_PGSAES=nullptr;

LRESULT CALLBACK WndProc(HWND hwnd, UINT message, WPARAM wParam, LPARAM lParam)
/**
	OPIS METOD(FUNKCJI):
	OPIS ARGUMENTÓW:
	OPIS ZMIENNYCH:
	OPIS WYNIKU METODY(FUNKCJI):
*/
{
	switch(message)
	{
		case WM_CREATE:
			OnCreate(hwnd, message, wParam, lParam);	//Procedura wywoływana podczas tworzenia okna
			break;
		//---
		case WM_CTLCOLORSTATIC:
		{
			HWND hCtl = reinterpret_cast<HWND>(lParam);
			HDC hdcStatic = reinterpret_cast<HDC>(wParam);

			if(hCtl == GLOBAL_HMEMORYTEXTINFOS)
			{
				SetTextColor(hdcStatic, RGB(255, 255, 255));
				SetBkMode(hdcStatic, TRANSPARENT);
				return reinterpret_cast<LRESULT>(GetStockObject(BLACK_BRUSH));
			}
			if(hCtl == GLOBAL_LABELPASS)
			{
				SetBkMode(hdcStatic, TRANSPARENT);	// przezroczyste tło
				SetTextColor(hdcStatic, RGB(255, 0, 0));	// Czerwony tekst

				return reinterpret_cast<LRESULT>(GetStockObject(HOLLOW_BRUSH)); // Brak tła.
			}
		}
			break;
		//---
		case WM_TRAYICON:
			if(lParam == WM_RBUTTONDOWN)
			{
				ShowTrayMenu(hwnd);
			}
			break;
		//---
		case WM_SIZE:
			OnResize(hwnd, message, lParam);	//Procedura wywoływana podczas tworzenia okna
			break;
		//---
		case WM_COMMAND:
			OnCommand(hwnd, message, wParam, lParam);
			break;
		//---
		case WM_NOTIFY:
			OnNotify(hwnd, message, lParam);
			break;
		//---
		case WM_MOUSEMOVE:
			break;
		//---
		case WM_CLOSE:
			{
				TASKDIALOGCONFIG tdc;

				SecureZeroMemory(&tdc, sizeof(tdc));

				tdc.cbSize = sizeof(TASKDIALOGCONFIG);
				tdc.hwndParent = hwnd;
				tdc.hInstance = GLOBAL_HINSTANCE;
				tdc.dwFlags = TDF_ALLOW_DIALOG_CANCELLATION | TDF_USE_HICON_MAIN;
				tdc.dwCommonButtons = TDCBF_OK_BUTTON | TDCBF_CANCEL_BUTTON;
				tdc.pszWindowTitle = TEXT("Zapytanie aplikacji");
				tdc.pszMainInstruction = TEXT("Czy naprawdę chcesz opuścić aplikację: \"AESManager\"?");
				tdc.pszContent = TEXT("Naciśnięcie przycisku OK spowoduje zamknięcie aplikacji. Zapisz konfiguracje jesli nie zapisałeś zanim opuścisz aplikacje.");
				tdc.hMainIcon = static_cast<HICON>(LoadImage(GLOBAL_HINSTANCE, MAKEINTRESOURCE(ICON_MAIN_ICON), IMAGE_ICON,
					32, 32, LR_DEFAULTCOLOR));

				int nButton = 0;
				TaskDialogIndirect(&tdc, &nButton, nullptr, nullptr);
				if (nButton == IDOK) DestroyWindow(hwnd);
			}
			break;
		//---
		case WM_PAINT:
			OnPaint(hwnd, message, lParam);
			break;
		//---
		case WM_DRAWITEM:
			OnDrawItem(hwnd, message, wParam, lParam);
			return true;
			//break;
		//---
		case WM_DESTROY:
			OnDestroy(hwnd, message, wParam, lParam);	//Procedura wywoływana podczas niszczenia okna
			PostQuitMessage(0);
			break;
		//---
		default:
			return DefWindowProc(hwnd, message, wParam, lParam);
	}
	return 0;
}
//---------------------------------------------------------------------------
int WINAPI WinMain(HINSTANCE hThisInstance, HINSTANCE hPrevInstance,
				LPSTR lpCmdLine, int nCmdShow)
/**
	OPIS METOD(FUNKCJI):
	OPIS ARGUMENTÓW:
	OPIS ZMIENNYCH:
	OPIS WYNIKU METODY(FUNKCJI):
*/
{
	WNDCLASSEX wincl;
	//Uchwyt do okna ekranu
	RECT rectScreen;
	TCHAR szpTextInfo[255];

  // Odczyt ścieżki dostępu do katalogu aplikacji
	SecureZeroMemory(&GLOBAL_GETEXEDIR, sizeof(GLOBAL_GETEXEDIR));
	GetModuleFileNameW(nullptr, GLOBAL_GETEXEDIR, MAX_PATH);
	PathCchRemoveFileSpec(GLOBAL_GETEXEDIR, MAX_PATH);
	// Stworzenie ścieżki do pliku konfiguracji
	PathCchCombine(GLOBAL_PATHCONFIG, MAX_PATH, GLOBAL_GETEXEDIR, GLOBAL_CONFIGFILENAME);
	//MessageBox(nullptr, GLOBAL_PATHCONFIG, TEXT("Katalog aplikacji"), MB_ICONINFORMATION);

	GLOBAL_STRVERSION = MyVersion::GetInfo(); // Informacja o wersji
	SecureZeroMemory(&szpTextInfo, sizeof(szpTextInfo));
	StringCchPrintf(szpTextInfo, 100, TEXT("AESManager v%s (c) Grzegorz Sołtysik"), GLOBAL_STRVERSION);
	SecureZeroMemory(&GLOBAL_NID, sizeof(GLOBAL_NID));

	//Rejestracja nowych klas GUI
	INITCOMMONCONTROLSEX icex;
	icex.dwSize = sizeof(INITCOMMONCONTROLSEX);
	icex.dwICC  = ICC_BAR_CLASSES | ICC_TAB_CLASSES; // toolbary, status bary i tool tipy
	BOOL bRetCommon = InitCommonControlsEx(&icex);
	if(!bRetCommon) //Błąd
	{
		MessageBox(nullptr, TEXT("Błąd inicjalizacji obsługi kontrolek!"),TEXT("Błąd!"),MB_ICONEXCLAMATION | MB_ICONERROR | MB_OK);
		return 0;
	}

	GLOBAL_HINSTANCE = hThisInstance;
	//Wymiary ekranu, dla wyśrodkowania głównego okna
	HWND hwndScreen = GetDesktopWindow();
	GetWindowRect(hwndScreen, &rectScreen);	//Wymiary okna głównego
	int iWidthScr = rectScreen.right - rectScreen.left;
	int iHeightScr = rectScreen.bottom - rectScreen.top;

	ZeroMemory(&wincl, sizeof(WNDCLASSEX));

	//Domyślny wygląd wskaźnika myszy i ikony okna
	wincl.hIcon = LoadIcon(hThisInstance, IDI_APPLICATION);
	wincl.hIconSm = LoadIcon(hThisInstance,  MAKEINTRESOURCE(ICON_MAIN_ICON));
	wincl.hCursor = LoadCursor(nullptr, IDC_ARROW);
	wincl.lpszMenuName = nullptr;                 //Bez menu
	wincl.cbClsExtra = 0;
	wincl.cbWndExtra = 0;
	wincl.lpfnWndProc = WndProc;
	wincl.hInstance = hThisInstance;
	wincl.lpszClassName = GLOBAL_CLASS_NAME;
	wincl.style = CS_HREDRAW | CS_VREDRAW | CS_PARENTDC;//CS_DBLCLKS;
	wincl.cbSize = sizeof(WNDCLASSEX);
	wincl.hbrBackground = reinterpret_cast<HBRUSH>(COLOR_BTNFACE);// + 1); // białe tło

	if(!RegisterClassEx(&wincl)) return 0;

	GLOBAL_MAINWINDOW = CreateWindowEx(
		0,
		GLOBAL_CLASS_NAME,
		szpTextInfo,//TITLE_WINDOW,
		//WS_OVERLAPPEDWINDOW,
		WS_VISIBLE | WS_CAPTION | WS_SYSMENU,
		iWidthScr / 2 - (GLOBAL_ICSTARTWIDTH / 2),       //Wyśrodkowanie w poziomie okna
		iHeightScr / 2 - (GLOBAL_ICSTARTHEIGHT / 2),			//Wyśrodkowanie w pionie okna
		GLOBAL_ICSTARTWIDTH,                							//Szerokość okna
		GLOBAL_ICSTARTHEIGHT,                 						//Wysokość okna
		HWND_DESKTOP,
		nullptr,
		hThisInstance,
		nullptr
	);

	if(GLOBAL_MAINWINDOW == nullptr) return 0;

	ShowWindow(GLOBAL_MAINWINDOW, nCmdShow);

	MSG msg;
	ZeroMemory(&msg, sizeof(MSG));
	while (GetMessage(&msg, nullptr, 0, 0))
	{
		TranslateMessage(&msg);
		DispatchMessage(&msg);
	}

	return static_cast<int>(msg.wParam);
}
//---------------------------------------------------------------------------
void __fastcall OnCreate(HWND hwnd, UINT message, WPARAM wParam, LPARAM lParam)
/**
	OPIS METOD (FUNKCJI): Procedura wywoływana podczas tworzenia okna
	OPIS ARGUMENTÓW:
	OPIS ZMIENNYCH:
	OPIS WYNIKU METODY (FUNKCJI):
*/
{
	//Odczyt i udostępnienie czcionki systemowej
	GLOBAL_HFONT = CreateFont(-MulDiv(GLOBAL_SIZE_FONT, GetDeviceCaps(GetDC(nullptr), LOGPIXELSY), 72), // wysokość w punktach
		0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE,
		DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY,
		DEFAULT_PITCH | FF_DONTCARE,
		GLOBAL_FONT_NAME); // lub "Consolas", "Tahoma", "Courier New"

	if(!GLOBAL_HFONT) return;
	// Załadowanie ikony dla podglądu hasła
	GLOBAL_HICON_VIEWPASS = static_cast<HICON>(LoadImage(GLOBAL_HINSTANCE, MAKEINTRESOURCEW(VIEW_PASS), IMAGE_ICON,
		32, 32,LR_DEFAULTCOLOR));
	if(!GLOBAL_HICON_VIEWPASS) return;
	// Tworzenie koloru dla memo
	//GLOBAL_HBRUSHTEXTCOLOR = CreateSolidBrush(RGB(0, 0, 0)); // Kolor tekstu w memo
	// Dodawanie tray icon
	AddTrayIcon(hwnd);
	//Stworzenie globalnej ImageListy
	GLOBAL_HIMGLIST32 = ImageList_Create(32, 32, ILC_COLOR32, 0, 0);
	if(!GLOBAL_HIMGLIST32) return;
	CreateToolBar(hwnd);				// Tworzenie ImageList oraz ToolBar
	CreateStatusBar(hwnd);			// Tworzenie status bara
	CreateOtherControls(hwnd);	// Tworzenie pozostałych kontrolek
	ReadFileConfig();
	LoadHistoryFile();
	//---
	GLOBAL_PGSAES = new GsAES();
	if(!GLOBAL_PGSAES)
	// Usunięcie klasy GsAES
	{
		MessageBox(nullptr, TEXT("Błąd inicjalizacji objektu, klasy GsAES"), TEXT("Error"), MB_ICONINFORMATION);
		OnDestroy(nullptr, 0, 0, 0);
		PostQuitMessage(0);
	}
	SetFontForAll(hwnd, GLOBAL_HFONT);
	//printf("OnCreate\n");
}
//---------------------------------------------------------------------------
void __fastcall OnDestroy(HWND hwnd, UINT message, WPARAM wParam, LPARAM lParam)
/**
	OPIS METOD(FUNKCJI): Procedura wywoływana podczas niszczenia okna
	OPIS ARGUMENTÓW:
	OPIS ZMIENNYCH:
	OPIS WYNIKU METODY(FUNKCJI):
*/
{
	ImageList_Destroy(GLOBAL_HIMGLIST32);	//Zniszczenie globalnej ImageListy dużej, 32x32
	GLOBAL_HIMGLIST32 = nullptr;
	// Zwolnienie uchwytu do ikonu pokazywania hasła
	DestroyIcon(GLOBAL_HICON_VIEWPASS);
	GLOBAL_HICON_VIEWPASS = nullptr;
	//Zwolnienie uchwytu do czcionki
	DeleteObject(GLOBAL_HFONT);
	GLOBAL_HFONT = nullptr;
	//WriteFileConfig();
	Shell_NotifyIcon(NIM_DELETE, &GLOBAL_NID);
	if(GLOBAL_PGSAES) {delete GLOBAL_PGSAES; GLOBAL_PGSAES = nullptr;}
}
//---------------------------------------------------------------------------
void __fastcall OnResize(HWND hwnd, UINT message, LPARAM lParam)
/**
	OPIS METOD (FUNKCJI): Procedura wywoływana podczas zmiany wymiarów okna
	OPIS ARGUMENTÓW:
	OPIS ZMIENNYCH:
	OPIS WYNIKU METODY (FUNKCJI):
*/
{
	RECT RecHToolBar, //Wymiary kontrolki ToolBary
		 RectHStatusBar, //Wymiary kontrolki StatusBaru
		 RectHMemoryTextInfo, // Wymiary kontrolki Memo
		 RectHLabel,
		 RectEditPass,	// Wymiary edycji hasła
		 RectButtonPass,	// Wymiary przycisku do pokazywania hasla
		 RectLabelInput,	// Wymiary etykiety pliku wejściowego
		 RectLabelOutput,// wymiary etykiety pliku wyjściowego
		 RectEditInput,	// Wymiary pola edycji pliku wejściowego
		 RectEditOutput,	// Wymiary pola edycji pliku wyjściowego
		 RectRGroupAES128,	// Wymiary przycisku radiowego szyfrowania AES128
		 RectRGroupAES256;	// Wymiary przycisku radiowego szyfrowania AES256
	//Odczyt szerokości i wysokości okna, po zmianie jego rozmiarów
	int iWidthMainWindow = LOWORD(lParam),	//Nowa szerokość okna
		iHeightMainWindow = HIWORD(lParam), //Nowa wysokość okna
		iHeightControl;

	//Zmiana wysokości kontrolki StatusBaru
	SetWindowPos(GLOBAL_HSTATUSBAR, nullptr, 0, 0, iWidthMainWindow, 0, SWP_NOZORDER);
	GsGetControlSize(GLOBAL_HSTATUSBAR, hwnd, RectHStatusBar);	//Wymiary StatusBar

	//Zmiana wysokości kontrolki ToolBaru
	SetWindowPos(GLOBAL_HTOOLBAR, nullptr, 4, 0, iWidthMainWindow - 8, 0, SWP_NOZORDER);
	GsGetControlSize(GLOBAL_HTOOLBAR, hwnd, RecHToolBar);	//Wymiary ToolBaru
	//Zmiana wysokości kontrolki MemoEdit
	int TOP_HMEMORYTEXTINFO = (iHeightMainWindow - RecHToolBar.bottom) / 2;
	iHeightControl = RectHStatusBar.bottom - RectHStatusBar.top;
	SetWindowPos(GLOBAL_HMEMORYTEXTINFOS, nullptr, 4, TOP_HMEMORYTEXTINFO,
		iWidthMainWindow - 8, iHeightMainWindow - TOP_HMEMORYTEXTINFO - iHeightControl, SWP_NOZORDER);
	GsGetControlSize(GLOBAL_HMEMORYTEXTINFOS, hwnd, RectHMemoryTextInfo);	//Wymiary Memo

	GLOBAL_RECT_LEFTTOPPANEL = RECT{4, RecHToolBar.bottom + 4,
		iWidthMainWindow / 4, (iHeightMainWindow - RecHToolBar.bottom) / 3 + 16};
	GLOBAL_RECT_RIGHTTOPPANEL = RECT{GLOBAL_RECT_LEFTTOPPANEL.right + 4, GLOBAL_RECT_LEFTTOPPANEL.top,
		iWidthMainWindow - 4, GLOBAL_RECT_LEFTTOPPANEL.bottom};
	GLOBAL_RECT_BOTTPANEL = RECT{4, GLOBAL_RECT_LEFTTOPPANEL.bottom + 4,
		iWidthMainWindow - 4, RectHMemoryTextInfo.top - 4};

	// Edycja hasła
	HFONT hFontToSize = reinterpret_cast<HFONT>(SendMessage(GLOBAL_HMEMORYTEXTINFOS, WM_GETFONT, 0, 0));
	HDC hdc = GetDC(GLOBAL_HMEMORYTEXTINFOS);
	SelectObject(hdc, hFontToSize);

	TEXTMETRIC tm;
	GetTextMetrics(hdc, &tm);
	ReleaseDC(GLOBAL_HMEMORYTEXTINFOS, hdc); hdc = nullptr;

	// Etykieta hasła
	SetWindowPos(GLOBAL_LABELPASS, nullptr, GLOBAL_RECT_LEFTTOPPANEL.left + 8, GLOBAL_RECT_LEFTTOPPANEL.top + 4,
		GLOBAL_RECT_LEFTTOPPANEL.right - GLOBAL_RECT_LEFTTOPPANEL.left - 16,
		tm.tmHeight + tm.tmExternalLeading + 6, SWP_NOZORDER);
	GsGetControlSize(GLOBAL_LABELPASS, hwnd, RectHLabel);

	SetWindowPos(GLOBAL_EDITPASSWORD, nullptr, RectHLabel.left, RectHLabel.bottom,
		RectHLabel.right - RectHLabel.left, tm.tmHeight + tm.tmExternalLeading + 6, SWP_NOZORDER);
	GsGetControlSize(GLOBAL_EDITPASSWORD, hwnd, RectEditPass);

	// Pokazywanie hasła
	SetWindowPos(GLOBAL_BUTTON_VIEPASS, nullptr,
			((RectEditPass.right - RectEditPass.left) / 2) - (GLOBAL_WIDTH_BUTT_VIEW_PASS / 2),
			RectEditPass.bottom + 6,
			GLOBAL_WIDTH_BUTT_VIEW_PASS, GLOBAL_HEIGHT_BUTT_VIEW_PASS, SWP_NOZORDER);
	GsGetControlSize(GLOBAL_BUTTON_VIEPASS, hwnd, RectButtonPass);

	// Etykieta pliku wejściowego
	SetWindowPos(GLOBAL_PATH_LABEL_INPUT, nullptr,
		GLOBAL_RECT_RIGHTTOPPANEL.left + 32, RectEditPass.top, 100, RectHLabel.bottom - RectHLabel.top,
	SWP_NOZORDER);
	GsGetControlSize(GLOBAL_PATH_LABEL_INPUT, hwnd,RectLabelInput);

	// Etykieta pliku wyjściowego
	SetWindowPos(GLOBAL_PATH_LABEL_OUTPUT, nullptr,
		RectLabelInput.left, RectLabelInput.bottom + 4, 100, RectLabelInput.bottom - RectLabelInput.top,
		SWP_NOZORDER);
	GsGetControlSize(GLOBAL_PATH_LABEL_OUTPUT, hwnd, RectLabelOutput);

	// Pole tekstowe pliku wejściowego
	SetWindowPos(GLOBAL_PATH_EDITINPUT, nullptr,
		RectLabelInput.right + 16, RectLabelInput.top,
		(GLOBAL_RECT_RIGHTTOPPANEL.right - GLOBAL_RECT_RIGHTTOPPANEL.left) / 2 + ((RectLabelInput.right - RectLabelInput.left) * 2),
		RectEditPass.bottom - RectEditPass.top, SWP_NOZORDER);
	GsGetControlSize(GLOBAL_PATH_EDITINPUT, hwnd, RectEditInput);

	// Pole tekstowe pliku wyjściowego
	SetWindowPos(GLOBAL_PATH_EDITOUTPUT, nullptr,
		RectEditInput.left, RectLabelOutput.top, RectEditInput.right - RectEditInput.left,
		RectEditPass.bottom - RectEditPass.top, SWP_NOZORDER);
	GsGetControlSize(GLOBAL_PATH_EDITOUTPUT, hwnd, RectEditOutput);

	// Przycisk radiowy AES 128
	SetWindowPos(GLOBAL_RGROUP_AES128, nullptr,
		GLOBAL_RECT_BOTTPANEL.left + 8,
		GLOBAL_RECT_BOTTPANEL.top + ((GLOBAL_RECT_BOTTPANEL.bottom - GLOBAL_RECT_BOTTPANEL.top) / 2) - ((RectEditPass.bottom - RectEditPass.top) / 2),
		iWidthMainWindow / 2 - 32,
		RectEditPass.bottom - RectEditPass.top, SWP_NOZORDER);
	GsGetControlSize(GLOBAL_RGROUP_AES128, hwnd, RectRGroupAES128);

	// Przycisk radiowy AES 256
	SetWindowPos(GLOBAL_RGROUP_AES256, nullptr,
		iWidthMainWindow / 2 + 16, RectRGroupAES128.top, iWidthMainWindow / 2 - 32,
		RectEditPass.bottom - RectEditPass.top, SWP_NOZORDER);
	GsGetControlSize(GLOBAL_RGROUP_AES256, hwnd, RectRGroupAES256);
}
//---------------------------------------------------------------------------
void __fastcall OnCommand(HWND hwnd, UINT message, WPARAM wParam, LPARAM lParam)
/**
	OPIS METOD (FUNKCJI): Procedura wywoływana podczas kliknięcia kontrolkę
	OPIS ARGUMENTÓW:
	OPIS ZMIENNYCH:
	OPIS WYNIKU METODY (FUNKCJI):
*/
{
	// === Przyciski znajdujące się na toolbarze ===
	if(reinterpret_cast<HWND>(lParam) ==  GLOBAL_HTOOLBAR)
	{
		switch(LOWORD(wParam)) // Przyciski toolbaru
		{
			case IDBUTTON_OPEN_FILE:
			{
				//MessageBox(nullptr, TEXT("Nacisnąłeś przycisk Open"), TEXT("Error"), MB_ICONINFORMATION);
				TCHAR szFileOpen[MAX_PATH];
				PCWSTR pExt=nullptr;
				size_t sLenInputFile=0, sLenCryptText=0;

				StringCchLength(GLOBAL_CRYPTEXT, MAX_PATH, &sLenCryptText);
				SecureZeroMemory(szFileOpen, sizeof(szFileOpen));
				SecureZeroMemory(GLOBAL_INPUTFILE, sizeof(GLOBAL_INPUTFILE));

				GsLoadFile(szFileOpen); // Wybór pliku do przeprowadzenia operacji

				StringCchCopy(GLOBAL_INPUTFILE, MAX_PATH, szFileOpen); // Skopiowanie wybranej ścieżki do globalnej ścieżki
				PathCchFindExtension(GLOBAL_INPUTFILE, MAX_PATH, &pExt); // Wyodrębnienie rozszerzenia

				if(StrRStrI(pExt, nullptr, GLOBAL_CRYPTEXT)) // Wyszukanie dodatku do rozszerzenia GLOBAL_CRYPTEXT
				{
					StringCchLength(szFileOpen, MAX_PATH, &sLenInputFile); // Długość ściezki pliku wejściowego
					StringCchCopyN(GLOBAL_OUTPUTFILE, MAX_PATH, szFileOpen, sLenInputFile - sLenCryptText); // Skopiowanie ściężki bez GLOBAL_CRYPTEXT
				}
				else //NULL
				{
					StringCchCopy(GLOBAL_OUTPUTFILE, MAX_PATH, GLOBAL_INPUTFILE);
					StringCchCat(GLOBAL_OUTPUTFILE, MAX_PATH, GLOBAL_CRYPTEXT); // Dodanie do oryginalnego rozszerzenia, ciągu GLOBAL_CRYPTEXT.
				}
				SetWindowText(GLOBAL_PATH_EDITINPUT, GLOBAL_INPUTFILE);
				SetWindowText(GLOBAL_PATH_EDITOUTPUT, GLOBAL_OUTPUTFILE);
			}
			break;
			//---
			case IDBUTTON_PROCESS_FILE:
			{
				RunProcess();
			}
			break;
			//---
			case IDBUTTON_SAVECOFIG:
				WriteFileConfig();
				break;
			//---
			case IDBUTTON_PROCESS_DIR:
				SecureZeroMemory(GLOBAL_PROJECTDIRECTORY, sizeof(GLOBAL_PROJECTDIRECTORY));

				GsSelectProjectDirectory(GLOBAL_PROJECTDIRECTORY, const_cast<TCHAR *>(TEXT("")));
				GsSetStateToolBarButton(GLOBAL_HTOOLBAR, IDBUTTON_PROCESS_FILE, true);

				MessageBox(nullptr, GLOBAL_PROJECTDIRECTORY, TEXT("Informacja"), MB_ICONINFORMATION);
				break;
			//---
			case IDBUTTON_SAVE_HISTORY:
			{
				SaveHistoryFile();
			}
			break;
			//---
			case IDBUTTON_CLEARHISTORY:
				SetWindowText(GLOBAL_HMEMORYTEXTINFOS, TEXT(""));
			break;
			//---
			default: break;
		}
	}

	// === Przyciski nieznajdujące się na tool barze ===
	else if((reinterpret_cast<HWND>(lParam) ==  GLOBAL_BUTTON_VIEPASS) && (LOWORD(wParam) == IDBUTTON_VIEWPASS) &&
		(HIWORD(wParam) == BN_CLICKED))
	{
		// Pokazanie lub ukrycie hasłą.
		/*LRESULT checked =*/ SendMessage(GLOBAL_BUTTON_VIEPASS, BM_GETCHECK, 0, 0);
		GLOBAL_TOGGLE_STATE_PASS = !GLOBAL_TOGGLE_STATE_PASS;

		SendMessage(GLOBAL_EDITPASSWORD, EM_SETPASSWORDCHAR, static_cast<WPARAM>(GLOBAL_TOGGLE_STATE_PASS) ? 0 : GLOBAL_CODEPASS, 0);
		InvalidateRect(GLOBAL_EDITPASSWORD, nullptr, TRUE); // przerysuj przycisk.
	}

	// === Kontrola poprawnego wprowadzenia danych: Hasła, ścieżki wejściowej i wyjściowej. ===
	else if((reinterpret_cast<HWND>(lParam) == GLOBAL_EDITPASSWORD) && (LOWORD(wParam) == IDEDIT_PASS) &&
		(HIWORD(wParam) == EN_CHANGE))
	// Edycja hasła
	{
		// Przycisk rozpoczęcia procesu zacznie się tylko wtedy gdy będą istnieć trzy zmienne:
		// hasło, ścieżka wejściowa i wyjściowa.
		bool bIsExist = IsExistParamsEdit(); // Sprawdzanie istnienia trzech parametrów.
		SendMessage(GLOBAL_HTOOLBAR, TB_ENABLEBUTTON, IDBUTTON_PROCESS_FILE, MAKELONG(bIsExist, 0));
	}
	else if((reinterpret_cast<HWND>(lParam) == GLOBAL_PATH_EDITINPUT) && (LOWORD(wParam) == IDEDIT_PATH_INPUT) &&
		(HIWORD(wParam) == EN_CHANGE))
	// Edycja ścieżki wejściowej
	{
		// Przycisk rozpoczęcia procesu zacznie się tylko wtedy gdy będą istnieć trzy zmienne:
		// hasło, ścieżka wejściowa i wyjściowa.
		bool bIsExist = IsExistParamsEdit(); // Sprawdzanie istnienia trzech parametrów.
		SendMessage(GLOBAL_HTOOLBAR, TB_ENABLEBUTTON, IDBUTTON_PROCESS_FILE, MAKELONG(bIsExist, 0));
	}
	else if((reinterpret_cast<HWND>(lParam) == GLOBAL_PATH_EDITOUTPUT) && (LOWORD(wParam) == IDEDIT_PATH_OUTPUT) &&
		(HIWORD(wParam) == EN_CHANGE))
	// Edycja ścieżki wyjściowej
	{
		// Przycisk rozpoczęcia procesu zacznie się tylko wtedy gdy będą istnieć trzy zmienne:
		// hasło, ścieżka wejściowa i wyjściowa.
		bool bIsExist = IsExistParamsEdit(); // Sprawdzanie istnienia trzech parametrów.
		SendMessage(GLOBAL_HTOOLBAR, TB_ENABLEBUTTON, IDBUTTON_PROCESS_FILE, MAKELONG(bIsExist, 0));
	}

	// === Obsługa komunikatów z traya. ===
	else // Wybrano pozycja z menu traya.
	{
		switch(LOWORD(wParam))
		{
			case IDI_TRAY_EXIT:
				PostMessage(hwnd, WM_CLOSE, 0, 0); // zamknij aplikację.
				break;
			//---
			default: break;
		}
	}
}
//---------------------------------------------------------------------------
void __fastcall OnNotify(HWND hwnd, UINT message, LPARAM lParam)
/**
	OPIS METOD (FUNKCJI): Procedura wywoływana podczas komunikatu WM_NOTIFY
	OPIS ARGUMENTÓW:
	OPIS ZMIENNYCH:
	OPIS WYNIKU METODY (FUNKCJI):
*/
{

	switch ((reinterpret_cast<LPNMHDR>(lParam))->code)
	{
		//*******************************************************
		//*          Komunikaty z kontrolki Tool Tip            *
		//*******************************************************
		case TTN_GETDISPINFO:	//Dymki pomocy
		{
			LPNMTTDISPINFO  lPNMDispInfo = reinterpret_cast<LPNMTTDISPINFO>(lParam);
			lPNMDispInfo->hinst = GLOBAL_HINSTANCE;	//Ustawić, jeśli tekst do wyświetlenia będzie pochodził zasabów.
			UINT_PTR idButton = lPNMDispInfo->hdr.idFrom;

			//Wyłuskanie okna podpowiedzi
			HWND hWindowTips = reinterpret_cast<HWND>(SendMessage(GLOBAL_HTOOLBAR, TB_GETTOOLTIPS, (WPARAM)0, (LPARAM)0));
			if(!hWindowTips) return;
			if(HICON hIcon = ImageList_GetIcon(GLOBAL_HIMGLIST32, static_cast<int>(idButton) - ID_START_COUNT, ILD_IMAGE))
			{
				//Ustawienie maksymalnej szerokości okna podpowiedzi i umieszczenie tytułu z ikonką
				SendMessage(lPNMDispInfo->hdr.hwndFrom, TTM_SETTITLE, reinterpret_cast<WPARAM>(hIcon),
										reinterpret_cast<LPARAM>(GLOBAL_STRINGS[STR_TITLE_BUTTON_HINT]));
				DestroyIcon(hIcon); hIcon = nullptr;
			}

			switch(idButton)
			{
				case IDBUTTON_OPEN_FILE:
					lPNMDispInfo->lpszText = const_cast<TCHAR *>(GLOBAL_STRINGS[STR_TEXT_HINT_OPEN_FILE]);
					SendMessage(GLOBAL_HSTATUSBAR, SB_SETTEXT, 0, reinterpret_cast<LPARAM>(GLOBAL_STRINGS[STR_LONG_OPEN_FILE]));
					break;
				//---
				case IDBUTTON_PROCESS_FILE:
					lPNMDispInfo->lpszText = const_cast<TCHAR *>(GLOBAL_STRINGS[STR_TEXT_HINT_PROCESS_FILE]);
					SendMessage(GLOBAL_HSTATUSBAR, SB_SETTEXT, 0, reinterpret_cast<LPARAM>(GLOBAL_STRINGS[STR_LONG_PROCESS_FILE]));
					break;
				//---
				case IDBUTTON_SAVECOFIG:
					lPNMDispInfo->lpszText = const_cast<TCHAR *>(GLOBAL_STRINGS[STR_TEXT_HINT_SAVECONFIG]);
					SendMessage(GLOBAL_HSTATUSBAR, SB_SETTEXT, 0, reinterpret_cast<LPARAM>(GLOBAL_STRINGS[STR_LONG_SAVECONFIG]));
					break;
				//---
				case IDBUTTON_PROCESS_DIR:
					lPNMDispInfo->lpszText = const_cast<TCHAR *>(GLOBAL_STRINGS[STR_TEXT_HINT_PROCESS_DIR]);
					SendMessage(GLOBAL_HSTATUSBAR, SB_SETTEXT, 0, reinterpret_cast<LPARAM>(GLOBAL_STRINGS[STR_LONG_PROCESS_DIR]));
					break;
				//---
				case IDBUTTON_SAVE_HISTORY:
					lPNMDispInfo->lpszText = const_cast<TCHAR *>(GLOBAL_STRINGS[STR_TEXT_HINT_SAVE_HISTORY]);
					SendMessage(GLOBAL_HSTATUSBAR, SB_SETTEXT, 0, reinterpret_cast<LPARAM>(GLOBAL_STRINGS[STR_LONG_SAVE_HISTORY]));
					break;
				//---
				case IDBUTTON_CLEARHISTORY:
					lPNMDispInfo->lpszText = const_cast<TCHAR *>(GLOBAL_STRINGS[STR_TEXT_HINT_CLEARHISTORY]);
					SendMessage(GLOBAL_HSTATUSBAR, SB_SETTEXT, 0, reinterpret_cast<LPARAM>(GLOBAL_STRINGS[STR_LONG_CLEARHISTORY]));
					break;
				//---
				default:
					break;
			}
		}
		//---
		default:
			break;
	}
}
//---------------------------------------------------------------------------
void __fastcall OnPaint(HWND hwnd, UINT message, LPARAM lParam)
/**
	OPIS METOD (FUNKCJI): Procedura wywoływana podczas malowania w oknie
	OPIS ARGUMENTÓW:
	OPIS ZMIENNYCH:
	OPIS WYNIKU METODY (FUNKCJI):
*/
{
	PAINTSTRUCT ps;
	HDC hdc = BeginPaint(hwnd, &ps);

	DrawEdge(hdc, &GLOBAL_RECT_LEFTTOPPANEL, EDGE_SUNKEN, BF_RECT | BF_FLAT);
	DrawEdge(hdc, &GLOBAL_RECT_RIGHTTOPPANEL, EDGE_SUNKEN, BF_RECT | BF_FLAT);
	DrawEdge(hdc, &GLOBAL_RECT_BOTTPANEL, EDGE_SUNKEN, BF_RECT | BF_FLAT);

	EndPaint(hwnd, &ps);
}
//---------------------------------------------------------------------------
void __fastcall OnDrawItem(HWND hwnd, UINT message, WPARAM wParam, LPARAM lParam)
/**
	OPIS METOD (FUNKCJI): Procedura własnego rysowania
	OPIS ARGUMENTÓW:
	OPIS ZMIENNYCH:
	OPIS WYNIKU METODY (FUNKCJI):
*/
{
	LPDRAWITEMSTRUCT dis = reinterpret_cast<LPDRAWITEMSTRUCT>(lParam);

	switch(dis->CtlID)
	{
		case IDBUTTON_VIEWPASS:
		{
			// Tło zależne od stanu toggle
			COLORREF bgColor = GLOBAL_TOGGLE_STATE_PASS ? RGB(200, 230, 255) : RGB(240, 240, 240);
			HBRUSH hBrush = CreateSolidBrush(bgColor);
			FillRect(dis->hDC, &dis->rcItem, hBrush);
			DeleteObject(hBrush); hBrush = nullptr;
			// Stan wciśnięcia
			//RECT rc = dis->rcItem;
			DrawEdge(dis->hDC, &dis->rcItem,
				GLOBAL_TOGGLE_STATE_PASS ? EDGE_SUNKEN : EDGE_RAISED, BF_RECT);

			// Ikona 32×32 przy lewej krawędzi
			int iconX = dis->rcItem.left + 4;
			int iconY = dis->rcItem.top + (dis->rcItem.bottom - dis->rcItem.top - 32) / 2;
			DrawIconEx(dis->hDC, iconX, iconY, GLOBAL_HICON_VIEWPASS, 32, 32, 0,
				nullptr, DI_NORMAL);

			//Odczytanie tekstu z przycisku
			TCHAR textButton[256];
			GetWindowText(dis->hwndItem, textButton, ARRAYSIZE(textButton));

			// Tekst po prawej stronie ikony
			SetBkMode(dis->hDC, TRANSPARENT);
			SetTextColor(dis->hDC, RGB(0, 0, 0));

			RECT rcText = dis->rcItem;
			rcText.left += 32 + 8; // przesunięcie za ikonę
			DrawText(dis->hDC, textButton, -1, &rcText, DT_SINGLELINE | DT_LEFT | DT_VCENTER);
		}
		break;
		//---
		default: break;
	}
	/*
case WM_DRAWITEM:
{
	LPDRAWITEMSTRUCT dis = (LPDRAWITEMSTRUCT)lParam;

	// Kolory
	COLORREF bgColor     = g_ToggleState ? RGB(225, 235, 255) : RGB(245, 245, 245);
	COLORREF borderColor = RGB(200, 200, 200);
	COLORREF textColor   = RGB(0, 0, 0);

	// Tło
	HBRUSH hBrush = CreateSolidBrush(bgColor);
	FillRect(dis->hDC, &dis->rcItem, hBrush);
	DeleteObject(hBrush);

	// Obramowanie prostokątne
	HPEN hPen = CreatePen(PS_SOLID, 1, borderColor);
	HPEN hOldPen = (HPEN)SelectObject(dis->hDC, hPen);
	HBRUSH hOldBrush = (HBRUSH)SelectObject(dis->hDC, GetStockObject(NULL_BRUSH));

	Rectangle(dis->hDC,
		dis->rcItem.left, dis->rcItem.top,
		dis->rcItem.right, dis->rcItem.bottom);

	SelectObject(dis->hDC, hOldBrush);
	SelectObject(dis->hDC, hOldPen);
	DeleteObject(hPen);

	// Ikona 32×32 przy lewej krawędzi
	int iconX = dis->rcItem.left + 8;
	int iconY = dis->rcItem.top + (dis->rcItem.bottom - dis->rcItem.top - 32) / 2;
	DrawIconEx(dis->hDC, iconX, iconY, hIcon32, 32, 32, 0, NULL, DI_NORMAL);

	// Tekst z przycisku
	TCHAR text[256];
	GetWindowText(dis->hwndItem, text, ARRAYSIZE(text));

	SetBkMode(dis->hDC, TRANSPARENT);
	SetTextColor(dis->hDC, textColor);

	RECT rcText = dis->rcItem;
	rcText.left += 32 + 16;
	DrawText(dis->hDC, text, -1, &rcText,
			 DT_SINGLELINE | DT_LEFT | DT_VCENTER);
}
 */
}
//---------------------------------------------------------------------------
void __fastcall CreateToolBar(HWND hwnd)
/**
	OPIS METOD(FUNKCJI): Stworzenie ImageList, oraz ToolBar
	OPIS ARGUMENTÓW:
	OPIS ZMIENNYCH:
	OPIS WYNIKU METODY(FUNKCJI):
*/
{
	HBITMAP hbmObraz=nullptr;
	constexpr int ciCountButton = 6;

	//------------ Bitmapy z zasobów główny ToolBar 32x32
	hbmObraz = static_cast<HBITMAP>(LoadImage(GLOBAL_HINSTANCE, MAKEINTRESOURCE(OPEN_FILE), IMAGE_BITMAP, 0, 0, LR_DEFAULTCOLOR)); //3
	ImageList_Add(GLOBAL_HIMGLIST32, hbmObraz, nullptr);
	DeleteObject(hbmObraz); // kasowanie bitmapy

	hbmObraz = static_cast<HBITMAP>(LoadImage(GLOBAL_HINSTANCE, MAKEINTRESOURCE(PROCESS_FILE), IMAGE_BITMAP, 0, 0, LR_DEFAULTCOLOR)); //3
	ImageList_Add(GLOBAL_HIMGLIST32, hbmObraz, nullptr);
	DeleteObject(hbmObraz); // kasowanie bitmapy

	hbmObraz = static_cast<HBITMAP>(LoadImage(GLOBAL_HINSTANCE, MAKEINTRESOURCE(SAVE_CONFIG), IMAGE_BITMAP, 0, 0, LR_DEFAULTCOLOR)); //3
	ImageList_Add(GLOBAL_HIMGLIST32, hbmObraz, nullptr);
	DeleteObject(hbmObraz); // kasowanie bitmapy

	hbmObraz = static_cast<HBITMAP>(LoadImage(GLOBAL_HINSTANCE, MAKEINTRESOURCE(PROCESS_DIR), IMAGE_BITMAP, 0, 0, LR_DEFAULTCOLOR)); //3
	ImageList_Add(GLOBAL_HIMGLIST32, hbmObraz, nullptr);
	DeleteObject(hbmObraz); // kasowanie bitmapy

	hbmObraz = static_cast<HBITMAP>(LoadImage(GLOBAL_HINSTANCE, MAKEINTRESOURCE(SAVE_HISTORY), IMAGE_BITMAP, 0, 0, LR_DEFAULTCOLOR)); //2
	ImageList_Add(GLOBAL_HIMGLIST32, hbmObraz, nullptr);
	DeleteObject(hbmObraz); // kasowanie bitmapy

	hbmObraz = static_cast<HBITMAP>(LoadImage(GLOBAL_HINSTANCE, MAKEINTRESOURCE(CLEAR_HISTORY), IMAGE_BITMAP, 0, 0, LR_DEFAULTCOLOR)); //3
	ImageList_Add(GLOBAL_HIMGLIST32, hbmObraz, nullptr);
	DeleteObject(hbmObraz); // kasowanie bitmapy

	//--- Tworzenie ToolBaru z ImageList
	GLOBAL_HTOOLBAR = CreateWindowEx(WS_EX_STATICEDGE, TOOLBARCLASSNAME, nullptr,
		WS_CHILD | WS_VISIBLE | WS_CLIPCHILDREN | WS_CLIPSIBLINGS | WS_BORDER |
		TBSTYLE_TOOLTIPS | TBSTYLE_FLAT | TBSTYLE_LIST,
		0, 0, 0, 0, hwnd, nullptr, GLOBAL_HINSTANCE, nullptr);
	if(GLOBAL_HTOOLBAR == nullptr) return;

	SendMessage(GLOBAL_HTOOLBAR,TB_SETIMAGELIST,0, reinterpret_cast<LPARAM>(GLOBAL_HIMGLIST32));
	SendMessage(GLOBAL_HTOOLBAR,TB_SETBITMAPSIZE,0, (LPARAM)MAKELONG(32,32));

	TBBUTTON tButton[ciCountButton];

	SecureZeroMemory(tButton, sizeof(tButton) );
	for(int iLicz=0; iLicz<ciCountButton; ++iLicz)
	{
		tButton[iLicz].idCommand = iLicz + ID_START_COUNT;// + SAVE_PROJECT;	//Identyfikacja przycisku, wysyłana do pętli obługującej okno apliakcji.
		//WM_COMMAND i WM_NOTIFY
		tButton[iLicz].iString = reinterpret_cast<INT_PTR>(GLOBAL_STRINGS[STR_TEXT_HINT_OPEN_FILE + iLicz]);	//Napis pod przyciskiem
		tButton[iLicz].iBitmap = iLicz;
		if(tButton[iLicz].idCommand == IDBUTTON_PROCESS_FILE) //Indeks ikony w image list
			tButton[iLicz].fsState = 0; else tButton[iLicz].fsState = TBSTATE_ENABLED;
		tButton[iLicz].fsStyle = BTNS_AUTOSIZE | BTNS_SHOWTEXT;
	}

	SendMessage(GLOBAL_HTOOLBAR,TB_BUTTONSTRUCTSIZE, (WPARAM)sizeof(TBBUTTON), 0);
	SendMessage(GLOBAL_HTOOLBAR,TB_ADDBUTTONS,(WPARAM)ciCountButton, reinterpret_cast<LPARAM>(&tButton));
	//Skalowanie ToolButtona i jego wyświetlenie.
	SendMessage(GLOBAL_HTOOLBAR, TB_AUTOSIZE, 0, 0);
	//ShowWindow(GLOBAL_HTOOLBAR,  TRUE);

	// Wyłuskanie okna podpowiedzi i jego modyfikacja
	HWND hWindowTips=nullptr;
	if(hWindowTips = reinterpret_cast<HWND>(SendMessage(GLOBAL_HTOOLBAR, TB_GETTOOLTIPS, (WPARAM)0, (LPARAM)0)))
	{
		SetWindowLongPtr(hWindowTips, GWL_STYLE, WS_POPUP | TTS_NOPREFIX | TTS_ALWAYSTIP | TTS_BALLOON);
		SendMessage(hWindowTips, TTM_SETDELAYTIME, TTDT_AUTOPOP, (LPARAM)1500);
		SendMessage(hWindowTips, TTM_SETMAXTIPWIDTH, (WPARAM)0, (LPARAM)300);
	}

}
//-------------------------------------------------------------------------
void __fastcall CreateStatusBar(HWND hwnd)
/**
	OPIS METOD(FUNKCJI):
	OPIS ARGUMENTÓW:
	OPIS ZMIENNYCH:
	OPIS WYNIKU METODY(FUNKCJI):
*/
{
	int iStatusBarWidths[] = {768, -1};
	GLOBAL_HSTATUSBAR = CreateWindowEx(0, STATUSCLASSNAME, nullptr, SBARS_TOOLTIPS | WS_CHILD | WS_VISIBLE,
																		0, 0, 0, 0, hwnd,nullptr, GLOBAL_HINSTANCE, nullptr );
	if(GLOBAL_HSTATUSBAR == nullptr) return;

	SendMessage(GLOBAL_HSTATUSBAR, SB_SETPARTS, 2, reinterpret_cast<LPARAM>(iStatusBarWidths));
}
//---------------------------------------------------------------------------
void __fastcall CreateOtherControls(HWND hwnd)
/**
	OPIS METOD(FUNKCJI): Tworzenie pozostałych kontrolek
	OPIS ARGUMENTÓW:
	OPIS ZMIENNYCH:
	OPIS WYNIKU METODY(FUNKCJI):
*/
{
	//Kontrolka memo
	GLOBAL_HMEMORYTEXTINFOS = CreateWindowEx(0, TEXT("EDIT"), nullptr, WS_CHILD | WS_VISIBLE | WS_BORDER |
		WS_VSCROLL | ES_MULTILINE | ES_AUTOVSCROLL | ES_AUTOHSCROLL | ES_READONLY,
		0, 0, 0, 0, hwnd, nullptr, GLOBAL_HINSTANCE, nullptr);
	if(GLOBAL_HMEMORYTEXTINFOS == nullptr) return;
	// Edycja hasła
	GLOBAL_EDITPASSWORD = CreateWindowEx(0, TEXT("EDIT"), nullptr,
		WS_CHILD | WS_VISIBLE | WS_BORDER | ES_PASSWORD,//  | SS_NOTIFY,
		0, 0, 0, 0, hwnd, reinterpret_cast<HMENU>(IDEDIT_PASS), GLOBAL_HINSTANCE, nullptr);
	if(GLOBAL_EDITPASSWORD == nullptr) return;
	// Etykieta
	GLOBAL_LABELPASS = CreateWindowEx(0, TEXT("STATIC"), TEXT("Hasło dla szyfrowania:"),
		WS_CHILD | WS_VISIBLE | SS_NOTIFY, 0, 0, 0, 0,
		hwnd, nullptr, GLOBAL_HINSTANCE, nullptr);
	if(GLOBAL_LABELPASS == nullptr) return;
	// Przycisk pokazywania hasła
	GLOBAL_BUTTON_VIEPASS = CreateWindowEx(0, TEXT("BUTTON"), TEXT("Pokaż hasło"),
		WS_TABSTOP | WS_CHILD | WS_VISIBLE | BS_OWNERDRAW,
		0, 0, 0, 0,
		hwnd, reinterpret_cast<HMENU>(IDBUTTON_VIEWPASS), GLOBAL_HINSTANCE, nullptr);
	SendMessage(GLOBAL_BUTTON_VIEPASS, BM_SETIMAGE, IMAGE_ICON, reinterpret_cast<LPARAM>(GLOBAL_HICON_VIEWPASS));
	// Etykieta ścieżki pliku wejściowego
	GLOBAL_PATH_LABEL_INPUT = CreateWindowEx(0, TEXT("STATIC"), TEXT("Plik wejściowy:"),
		WS_CHILD | WS_VISIBLE | SS_NOTIFY, 0, 0, 0, 0,
		hwnd, nullptr, GLOBAL_HINSTANCE, nullptr);
	if(GLOBAL_PATH_LABEL_INPUT == nullptr) return;
	// Etykieta ścieżki pliku wyjściowego
	GLOBAL_PATH_LABEL_OUTPUT = CreateWindowEx(0, TEXT("STATIC"), TEXT("Plik wyjściowy:"),
		WS_CHILD | WS_VISIBLE | SS_NOTIFY, 0, 0, 0, 0,
		hwnd, nullptr, GLOBAL_HINSTANCE, nullptr);
	if(GLOBAL_PATH_LABEL_OUTPUT == nullptr) return;
	// Pole tekstowe sciezki pliku wejściowego
	GLOBAL_PATH_EDITINPUT = CreateWindowEx(0, TEXT("EDIT"), nullptr, WS_CHILD | WS_VISIBLE | WS_BORDER | SS_NOTIFY,
		0, 0, 0, 0, hwnd, reinterpret_cast<HMENU>(IDEDIT_PATH_INPUT), GLOBAL_HINSTANCE, nullptr);
	if(GLOBAL_PATH_EDITINPUT == nullptr) return;
	// Pole tekstowe sciezki pliku wyjściowego
	GLOBAL_PATH_EDITOUTPUT = CreateWindowEx(0, TEXT("EDIT"), nullptr, WS_CHILD | WS_VISIBLE | WS_BORDER | SS_NOTIFY,
		0, 0, 0, 0, hwnd, reinterpret_cast<HMENU>(IDEDIT_PATH_OUTPUT), GLOBAL_HINSTANCE, nullptr);
	if(GLOBAL_PATH_EDITOUTPUT == nullptr) return;
	// Przycisk radiowy AES 128
	GLOBAL_RGROUP_AES128 = CreateWindowEx(0, TEXT("BUTTON"), TEXT("Standard szyfrowania: AES 128"),
		WS_CHILD | WS_VISIBLE | WS_GROUP | BS_AUTORADIOBUTTON,// | WS_BORDER,
		0, 0, 0, 0, hwnd, nullptr, GLOBAL_HINSTANCE, nullptr);
	if(GLOBAL_RGROUP_AES128 == nullptr) return;
	// Przycisk radiowy AES 256
	GLOBAL_RGROUP_AES256 = CreateWindowEx(0, TEXT("BUTTON"), TEXT("Standard szyfrowania: AES 256"),
		WS_CHILD | WS_VISIBLE | BS_AUTORADIOBUTTON,// | WS_BORDER,
		0, 0, 0, 0, hwnd, nullptr, GLOBAL_HINSTANCE, nullptr);
	if(GLOBAL_RGROUP_AES256 == nullptr) return;
	SendMessage(GLOBAL_RGROUP_AES256, BM_SETCHECK, BST_CHECKED, 0);   // Zaznaczony AES 256
}
//---------------------------------------------------------------------------
void __fastcall AddTrayIcon(HWND hwnd)
/**
	OPIS METOD(FUNKCJI):
	OPIS ARGUMENTÓW:
	OPIS ZMIENNYCH:
	OPIS WYNIKU METODY(FUNKCJI):
*/
{
	TCHAR wlpszText[GLOBAL_CIMAXLONGTEXTHINT];

	SecureZeroMemory(&wlpszText, sizeof(wlpszText));

	GLOBAL_NID.cbSize = sizeof(NOTIFYICONDATA);
	GLOBAL_NID.hWnd = hwnd;
	GLOBAL_NID.uID = 1;
	GLOBAL_NID.uFlags = NIF_ICON | NIF_MESSAGE | NIF_TIP | NIF_INFO;
	GLOBAL_NID.uCallbackMessage = WM_TRAYICON;
	GLOBAL_NID.hIcon = LoadIcon(GLOBAL_HINSTANCE, MAKEINTRESOURCE(ICON_MAIN_ICON));

	StringCbCopy(GLOBAL_NID.szTip, sizeof(GLOBAL_NID.szTip), GLOBAL_STRINGS[STR_TRAYHINT]); // Podpowiedź do traja
	// Powiadomienie
	StringCbCopy(GLOBAL_NID.szInfoTitle, sizeof(GLOBAL_NID.szInfoTitle), GLOBAL_STRINGS[STR_INF0_TITLE]);

	StringCbCopy(GLOBAL_NID.szInfo, sizeof(GLOBAL_NID.szInfo), GLOBAL_STRINGS[STR_INFO_TEXT]);
	GLOBAL_NID.dwInfoFlags = NIIF_INFO;
	GLOBAL_NID.uTimeout = 5000;

	Shell_NotifyIcon(NIM_ADD, &GLOBAL_NID);
}
//---------------------------------------------------------------------------
void __fastcall ShowTrayMenu(HWND hwnd)
/**
	OPIS METOD(FUNKCJI): Tworzenie i otwieranie popupmenu traja
	OPIS ARGUMENTÓW:
	OPIS ZMIENNYCH:
	OPIS WYNIKU METODY(FUNKCJI):
*/
{
	HMENU hMenu=nullptr;

	if(hMenu = CreatePopupMenu())
	{
		// Dodajemy opcję Wyjście.
		InsertMenu(hMenu, -1, MF_BYPOSITION, IDI_TRAY_EXIT, GLOBAL_STRINGS[STR_TRAYMENU_EXIT]);

		// potrzebne do poprawnego wyświetlenia menu
		POINT pt;
		GetCursorPos(&pt);
		SetForegroundWindow(hwnd);
		TrackPopupMenu(hMenu, TPM_BOTTOMALIGN | TPM_LEFTALIGN,
									pt.x, pt.y, 0, hwnd, nullptr);

		DestroyMenu(hMenu); hMenu = nullptr;
	}
}
//---------------------------------------------------------------------------
void __fastcall ReadFileConfig()
/**
	OPIS METOD(FUNKCJI): Odczyt pliku konfiguracyjnego
	OPIS ARGUMENTÓW:
	OPIS ZMIENNYCH:
	OPIS WYNIKU METODY(FUNKCJI):
*/
{
	constexpr int ciSizeTextTypeAES=48;
	TCHAR lpszGetPassword[MAX_PATH], lpszTypeAES[ciSizeTextTypeAES], pszOut[MAX_PATH];

	SecureZeroMemory(&lpszGetPassword, sizeof(lpszGetPassword));
	SecureZeroMemory(&lpszTypeAES, sizeof(lpszTypeAES));
	GetPrivateProfileString(GLOBAL_MAINSECTION, GLOBAL_KEY_PASSWORD, GLOBAL_TEXT_DEFAULT_PASSWORD, lpszGetPassword,
		MAX_PATH, GLOBAL_PATHCONFIG);
	GetPrivateProfileString(GLOBAL_MAINSECTION, GLOBAL_KEY_TYPEAES, GLOBAL_DEFAULT_VALUE_KEY_TYPEAES, lpszTypeAES,
		MAX_PATH, GLOBAL_PATHCONFIG);
	// Deszyfrowanie odczytanego hasła
	bool bReturnDecrypt = GsAES::GsAESDecodeBase64(lpszGetPassword, pszOut, MAX_PATH);

	if(bReturnDecrypt) SetWindowText(GLOBAL_EDITPASSWORD, pszOut); else return;
	if(StrRStrI(lpszTypeAES, nullptr, GLOBAL_VALUE_TYPEAES_128))
	{
		SendMessage(GLOBAL_RGROUP_AES128, BM_SETCHECK, BST_CHECKED, 0);
		SendMessage(GLOBAL_RGROUP_AES256, BM_SETCHECK, BST_UNCHECKED, 0);
		//MessageBox(nullptr, lpszTypeAES, TEXT("Type AES"), MB_ICONINFORMATION);
	}
	else if(StrRStrI(lpszTypeAES, nullptr, GLOBAL_VALUE_TYPEAES_256))
	{
		SendMessage(GLOBAL_RGROUP_AES256, BM_SETCHECK, BST_CHECKED, 0);
		SendMessage(GLOBAL_RGROUP_AES128, BM_SETCHECK, BST_UNCHECKED, 0);
		//MessageBox(nullptr, lpszTypeAES, TEXT("Type AES"), MB_ICONINFORMATION);
	}
}
//---------------------------------------------------------------------------
void __fastcall WriteFileConfig()
/**
	OPIS METOD(FUNKCJI): Zapis do pliku konfiguracyjnego
	OPIS ARGUMENTÓW:
	OPIS ZMIENNYCH:
	OPIS WYNIKU METODY(FUNKCJI):
*/
{
	constexpr int ciSizeTextTypeAES=48;
	TCHAR lpszSetPassword[MAX_PATH], lpszTypeAES[ciSizeTextTypeAES];
	SecureZeroMemory(&lpszSetPassword, sizeof(lpszSetPassword));
	SecureZeroMemory(&lpszTypeAES, sizeof(lpszTypeAES));
	GetWindowText(GLOBAL_EDITPASSWORD, lpszSetPassword, MAX_PATH);
	// Zakodowanie hasła Base64
	TCHAR *pszCryptPass = GsAES::GsAESEncodeBase64(lpszSetPassword);
	if(pszCryptPass)
	{
		WritePrivateProfileString(GLOBAL_MAINSECTION, GLOBAL_KEY_PASSWORD, pszCryptPass, GLOBAL_PATHCONFIG);
		HeapFree(GetProcessHeap(), 0, pszCryptPass); pszCryptPass = nullptr;
	} else return;

	if(SendMessage(GLOBAL_RGROUP_AES128, BM_GETCHECK, 0, 0) == BST_CHECKED)
	{
		StringCchCopy(lpszTypeAES, ciSizeTextTypeAES, TEXT("128"));
	}
	else if(SendMessage(GLOBAL_RGROUP_AES256, BM_GETCHECK, 0, 0) == BST_CHECKED)
	{
		StringCchCopy(lpszTypeAES, ciSizeTextTypeAES, TEXT("256"));
	}
	WritePrivateProfileString(GLOBAL_MAINSECTION, GLOBAL_KEY_TYPEAES, lpszTypeAES, GLOBAL_PATHCONFIG);
}
//---------------------------------------------------------------------------
void __fastcall RunProcess()
/**
	OPIS METOD(FUNKCJI): Wykonywanie mieszania hasła a następnie szyfrowania lub deszyfrowania
	OPIS ARGUMENTÓW:
	OPIS ZMIENNYCH:
	OPIS WYNIKU METODY(FUNKCJI):
*/
{
	TCHAR szGetPassword[MAX_PATH], szInputFilePath[MAX_PATH], szOutputFilePath[MAX_PATH],
		szTextInfos[MAX_PATH];
	enSizeSHABit eSelectHash=enSizeSHABit_256;
	enSizeKey eSizeKey;
	SYSTEMTIME st;

	GetLocalTime(&st);
	SecureZeroMemory(&szGetPassword, sizeof(szGetPassword));
	SecureZeroMemory(&szTextInfos, sizeof(szTextInfos));
	GetWindowText(GLOBAL_EDITPASSWORD, szGetPassword, MAX_PATH);
	GetWindowText(GLOBAL_PATH_EDITINPUT, szInputFilePath, MAX_PATH);
	GetWindowText(GLOBAL_PATH_EDITOUTPUT, szOutputFilePath, MAX_PATH);
	// Selekcja typu szyfrowania
	if(SendMessage(GLOBAL_RGROUP_AES128, BM_GETCHECK, 0, 0) == BST_CHECKED)
	{
		eSelectHash = enSizeSHABit_256;
		eSizeKey = enSizeKey_128;
	}
	else if(SendMessage(GLOBAL_RGROUP_AES256, BM_GETCHECK, 0, 0) == BST_CHECKED)
	{
		eSelectHash = enSizeSHABit_512;
		eSizeKey = enSizeKey_256;
	}
	AESResult HashResult = GsAES::GsAESComputeSHAHash(szGetPassword, eSelectHash);
	auto CleanupRunProc = [&]()
	{
		// zwolnienie pamięci
		if(HashResult.pbData) {HeapFree(GetProcessHeap(), 0, HashResult.pbData); HashResult.pbData = nullptr;}
	};

	if (HashResult.cbDataLength == 0)
	{
		MessageBox(nullptr, TEXT("Błąd funkcji GsAESComputeSHAHash()!"), TEXT("Błąd"), MB_ICONERROR);
		StringCchPrintf(szTextInfos, MAX_PATH, TEXT("Data: %04d-%02d-%02d, Czas: %02d:%02d:%02d - Błąd funkcji tworzącej skrót do hasła!"),
					st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);
		AppendMemoInfos(szTextInfos);
		CleanupRunProc();
		return;
	}
	if(StrRStrI(szInputFilePath, nullptr, GLOBAL_CRYPTEXT))
	// Wyszukanie dodatku do rozszerzenia GLOBAL_CRYPTEXT
	{
		//MessageBox(nullptr, TEXT("Odszyfrowywanie"), TEXT("Typ akcji"), MB_ICONINFORMATION);
		StringCchPrintf(szTextInfos, MAX_PATH, TEXT("Data: %04d-%02d-%02d, Czas: %02d:%02d:%02d - Odszyfrowywuje plik: \"%s\""),
			st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond, szInputFilePath);
		bool bIsSucces = GsAES::GsAESDecryptFile(HashResult, szInputFilePath, szOutputFilePath, eSizeKey);
		if(!bIsSucces)
		{
			MessageBox(nullptr, TEXT("Błąd metody GsAES::GsAESDecryptFile()!"), TEXT("Bląd"), MB_ICONERROR);
			StringCchPrintf(szTextInfos, MAX_PATH, TEXT("Data: %04d-%02d-%02d, Czas: %02d:%02d:%02d - Błąd odszyfrowywania pliku: \"%s\""),
				st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond, szInputFilePath);
		}
	}
	else
	{
		StringCchPrintf(szTextInfos, MAX_PATH, TEXT("Data: %04d-%02d-%02d, Czas: %02d:%02d:%02d - Szyfruje plik: \"%s\""),
			st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond, szInputFilePath);
		bool bIsSucces = GsAES::GsAESCryptFile(HashResult, szInputFilePath, szOutputFilePath, eSizeKey);
		if(!bIsSucces)
		{
			MessageBox(nullptr, TEXT("Błąd metody GsAES::GsAESCryptFile()!"), TEXT("Bląd"), MB_ICONERROR);
			StringCchPrintf(szTextInfos, MAX_PATH, TEXT("Data: %04d-%02d-%02d, Czas: %02d:%02d:%02d - Błąd szyfrowania pliku: \"%s\""),
				st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond, szInputFilePath);
		}
	}
	AppendMemoInfos(szTextInfos);
	CleanupRunProc();
}
//---------------------------------------------------------------------------
bool __fastcall IsExistParamsEdit()
/**
	OPIS METOD(FUNKCJI): Funkcja sprawdza, czy istnieje hasło, ścieżka wejściowa i wyjściowa.
	OPIS ARGUMENTÓW:
	OPIS ZMIENNYCH:
	OPIS WYNIKU METODY(FUNKCJI): true, gdy istnieją wszystkie zawartości.
*/
{
	bool bResult = false;
	TCHAR szPass[MAX_PATH], szInputFilePath[MAX_PATH], szOutputFilePath[MAX_PATH];
	int iLengthPass=0, iLengthInputFilePath=0, iLengthOutputFilePath=0;

	iLengthPass = GetWindowText(GLOBAL_EDITPASSWORD, szPass, MAX_PATH);
	iLengthInputFilePath = GetWindowText(GLOBAL_PATH_EDITINPUT, szInputFilePath, MAX_PATH);
	iLengthOutputFilePath = GetWindowText(GLOBAL_PATH_EDITOUTPUT, szOutputFilePath, MAX_PATH);

	bResult = (iLengthPass > 0) && (iLengthInputFilePath > 0) && (iLengthOutputFilePath > 0);
	return bResult;
}
//---------------------------------------------------------------------------
bool __fastcall SaveHistoryFile()
/**
	OPIS METOD(FUNKCJI): Funkcja zapisująca plik historii.
	OPIS ARGUMENTÓW:
	OPIS ZMIENNYCH:
	OPIS WYNIKU METODY(FUNKCJI): true, gdy istnieją wszystkie zawartości.
*/
{
	int len = 0;
	LPWSTR pBuffer = nullptr;
	HANDLE hFile = INVALID_HANDLE_VALUE;
	DWORD dwWritten=0;
	LPSTR pUtf8 = nullptr;
	TCHAR szPathIniFile[MAX_PATH];

	auto CleanupSHistory = [&]()
	{
		if (hFile != INVALID_HANDLE_VALUE) CloseHandle(hFile);
		if(pBuffer) {HeapFree(GetProcessHeap(), 0, pBuffer); pBuffer = nullptr;}
		if (pUtf8) {HeapFree(GetProcessHeap(), 0, pUtf8); pUtf8 = nullptr;}
	};
	// Tworzenie ścieżki dostępu do pliku ini
	HRESULT hr = PathCchCombine(szPathIniFile, MAX_PATH, GLOBAL_GETEXEDIR, GLOBAL_HISTORY_FILE);
	if(!SUCCEEDED(hr)) return false;
	len = GetWindowTextLength(GLOBAL_HMEMORYTEXTINFOS);
	if (len <= 0) return false;
	// Alokuj bufor (len + 1 na terminator)
	pBuffer = static_cast<LPWSTR>(HeapAlloc(GetProcessHeap(), 0, (len + 1) * sizeof(WCHAR)));
	if (!pBuffer) {CleanupSHistory(); return false;}
	// Pobierz tekst.
	GetWindowText(GLOBAL_HMEMORYTEXTINFOS, pBuffer, len + 1);
	// Oblicz rozmiar UTF-8
	int utf8Size = WideCharToMultiByte(CP_UTF8, 0, pBuffer, -1, nullptr, 0,
		nullptr, nullptr);
	if (utf8Size <= 0) {CleanupSHistory(); return false;}
	// Alokuj bufor UTF-8
	pUtf8 = static_cast<LPSTR>(HeapAlloc(GetProcessHeap(), 0, utf8Size));
	if (!pUtf8) {CleanupSHistory(); return false;}
	// Konwersja do UTF-8
	WideCharToMultiByte(CP_UTF8, 0, pBuffer, -1, pUtf8, utf8Size, nullptr, nullptr);
	// Otwórz plik do zapisu.
	hFile = CreateFile(szPathIniFile, GENERIC_WRITE, 0, nullptr,
		CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
	if (hFile == INVALID_HANDLE_VALUE) {CleanupSHistory(); return false;}
	// Zapisz tekst (UTF-16LE)
	if (!WriteFile(hFile, pUtf8, utf8Size - 1, &dwWritten, nullptr)) {CleanupSHistory(); return false;}

	CleanupSHistory();

	return true;
}
//---------------------------------------------------------------------------
bool __fastcall LoadHistoryFile()
/**
	OPIS METOD(FUNKCJI): Funkcja, która wczytuje plik histori na początku.
	OPIS ARGUMENTÓW:
	OPIS ZMIENNYCH:
	OPIS WYNIKU METODY(FUNKCJI): true, gdy istnieją wszystkie zawartości.
*/
{
	HANDLE hFile=INVALID_HANDLE_VALUE;
	BOOL bResult=FALSE;
	DWORD dwSize=0;
	DWORD dwRead=0;
	LPBYTE pBuffer=nullptr;
	TCHAR szPathIniFile[MAX_PATH];

	auto CleanupLHistory = [&]()
	{
		if(hFile != INVALID_HANDLE_VALUE) CloseHandle(hFile);
		if(pBuffer) {HeapFree(GetProcessHeap(), 0, pBuffer); pBuffer = nullptr;}
	};
	// Tworzenie ścieżki dostępu do pliku ini
	HRESULT hr = PathCchCombine(szPathIniFile, MAX_PATH, GLOBAL_GETEXEDIR, GLOBAL_HISTORY_FILE);
	if(!SUCCEEDED(hr)) return false;
	// Otwórz plik do odczytu.
	hFile = CreateFileW(szPathIniFile,
		GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING,
		FILE_ATTRIBUTE_NORMAL, nullptr);
	if (hFile == INVALID_HANDLE_VALUE) {CleanupLHistory(); return false;}
	// Pobierz długość pliku.
	LARGE_INTEGER liSize;
	if (!GetFileSizeEx(hFile, &liSize)) {CleanupLHistory(); return false;}
	if (liSize.QuadPart > MAXDWORD) {CleanupLHistory(); return false;}// uproszczenie: obsługa plików <= 4 GB
	dwSize = static_cast<DWORD>(liSize.QuadPart);

	// Alokuj bufor
	pBuffer = static_cast<LPBYTE>(HeapAlloc(GetProcessHeap(), 0, dwSize + sizeof(WCHAR)));
	if(!pBuffer) {CleanupLHistory(); return false;}

	// Wczytaj dane.
	if(!ReadFile(hFile, pBuffer, dwSize, &dwRead, nullptr)) {CleanupLHistory(); return false;}
	// Bufor ANSI/UTF-8 -> Unicode
	int wideLen = MultiByteToWideChar(CP_UTF8, 0, reinterpret_cast<LPCSTR>(pBuffer), dwRead, nullptr, 0);
	LPWSTR pWide = static_cast<LPWSTR>(HeapAlloc(GetProcessHeap(), 0, (wideLen + 1) * sizeof(WCHAR)));
	MultiByteToWideChar(CP_UTF8, 0, reinterpret_cast<LPCSTR>(pBuffer), dwRead, pWide, wideLen);
	pWide[wideLen] = L'\0';
	// Ustaw tekst w kontrolce EDIT.
	SetWindowTextW(GLOBAL_HMEMORYTEXTINFOS, pWide);

	CleanupLHistory();
	return true;
}
//---------------------------------------------------------------------------
void __fastcall AppendMemoInfos(LPCWSTR lpszTextAdd)
/**
	OPIS METOD(FUNKCJI): Dodanie nowej lini do histori.
	OPIS ARGUMENTÓW:
	OPIS ZMIENNYCH:
	OPIS WYNIKU METODY(FUNKCJI): true, gdy istnieją wszystkie zawartości.
*/
{
	// Pobierz bieżącą długość tekstu.
	int len = GetWindowTextLength(GLOBAL_HMEMORYTEXTINFOS);
	// Ustaw kursor na końcu.
	SendMessageW(GLOBAL_HMEMORYTEXTINFOS, EM_SETSEL, static_cast<WPARAM>(len), static_cast<LPARAM>(len));
	// Dodaj tekst + nową linię.
	SendMessageW(GLOBAL_HMEMORYTEXTINFOS, EM_REPLACESEL, FALSE, reinterpret_cast<LPARAM>(lpszTextAdd));
	SendMessageW(GLOBAL_HMEMORYTEXTINFOS, EM_REPLACESEL, FALSE, reinterpret_cast<LPARAM>(TEXT("\r\n")));
}
//---------------------------------------------------------------------------