// Copyright (c) Grzegorz Sołtysik
// Nazwa projektu: AESManager
// Nazwa pliku: AESManager.h
// Data: 28.11.2025, 19:40

//
// Created by GrzegorzS on 21.10.2025.
//

#ifndef AESMANAGER_AESMANAGER_H
#define AESMANAGER_AESMANAGER_H

#include <windows.h>
// Identyfikatory pozycji napisów tablicy GLOBAL_STRINGS
enum
{
	STR_INF0_TITLE=0, STR_TRAYMENU_EXIT, STR_TRAYHINT, STR_INFO_TEXT,
	// Opisy przycisków
	STR_BUTTON_TEXT, //4
	// Tekst opisów w statusbarze
	STR_LONG_OPEN_FILE, STR_LONG_PROCESS_FILE, STR_LONG_SAVECONFIG,
	STR_LONG_PROCESS_DIR, STR_LONG_SAVE_HISTORY, STR_LONG_CLEARHISTORY,
	STR_LONG_INFO,
	// Teksty w podpowiedziach przycisków
	STR_TITLE_BUTTON_HINT, // Tytuł opisu
	// Tekst podpowiedzi
	STR_TEXT_HINT_OPEN_FILE, STR_TEXT_HINT_PROCESS_FILE, STR_TEXT_HINT_SAVECONFIG,
	STR_TEXT_HINT_PROCESS_DIR, STR_TEXT_HINT_SAVE_HISTORY, STR_TEXT_HINT_CLEARHISTORY,
	STR_TEXT_HINT_INFO,
	// Identyfikacje w menu traya
	IDI_TRAY_EXIT = 1000,
	// Identyfikatory ikon w ImageList
	IDIMAGE_OPEN_FILE=0, IDIMAGE_PROCESS_FILE, IDIMAGE_SAVE_CONFIG,
	IDIMAGE_PROCESS_DIR, IDIMAGE_SAVE_HISTORY, IDIMAGE_CLEARHISTORY,
	IDIMAGE_INFO,
	// Identyfikator numerów przycisków
	IDBUTTON_OPEN_FILE=1000, IDBUTTON_PROCESS_FILE, IDBUTTON_SAVECOFIG,
	IDBUTTON_PROCESS_DIR, IDBUTTON_SAVE_HISTORY, IDBUTTON_CLEARHISTORY,
	IDBUTTON_INFO,

	IDBUTTON_VIEWPASS=100, IDEDIT_PASS, IDEDIT_PATH_INPUT, IDEDIT_PATH_OUTPUT
};

constexpr TCHAR GLOBAL_CLASS_NAME[] = TEXT("MojeOknoWinAPI"),
	GLOBAL_TITLE_WINDOW[] = TEXT("Główne okno - Grzegorz Sołtysik"),
	GLOBAL_FONT_NAME[] = TEXT("Segoe UI"),
	GLOBAL_CRYPT_EXT[] = TEXT(".gscrypt"),
	// Zmienne dla pliku .ini
	GLOBAL_CONFIGFILENAME[] = TEXT("AESManager.ini"),
	GLOBAL_MAINSECTION[] = TEXT("MAIN"),
	GLOBAL_KEY_PASSWORD[] = TEXT("PassDefault"),
	GLOBAL_TEXT_DEFAULT_PASSWORD[] = TEXT(""),
	GLOBAL_KEY_TYPEAES[] = TEXT("AESType"),
	// Możliwe typy szyfrowania(długości klucza)
	GLOBAL_VALUE_TYPEAES_128[] = TEXT("128"),
	GLOBAL_VALUE_TYPEAES_256[] = TEXT("256"),
	GLOBAL_DEFAULT_VALUE_KEY_TYPEAES[] = TEXT("256"),

	GLOBAL_HISTORY_FILE[] = TEXT("Historia_AES.txt");

constexpr int ID_START_COUNT = IDBUTTON_OPEN_FILE,
				GLOBAL_SIZE_FONT = 11,
				GLOBAL_CODEPASS = 0x25CF;
// Tablica napisów
const TCHAR *GLOBAL_STRINGS[] =
{
	TEXT("Informacja"), TEXT("Wyjście"), TEXT("Ikona"),							//0-2
	TEXT("AESManager - Aplikacja do szyfrowania"), TEXT("Przycisk"),			//3-4
	// Tekst opisów w status barze
	TEXT("Otwarcie pliku lub katalogu do zaszyfrowania, lub odszyfrowania"),	//5
	TEXT("Rozpoczęcie procesu szyfrowania, lub deszyfrowania pliku"),			//6
	TEXT("Zapisanie aktualnej konfiguracji do pliku"),							//7
	TEXT("Rozpoczęcie procesu szyfrowania, lub deszyfrowania całego katalogu"),	//8
	TEXT("Zapis historii operacji wykonywanych w aplikacji"),					//9
	TEXT("Kasowanie całej historii operacji"),									//10
	TEXT("Informacja o aplikacji"),												//11

	TEXT("Opis przycisku"),														//12
	// Tekst podpowiedzi
	TEXT("Otwarcie pliku"),														//13
	TEXT("(De)Szyfrowanie pliku"),												//14
	TEXT("Zapisanie konfiguracji"),												//15
	TEXT("(De)Szyfrowanie katalogu"),											//16
	TEXT("Zapisanie historii"),													//17
	TEXT("Kasowanie historii"),
	TEXT("Informacje")
};

#endif //AESMANAGER_AESMANAGER_H