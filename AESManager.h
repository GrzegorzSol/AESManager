// Copyright (c) Grzegorz Sołtysik
// Nazwa projektu: AESManager
// Nazwa pliku: AESManager.h
// Data: 1.01.2026, 06:04

//
// Created by GrzegorzS on 21.10.2025.
//

#ifndef AESMANAGER_AESMANAGER_H
#define AESMANAGER_AESMANAGER_H

#include <windows.h>
// Identyfikatory pozycji napisów tablicy GLOBAL_STRINGS
enum
{
	STR_INF0_TITLE=0, STR_TRAYMENU_EXIT, STR_TRAYHINT, STR_INFO_TEXT,								//0-3
	// Opisy przycisków
	STR_BUTTON_TEXT, 																																//4
	// Tekst opisów w statusbarze
	STR_LONG_OPEN_FILE, STR_LONG_RUN_PROCESS, STR_LONG_SAVECONFIG,									//5-7
	STR_LONG_READCONFIG,																														//8
	STR_LONG_OPEN_DIR, STR_LONG_SAVE_HISTORY, STR_LONG_CLEARHISTORY,								//9-11
	STR_LONG_INFO,																																	//12
	// Teksty w podpowiedziach przycisków
	STR_TITLE_BUTTON_HINT, // Tytuł opisu																						//13
	// Tekst podpowiedzi
	STR_TEXT_HINT_OPEN_FILE, STR_TEXT_HINT_RUN_PROCESS, STR_TEXT_HINT_SAVECONFIG,		//14-16
	STR_TEXT_HINT_READCONFIG,
	STR_TEXT_HINT_OPEN_DIR, STR_TEXT_HINT_SAVE_HISTORY, STR_TEXT_HINT_CLEARHISTORY,	//17-19
	STR_TEXT_HINT_INFO,																															//20
	// Identyfikacje w menu traya
	IDI_TRAY_EXIT = 1000,
	// Identyfikatory ikon w ImageList
	IDIMAGE_OPEN_FILE=0, IDIMAGE_RUN_PROCESS, IDIMAGE_SAVE_CONFIG, IDIMAGE_READCONFIG,
	IDIMAGE_OPEN_DIR, IDIMAGE_SAVE_HISTORY, IDIMAGE_CLEARHISTORY,
	IDIMAGE_INFO,
	// Identyfikator numerów przycisków
	IDBUTTON_OPEN_FILE=1000, IDBUTTON_RUN_PROCESS, IDBUTTON_SAVECOFIG, IDBUTTON_READCONFIG,
	IDBUTTON_OPEN_DIR, IDBUTTON_SAVE_HISTORY, IDBUTTON_CLEARHISTORY,
	IDBUTTON_INFO,

	IDBUTTON_VIEWPASS=100, IDEDIT_PASS, IDEDIT_PATH_INPUT, IDEDIT_PATH_OUTPUT,
	IDBUTTON_PATH_DIR, IDBUTTON_RBUTTON_AESBASIC, IDBUTTON_RBUTTON_AESPROFF,  IDBUTTON_CBOX_TYPEAES
};

extern const TCHAR GLOBAL_CLASS_NAME[], //Nazwa klasy głównego okna
	GLOBAL_TITLE_WINDOW[], // Domyślny tekst na belce głównego okna
	GLOBAL_FONT_NAME[], // Nazwa głównej czcionki
	GLOBAL_CRYPT_EXT[], // Rozszerzenie plików zaszyfrowanych
	
	// ###### Zmienne dla pliku .ini ######
	GLOBAL_PATH_CONFIGFILENAME[], // Ścieżka dostepu do pliku ini
		// Klucze
	GLOBAL_KEY_MAINSECTION[], // Główna sekcja pliku ini
	GLOBAL_KEY_PASSWORD[], // Klucz hasła szyfrowania
	GLOBAL_KEY_TYPEAES[], // Klucz czy AES-128, czy AES-256.
	GLOBAL_KEY_AESTYPE[],	// Klucz wersji uproszczonej, czy profesjonalnej.
	GLOBAL_KEY_AES_PROFF_VERSION[], // Podtyp wersji profesjonalnej AES
	// === WARTOŚCI DLA KLUCZY W PLIKU INI ===
	//Długości klucza dla szyfrowania
	GLOBAL_VALUE_SIZEAES_128[], // 128 bitów -> 16 bajtów
	GLOBAL_VALUE_SIZEAES_256[], // 256 bitów -> 32 bajty

	GLOBAL_VALUE_DEFAULT_PASSWORD[], // Wartość domyślnego hasła szyfrowania
		// Wartości podtypów szyfrowania dla wersji profesjonalnej
	GLOBAL_VALUE_VERSION_AES_CBC_HMAC[],
	GLOBAL_VALUE_VERSION_AES_GCM_TAG[],
		// Możliwe typ szyfrowania AES
	GLOBAL_VALUE_TYPEAES_BASIC[], // Proste szyfrowanie AES
	GLOBAL_VALUE_TYPEAES_PROFF[], // Profesjonalne szyfrowanie AES (Jeszcze są podtypy)
	
	// Nazwa pliku zapisanej histori operacji
	GLOBAL_HISTORY_FILE[];

extern const int ID_START_COUNT,
				GLOBAL_SIZE_FONT,
				GLOBAL_CODEPASS;
// Tablica napisów
extern const TCHAR *GLOBAL_STRINGS[];

#endif //AESMANAGER_AESMANAGER_H