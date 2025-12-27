// Copyright (c) Grzegorz Sołtysik
// Nazwa projektu: AESManager
// Nazwa pliku: AESManager.cpp
// Data: 26.12.2025, 07:26

//
// Created by GrzegorzS on 13.12.2025.
//
#define UNICODE
#include "AESManager.h"

constexpr TCHAR GLOBAL_CLASS_NAME[] = TEXT("MojeOknoWinAPI"),
	GLOBAL_TITLE_WINDOW[] = TEXT("Główne okno - Grzegorz Sołtysik"),
	GLOBAL_FONT_NAME[] = TEXT("Segoe UI"),
	GLOBAL_CRYPT_EXT[] = TEXT(".gscrypt"),
	// Zmienne dla pliku .ini
	GLOBAL_CONFIGFILENAME[] = TEXT("AESManager.ini"),
	GLOBAL_MAINSECTION[] = TEXT("MAIN"),
	GLOBAL_KEY_PASSWORD[] = TEXT("PassDefault"),
	GLOBAL_TEXT_DEFAULT_PASSWORD[] = TEXT(""),
	GLOBAL_KEY_TYPEAES[] = TEXT("AESSizeType"), // Czy AES-128, czy AES-256.
	GLOBAL_AESTYPE[] = TEXT("AESType"),					// Wersja uproszczona, czy profesjonalna.
	// Możliwe typy szyfrowania(długości klucza)
	GLOBAL_VALUE_SIZEAES_128[] = TEXT("128"),
	GLOBAL_VALUE_SIZEAES_256[] = TEXT("256"),
	// Możliwe typ szyfrowania AES
	GLOBAL_VALUE_TYPEAES_BASIC[] = TEXT("AESBasic"),
	GLOBAL_VALUE_TYPEAES_PROFF[] = TEXT("AESProff"),
	// Nazwa pliku zapisanej histori operacji
	GLOBAL_HISTORY_FILE[] = TEXT("Historia_AES.txt");

const int ID_START_COUNT = IDBUTTON_OPEN_FILE,
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
	TEXT("Wybór pliku..."),														//13
	TEXT("Start..."),												//14
	TEXT("Zapisanie konfiguracji"),												//15
	TEXT("Wybór katalogu..."),											//16
	TEXT("Zapisanie historii"),													//17
	TEXT("Kasowanie historii"),
	TEXT("Informacje")
};