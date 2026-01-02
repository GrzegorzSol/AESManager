// Copyright (c) Grzegorz Sołtysik
// Nazwa projektu: AESManager
// Nazwa pliku: AESManager.cpp
// Data: 1.01.2026, 06:04

//
// Created by GrzegorzS on 13.12.2025.
//
#define UNICODE
#include "AESManager.h"

constexpr TCHAR GLOBAL_CLASS_NAME[] = TEXT("MojeOknoWinAPI"), //Nazwa klasy głównego okna
	GLOBAL_TITLE_WINDOW[] = TEXT("Główne okno - Grzegorz Sołtysik"), // Domyślny tekst na belce głównego okna
	GLOBAL_FONT_NAME[] = TEXT("Segoe UI"), // Nazwa głównej czcionki
	GLOBAL_CRYPT_EXT[] = TEXT(".gscrypt"), // Rozszerzenie plików zaszyfrowanych
	
	// ###### Zmienne dla pliku .ini ######
	GLOBAL_PATH_CONFIGFILENAME[] = TEXT("AESManager.ini"), // Ścieżka dostepu do pliku ini
		// Klucze
	GLOBAL_KEY_MAINSECTION[] = TEXT("MAIN"), // Główna sekcja pliku ini
	GLOBAL_KEY_PASSWORD[] = TEXT("PassDefault"),  // Klucz hasła szyfrowania
	GLOBAL_KEY_TYPEAES[] = TEXT("AESSizeType"), // Klucz, czy AES-128, czy AES-256.
	GLOBAL_KEY_AESTYPE[] = TEXT("AESType"),			// Klucz wersji uproszczonej, czy profesjonalnej.
	GLOBAL_KEY_AES_PROFF_VERSION[] = TEXT("AESProffTypes"), // Podtyp wersji profesjonalnej AES
		// Wartości podtypów szyfrowania dla wersji profesjonalnej
	GLOBAL_VALUE_VERSION_AES_CBC_HMAC[] = TEXT("AES-CBC"), // AES-CBC + HMAC
	GLOBAL_VALUE_VERSION_AES_GCM_TAG[] = TEXT("AES-GCM"), // AES-GCM + TAG
		// Możliwe typy szyfrowania(długości klucza)
	GLOBAL_VALUE_SIZEAES_128[] = TEXT("128"), // 128 bitów -> 16 bajtów
	GLOBAL_VALUE_SIZEAES_256[] = TEXT("256"), // 256 bitów -> 32 bajty

	GLOBAL_VALUE_DEFAULT_PASSWORD[] = TEXT(""), // Wartość domyślnego hasła szyfrowania
	// === WARTOŚCI DLA KLUCZY W PLIKU INI ===
		// Możliwe typ szyfrowania AES
	GLOBAL_VALUE_TYPEAES_BASIC[] = TEXT("AESBasic"), // Proste szyfrowanie AES
	GLOBAL_VALUE_TYPEAES_PROFF[] = TEXT("AESProff"), // Profesjonalne szyfrowanie AES (Jescze są podtypy)
	
	// Nazwa pliku zapisanej histori operacji
	GLOBAL_HISTORY_FILE[] = TEXT("Historia_AES.txt");

const int ID_START_COUNT = IDBUTTON_OPEN_FILE,
				GLOBAL_SIZE_FONT = 11,
				GLOBAL_CODEPASS = 0x25CF;
// Tablica napisów
const TCHAR *GLOBAL_STRINGS[] =
{
	TEXT("Informacja"), TEXT("Wyjście"), TEXT("Ikona"),													//0-2
	TEXT("AESManager - Aplikacja do szyfrowania"), TEXT("Przycisk"),						//3-4
	// Tekst opisów w status barze
	TEXT("Otwarcie pliku lub katalogu do zaszyfrowania, lub odszyfrowania"),		//5
	TEXT("Rozpoczęcie procesu szyfrowania, lub deszyfrowania pliku"),						//6
	TEXT("Zapisanie aktualnej konfiguracji do pliku"),													//7
	TEXT("Odczyt i użycie zapisanej konfiguracji"),															//8
	TEXT("Rozpoczęcie procesu szyfrowania, lub deszyfrowania całego katalogu"),	//9
	TEXT("Zapis historii operacji wykonywanych w aplikacji"),										//10
	TEXT("Kasowanie całej historii operacji"),																	//11
	TEXT("Informacja o aplikacji"),																							//12

	TEXT("Opis przycisku"),																											//13
	// Tekst podpowiedzi
	TEXT("Wybór pliku..."),																											//14
	TEXT("Start operacji..."),																									//15
	TEXT("Zapisanie konfiguracji"),																							//16
	TEXT("Odczyt konfiguracji"),																								//17
	TEXT("Wybór katalogu..."),																									//18
	TEXT("Zapisanie historii"),																									//19
	TEXT("Kasowanie historii"),																									//20
	TEXT("Informacje")																													//21
};