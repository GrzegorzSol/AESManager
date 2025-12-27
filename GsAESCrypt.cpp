// Copyright (c) Grzegorz Sołtysik
// Nazwa projektu: AESManager
// Nazwa pliku: GsAESCrypt.cpp
// Data: 26.12.2025, 07:26

//
// Created by GrzegorzS on 17.10.2025.
//

#define UNICODE
#include "GsAESCrypt.h"
#include <bcrypt.h>
#include <wincrypt.h>
#include <Strsafe.h>

#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)

//---------------------------------------------------------------------------
// Klas:	GsAESContext
// Cel:		Zwalnianie zasobów oraz sprzątanie w klasie GsAESPro.
//				Klasa dotyczy metod: GsAESProCryptFile() i GsAESProDecryptFile().
// Uwagi:
//---------------------------------------------------------------------------
static GsAESHeader Gl_GsAESHeader; // Struktura nagłówka
//=========================== METODY PRYWATNE POMOCNICZE ====================

//---------------------------------------------------------------------------
// Klas:	GsAESBasic
// Cel:		Proste szyfrowanie pliku z KEY i IV, ale bez Salt.
// Uwagi:	Przy niezmienionym haśle nagłówki zakodowanych plików są
//				identyczne.
//---------------------------------------------------------------------------

__fastcall GsStoreData GsAESFunComputeSHAHash(LPCWSTR lpcszText, const enSizeSHABit enTypeHash)
/**
	OPIS METOD(FUNKCJI): Oblicza skrót SHA-256 lub SHA-512 dla tekstu Unicode (LPCWSTR)
	OPIS ARGUMENTÓW: [in] - LPCWSTR pszText-wskaźnik do szerokoznakowego łańcucha wejściowego
					 [in] - enSizeSHABit enTypeHash-typ haszowania, SHA-256 lub SHA-512
	OPIS ZMIENNYCH:
	OPIS WYNIKU METODY(FUNKCJI): Struktura SHAResult zawierająca 32 bajty, lub 64 bajty skrótu.
	UWAGI: Bufor pbData należy zwolnić przez HeapFree(GetProcessHeap(),0,pbData)
*/
{
	GsStoreData gsResult = { nullptr, 0 };
	BYTE* pButf8Data=nullptr;
	BCRYPT_ALG_HANDLE hAlg=nullptr;
	BCRYPT_HASH_HANDLE hHash=nullptr;
	PBYTE pBHashObject=nullptr;
	DWORD DHashObject=0, DData=0, DHash=0;
	NTSTATUS status=1;

	auto CleanupHash = [&]()
	/**
		OPIS METOD(FUNKCJI): Funkcja zwalniająca zarezerwowane zasoby podczas błędu
												 lub zakończenia nadrzędnej funkcji typu lambda
	*/
	{
		if(hHash) {BCryptDestroyHash(hHash); hHash = nullptr;}
		if(pBHashObject) {HeapFree(GetProcessHeap(), 0, pBHashObject); pBHashObject = nullptr;}
		if(hAlg) {BCryptCloseAlgorithmProvider(hAlg, 0); hAlg = nullptr;}
		if(pButf8Data) {HeapFree(GetProcessHeap(), 0, pButf8Data); hAlg = nullptr;}
	};

	if(lpcszText == nullptr)
	{
		MessageBox(nullptr, TEXT("Nie wprowadziłeś hasła!"), TEXT("Błąd"), MB_ICONERROR);
		// Czyszczenie po sobie
		CleanupHash();
		return gsResult;
	}

	// Bezpieczne obliczenie długości
	size_t cchSize = 0;
	HRESULT hr = StringCchLength(lpcszText, STRSAFE_MAX_CCH, &cchSize);
	if(FAILED(hr))
	{
		MessageBox(nullptr, TEXT("Błąd funkcji StringCchLength()!"), TEXT("Błąd"), MB_ICONERROR);
		// Czyszczenie po sobie
		CleanupHash();
		return gsResult;
	}

	// Konwersja do UTF-8
	const int ciUtf8 = WideCharToMultiByte(CP_UTF8, 0, lpcszText, static_cast<int>(cchSize),
									 nullptr, 0, nullptr, nullptr);
	if(ciUtf8 <= 0)
	{
		MessageBox(nullptr, TEXT("Błąd funkcji WideCharToMultiByte()!"), TEXT("Błąd"), MB_ICONERROR);
		// Czyszczenie po sobie
		CleanupHash();
		return gsResult;
	}

	pButf8Data = static_cast<BYTE*>(HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, ciUtf8));
	if(!pButf8Data)
	{
		MessageBox(nullptr, TEXT("Błąd funkcji HeapAlloc()!"), TEXT("Błąd"), MB_ICONERROR);
		// Czyszczenie po sobie
		CleanupHash();
		return gsResult;
	}

	if(WideCharToMultiByte(CP_UTF8, 0, lpcszText, static_cast<int>(cchSize),
		reinterpret_cast<LPSTR>(pButf8Data), ciUtf8, nullptr, nullptr) <= 0)
	{
		MessageBox(nullptr, TEXT("Błąd funkcji WideCharToMultiByte()!"), TEXT("Błąd"), MB_ICONERROR);
		// Czyszczenie po sobie
		CleanupHash();
		return gsResult;
	}

	// Hashowanie SHA-256 lub SHA-512
	if(enTypeHash == enSizeSHABit_256) // SHA-256
		status = BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_SHA256_ALGORITHM, nullptr, 0);
	else if(enTypeHash == enSizeSHABit_512) // SHA-512
		status = BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_SHA512_ALGORITHM, nullptr, 0);
	if(status != 0)
	{
		MessageBox(nullptr, TEXT("Błąd funkcji BCryptOpenAlgorithmProvider()!"), TEXT("Błąd"), MB_ICONERROR);
		// Czyszczenie po sobie
		CleanupHash();
		return gsResult;
	}

	status = BCryptGetProperty(hAlg, BCRYPT_OBJECT_LENGTH,
		reinterpret_cast<PUCHAR>(&DHashObject), sizeof(DHashObject), &DData, 0);
	if(status != 0)
	{
		MessageBox(nullptr, TEXT("Błąd funkcji BCryptGetProperty()!"), TEXT("Błąd"), MB_ICONERROR);
		// Czyszczenie po sobie
		CleanupHash();
		return gsResult;
	}

	status = BCryptGetProperty(hAlg, BCRYPT_HASH_LENGTH,
		reinterpret_cast<PUCHAR>(&DHash), sizeof(DHash), &DData, 0);
	if(status != 0)
	{
		MessageBox(nullptr, TEXT("Błąd funkcji BCryptGetProperty()!"), TEXT("Błąd"), MB_ICONERROR);
		// Czyszczenie po sobie
		CleanupHash();
		return gsResult;
	}

	pBHashObject = static_cast<PBYTE>(HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, DHashObject));
	if(!pBHashObject)
	{
		MessageBox(nullptr, TEXT("Błąd funkcji HeapAlloc()!"), TEXT("Błąd"), MB_ICONERROR);
		// Czyszczenie po sobie
		CleanupHash();
		return gsResult;
	}

	status = BCryptCreateHash(hAlg, &hHash, pBHashObject, DHashObject, nullptr, 0, 0);
	if(status != 0)
	{
		MessageBox(nullptr, TEXT("Błąd funkcji BCryptCreateHash()!"), TEXT("Błąd"), MB_ICONERROR);
		// Czyszczenie po sobie
		CleanupHash();
		return gsResult;
	}

	if(ciUtf8 > 0)
	{
		status = BCryptHashData(hHash, pButf8Data, ciUtf8, 0);
		if(status != 0)
		{
			MessageBox(nullptr, TEXT("Błąd funkcji BCryptHashData()!"), TEXT("Błąd"), MB_ICONERROR);
			// Czyszczenie po sobie
			CleanupHash();
			return gsResult;
		}
	}

	gsResult.pBData = static_cast<BYTE*>(HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, DHash));
	if(!gsResult.pBData)
	{
		MessageBox(nullptr, TEXT("Błąd funkcji HeapAlloc()!"), TEXT("Błąd"), MB_ICONERROR);
		// Czyszczenie po sobie
		CleanupHash();
		return gsResult;
	}

	gsResult.DDataLen = DHash;
	status = BCryptFinishHash(hHash, gsResult.pBData, DHash, 0);
	if(status != 0)
	{
		MessageBox(nullptr, TEXT("Błąd funkcji BCryptFinishHash()!"), TEXT("Błąd"), MB_ICONERROR);
		// Czyszczenie po sobie
		CleanupHash();
		gsResult.DDataLen = 0;
		return gsResult;
	}

	CleanupHash();

	return gsResult;
}
//---------------------------------------------------------------------------
__fastcall bool GsAESBasic::_GsAESBasicGenerateKeyAndIV_128(const GsStoreData &gsHash, GsStoreData &gsKey, GsStoreData &gsIV)
/**
	OPIS METOD(FUNKCJI): Funkcja do generowania klucza AES-128 i IV z hasła
	OPIS ARGUMENTÓW: [in] - const SHAResult &Hash - wygenerowany hash z hasła w funkcji ComputeSHAHash().
					 [out] - SHAResult &Key - Klucz do wygenerowania.
					 [out] - SHAResult &IV - IV do wygenerowania.
	OPIS ZMIENNYCH:
	OPIS WYNIKU METODY(FUNKCJI): Struktura SHAResult zawierająca 32 bajty, lub 64 bajty skrótu
	UWAGI: Bufor pbData dla Key i IV należy zwolnić przez HeapFree(GetProcessHeap(),0,pbData)
*/
{
	bool bResult = false;
	// Podział Hash na Key i IV.
	gsKey.DDataLen = 16;
	gsKey.pBData = static_cast<BYTE*>(HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, gsKey.DDataLen));
	gsIV.DDataLen = 16;
	gsIV.pBData = static_cast<BYTE*>(HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, gsIV.DDataLen));

	if(gsKey.pBData && gsIV.pBData)
	{
		if(gsHash.DDataLen < (gsKey.DDataLen + gsIV.DDataLen)) return false; // AI [23-12-2025]
		bResult = true;
		memcpy(gsKey.pBData, gsHash.pBData, gsKey.DDataLen);
		memcpy(gsIV.pBData, gsHash.pBData + gsKey.DDataLen, gsKey.DDataLen);
	}

	return bResult;
}
//---------------------------------------------------------------------------
__fastcall bool GsAESBasic::_GsAESBasicGenerateKeyAndIV_256(const GsStoreData &gsHash, GsStoreData &gsKey, GsStoreData &gsIV)
/**
	OPIS METOD(FUNKCJI): Funkcja do generowania klucza AES-128 i IV z hasła
	OPIS ARGUMENTÓW: [in] - const SHAResult &Hash - wygenerowany hash z hasła w funkcji ComputeSHAHash().
					 [out] - SHAResult &Key - Klucz do wygenerowania.
					 [out] - SHAResult &IV - IV do wygenerowania.
	OPIS ZMIENNYCH:
	OPIS WYNIKU METODY(FUNKCJI): Struktura SHAResult zawierająca 32 bajty, lub 64 bajty skrótu
	UWAGI: Bufor pbData dla Key i IV należy zwolnić przez HeapFree(GetProcessHeap(),0,pbData)
*/
{
	bool bResult = false;
	// Podział Hash na Key i IV.
	gsKey.DDataLen = 32;
	gsKey.pBData = static_cast<BYTE*>(HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, gsKey.DDataLen));
	gsIV.DDataLen = 16;
	gsIV.pBData = static_cast<BYTE*>(HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, gsIV.DDataLen));

	if(gsKey.pBData && gsIV.pBData)
	{
		if(gsHash.DDataLen < (gsKey.DDataLen + gsIV.DDataLen)) return false; // AI [23-12-2025]
		bResult = true;
		memcpy(gsKey.pBData, gsHash.pBData, gsKey.DDataLen);
		memcpy(gsIV.pBData, gsHash.pBData + gsKey.DDataLen, gsIV.DDataLen);
		//CopyMemory(Key.pbData, Hash.pbData, Key.cbDataLength);
		//CopyMemory(IV.pbData, Hash.pbData + Key.cbDataLength, Key.cbDataLength);
	}
	return bResult;
}
//---------------------------------------------------------------------------
__fastcall bool GsAESBasic::GsAESBasicCryptFile(const GsStoreData &gsHash, LPCWSTR lpcszFileInput, LPCWSTR lpcszFileOutput, const enSizeKey enAESKey)
/**
	OPIS METOD(FUNKCJI): Właściwe szyfrowanie lub odszyfrowywania.
	OPIS ARGUMENTÓW: [in] - const SHAResult &Hash - Wygenerowany wcześnie hash z hasła w funkcji ComputeSHAHash().
					 [in] - LPCWSTR lpszFileInput-ścieżka dostępu do pliku wejściowego.
					 [in] - LPCWSTR lpszFileOutput-ścieżka dostępu do pliku wyjściowego.
					 [in] - enSizeKey enAESKey-Typ (De)Szyfrowania AES, enSizeKey_128 - 128-bitowe,
							enSizeKey_256 - 256-bitowe.
	OPIS ZMIENNYCH:
*/
{
	// Szyfrowanie za pomocą BCrypt
	BCRYPT_ALG_HANDLE hAlg = nullptr;
	BCRYPT_KEY_HANDLE hKey = nullptr;
	NTSTATUS status=1;
	ULONG ULDataLength=0, ULComputeLength=0;
	GsAESHeader MyAESHeader;

	// Walidacja argumentów
	if (!gsHash.pBData || gsHash.DDataLen == 0 || !lpcszFileInput || !lpcszFileOutput) return false;
	MyAESHeader.Version = CPB_VERSIONCRYPTBASIC;

	bool bResult = false;
	GsStoreData gsKEY = { nullptr, 0 },
				gsIV = {nullptr, 0},
				gsPlainText = { nullptr, 0 },
				gsCipherText = { nullptr, 0 },
				gsFullData = { nullptr, 0 },
				gsCopyIV = { nullptr, 0 };

	auto CleanupCrypt = [&]()
	/**
		OPIS METOD(FUNKCJI): Funkcja zwalniająca zarezerwowane zasoby podczas błędu
												 lub zakończenia nadrzędnej funkcji typu lambda
	*/
	{
		// Sprzatanie po BCrypt
		if(hKey) {BCryptDestroyKey(hKey); hKey = nullptr;}
		if(hAlg) {BCryptCloseAlgorithmProvider(hAlg, 0); hAlg = nullptr;}
	};
	// Długość klucza
	switch(enAESKey)
	{
		case enSizeKey_128:
			bResult = GsAESBasic::_GsAESBasicGenerateKeyAndIV_128(gsHash, gsKEY, gsIV);
		break;
		//---
		case enSizeKey_256:
			bResult = GsAESBasic::_GsAESBasicGenerateKeyAndIV_256(gsHash, gsKEY, gsIV);
		break;
		//---
		default: bResult = false;
	}

	if(bResult)
	{
		// Wczytanie danych wejściowych
		if(!GsReadDataFromFile(lpcszFileInput, &gsPlainText))
		{
			MessageBox(nullptr, TEXT("Błąd odczytu pliku wejściowego!"), TEXT("Błąd"), MB_ICONERROR);
			// Czyszczenie po sobie
			CleanupCrypt();
			return false;
		}

		// Skopiowanie IV, przed jego napisaniem w funkcji BCryptEncrypt()
		gsCopyIV.DDataLen = gsIV.DDataLen;
		gsCopyIV.pBData = static_cast<BYTE*>(HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, gsCopyIV.DDataLen));
		if(!gsCopyIV.pBData)
		{
			MessageBox(nullptr, TEXT("Błąd alokacji pamięci!"), TEXT("Błąd"), MB_ICONERROR);
			// Czyszczenie po sobie
			CleanupCrypt();
			return false;
		}
		memcpy(gsCopyIV.pBData, gsIV.pBData, gsIV.DDataLen); // Wykonanie kopii IV.

		// Otwórz algorytm AES.
		status = BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_AES_ALGORITHM, nullptr, 0);
		if(!BCRYPT_SUCCESS(status))
		{
			MessageBox(nullptr, TEXT("Błąd funkcji BCryptOpenAlgorithmProvider()!"), TEXT("Błąd"), MB_ICONERROR);
			// Czyszczenie po sobie
			CleanupCrypt();
			return false;
		}

		// Ustaw tryb na CBC
		status = BCryptSetProperty(hAlg, BCRYPT_CHAINING_MODE, (PUCHAR)BCRYPT_CHAIN_MODE_CBC, sizeof(BCRYPT_CHAIN_MODE_CBC), 0);
		if(!BCRYPT_SUCCESS(status))
		{
			MessageBox(nullptr, TEXT("Błąd funkcji BCryptSetProperty()!"), TEXT("Błąd"), MB_ICONERROR);
			// Czyszczenie po sobie
			CleanupCrypt();
			return false;
		}

		// Utwórz klucz
		status = BCryptGenerateSymmetricKey(hAlg, &hKey, nullptr, 0, (PUCHAR)gsKEY.pBData, gsKEY.DDataLen, 0);
		if(!BCRYPT_SUCCESS(status))
		{
			MessageBox(nullptr, TEXT("Błąd funkcji BCryptGenerateSymmetricKey()!"), TEXT("Błąd"), MB_ICONERROR);
			// Czyszczenie po sobie
			CleanupCrypt();
			return false;
		}

		// Wywołanie wstępne — poznaj rozmiar bufora -> ulWyliczone
		status = BCryptEncrypt(hKey, gsPlainText.pBData, gsPlainText.DDataLen, nullptr, gsIV.pBData, gsIV.DDataLen, nullptr,
			0, &ULComputeLength, BCRYPT_BLOCK_PADDING);
		if(!BCRYPT_SUCCESS(status))
		{
			MessageBox(nullptr, TEXT("Błąd funkcji BCryptEncrypt()!"), TEXT("Błąd"), MB_ICONERROR);
			// Czyszczenie po sobie
			CleanupCrypt();
			return false;
		}

		// Przygotowanie bufora na zaszyfrowane dane.
		gsCipherText.DDataLen = ULComputeLength;
		gsCipherText.pBData = static_cast<BYTE*>(HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, gsCipherText.DDataLen));
		if(!gsCipherText.pBData)
		{
			MessageBox(nullptr, TEXT("Błąd alokacji pamięci!"), TEXT("Błąd"), MB_ICONERROR);
			// Czyszczenie po sobie
			CleanupCrypt();
			return false;
		}

		// Szyfrowanie danych
		status = BCryptEncrypt(hKey, gsPlainText.pBData, gsPlainText.DDataLen, nullptr, gsIV.pBData, gsIV.DDataLen, gsCipherText.pBData,
			gsCipherText.DDataLen, &ULDataLength, BCRYPT_BLOCK_PADDING);
		// Funkcja nadpisuje IV.pbData ostatnim blokiem CipherText.pbData!!!
		if(!BCRYPT_SUCCESS(status))
		{
			MessageBox(nullptr, TEXT("Błąd funkcji BCryptEncrypt()!"), TEXT("Błąd"), MB_ICONERROR);
			// Czyszczenie po sobie
			CleanupCrypt();
			return false;
		}

		// Skompletowanie i połączenie wszystkich danych do zapisu // [15-12-2025]
		gsFullData.DDataLen = gsCopyIV.DDataLen + ULDataLength + sizeof(GsAESHeader);
		gsFullData.pBData = static_cast<BYTE*>(HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, gsFullData.DDataLen));
		if(!gsFullData.pBData)
		{
			MessageBox(nullptr, TEXT("Błąd alokacji pamięci!"), TEXT("Błąd"), MB_ICONERROR);
			// Czyszczenie po sobie
			CleanupCrypt();
			return false;
		}
		memcpy(gsFullData.pBData, &MyAESHeader, sizeof(GsAESHeader));
		memcpy(gsFullData.pBData + sizeof(GsAESHeader), gsCopyIV.pBData, gsCopyIV.DDataLen);
		memcpy(gsFullData.pBData + gsCopyIV.DDataLen + sizeof(GsAESHeader), gsCipherText.pBData, gsCipherText.DDataLen);
		if(!GsWriteDataToFile(lpcszFileOutput, gsFullData.pBData, gsFullData.DDataLen))
		{
			MessageBox(nullptr, TEXT("Błąd zapisu zaszyfrowanych danych!"), TEXT("Błąd"), MB_ICONERROR);
			// Czyszczenie po sobie
			CleanupCrypt();
			return false;
		}
	}
	// Czyszczenie po sobie
	CleanupCrypt();
	return bResult;
}
//---------------------------------------------------------------------------
__fastcall bool GsAESBasic::GsAESBasicDecryptFile(const GsStoreData &gsHash, LPCWSTR lpcszFileInput, LPCWSTR lpcszFileOutput, const enSizeKey enAESKey)
/**
	OPIS METOD(FUNKCJI): Właściwe szyfrowanie lub odszyfrowywania.
	OPIS ARGUMENTÓW: [in] - const SHAResult &Hash - Wygenerowany wcześnie hash z hasła w funkcji ComputeSHAHash().
					 [in] - LPCWSTR lpszFileInput-ścieżka dostępu do pliku wejściowego.
					 [in] - LPCWSTR lpszFileOutput-ścieżka dostępu do pliku wyjściowego.
					 [in] - enSizeKey enAESKey-Typ (De)Szyfrowania AES, enSizeKey_128 - 128-bitowe,
							enSizeKey_256 - 256-bitowe.
	OPIS ZMIENNYCH:
*/
{
	// Odszyfrowywanie za pomocą BCrypt
	BCRYPT_ALG_HANDLE hAlg = nullptr;
	BCRYPT_KEY_HANDLE hKey = nullptr;
	NTSTATUS status=1;
	HANDLE hFileInput = INVALID_HANDLE_VALUE,
			 hFileOutput = INVALID_HANDLE_VALUE;
	LARGE_INTEGER LIsizeFileInput;
	DWORD DRead=0, dwWritten=0;
	bool bResult = false;
	GsStoreData gsKEY = { nullptr, 0 },
				gsIV = {nullptr, 0},
				gsPlainText = { nullptr, 0 },
				gsFileIV = { nullptr, 0 },
				gsEncryptedText = { nullptr, 0 };
	GsAESHeader MyAESHeader;

	// Walidacja argumentów
	if (!gsHash.pBData || gsHash.DDataLen == 0 || !lpcszFileInput || !lpcszFileOutput) return false;
	auto CleanupDecrypt = [&]()
	{
		if(hFileInput != INVALID_HANDLE_VALUE) {CloseHandle(hFileInput); hFileInput = INVALID_HANDLE_VALUE;}
		if(hFileOutput != INVALID_HANDLE_VALUE) {CloseHandle(hFileOutput); hFileOutput = INVALID_HANDLE_VALUE;}
		// Sprzatanie po BCrypt
		if(hKey) {BCryptDestroyKey(hKey); hKey = nullptr;}
		if(hAlg) {BCryptCloseAlgorithmProvider(hAlg, 0); hAlg = nullptr;}

		//MessageBox(nullptr, TEXT("Wywołanie funkcji Cleanup()!"), TEXT("Cleanup()"), MB_ICONINFORMATION);
	};
	// Długość klucza
	switch(enAESKey)
	{
		case enSizeKey_128:
			bResult = GsAESBasic::_GsAESBasicGenerateKeyAndIV_128(gsHash, gsKEY, gsIV);
		break;
		//---
		case enSizeKey_256:
			bResult = GsAESBasic::_GsAESBasicGenerateKeyAndIV_256(gsHash, gsKEY, gsIV);
		break;
		//---
		default: bResult = false;
	}

	if(bResult)
	{
		// Wczytanie danych wejściowych
		hFileInput = CreateFile(lpcszFileInput, GENERIC_READ, FILE_SHARE_READ, nullptr,
			OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
		if(hFileInput == INVALID_HANDLE_VALUE)
		{
			MessageBox(nullptr, TEXT("Błąd otwarcia pliku wejściowego!"), TEXT("Błąd"), MB_ICONERROR);
			// Czyszczenie po sobie
			CleanupDecrypt();
			return false;
		}
		if(!GetFileSizeEx(hFileInput, &LIsizeFileInput))
		{
			MessageBox(nullptr, TEXT("Błąd odczytu wielkości pliku wejściowego!"), TEXT("Błąd"), MB_ICONERROR);
			// Czyszczenie po sobie
			CleanupDecrypt();
			return false;
		}
		// Odczytanie nagłówka
		if(!ReadFile(hFileInput, &MyAESHeader, sizeof(GsAESHeader), &DRead, nullptr))
		{
			MessageBox(nullptr, TEXT("Błąd odczytu pliku wejściowego!"), TEXT("Błąd"), MB_ICONERROR);
			// Czyszczenie po sobie
			CleanupDecrypt();
			return false;
		}
		if(DRead != sizeof(GsAESHeader))
		{
			MessageBox(nullptr, TEXT("Błąd odczytu pliku wejściowego!"), TEXT("Błąd"), MB_ICONERROR);
			// Czyszczenie po sobie
			CleanupDecrypt();
			return false;
		}
		// Porównanie odczytanego nagłówka ze wzorem.
		if(memcmp(Gl_GsAESHeader.Magic, MyAESHeader.Magic, sizeof(Gl_GsAESHeader.Magic)) != 0)
		{
			MessageBox(nullptr, TEXT("Plik ten nie został zaszyfrowany w tej aplikacji!"), TEXT("Błąd"), MB_ICONERROR);
			// Czyszczenie po sobie
			CleanupDecrypt();
			return false;
		}

		// Odczytanie IV z początku pliku, po nagłówku
		gsFileIV.DDataLen = 16; // Długość IV dla AES
		gsFileIV.pBData = static_cast<BYTE*>(HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, gsFileIV.DDataLen));
		if(!gsFileIV.pBData)
		{
			MessageBox(nullptr, TEXT("Błąd alokacji pamięci!"), TEXT("Błąd"), MB_ICONERROR);
			// Czyszczenie po sobie
			CleanupDecrypt();
			return false;
		}
		if(!ReadFile(hFileInput, gsFileIV.pBData, gsFileIV.DDataLen, &DRead, nullptr))
		{
			MessageBox(nullptr, TEXT("Błąd odczytu pliku wejściowego!"), TEXT("Błąd"), MB_ICONERROR);
			// Czyszczenie po sobie
			CleanupDecrypt();
			return false;
		}
		if(DRead != gsFileIV.DDataLen)
		{
			MessageBox(nullptr, TEXT("Błąd odczytu pliku wejściowego!"), TEXT("Błąd"), MB_ICONERROR);
			// Czyszczenie po sobie
			CleanupDecrypt();
			return false;
		}
		// Porównanie IV z oczekiwanym
		if(memcmp(gsFileIV.pBData, gsIV.pBData, gsIV.DDataLen) != 0)
		{
			MessageBox(nullptr, TEXT("Nieprawidłowy klucz lub IV!"), TEXT("Błąd"), MB_ICONERROR);
			// Czyszczenie po sobie
			CleanupDecrypt();
			return false;
		}
		// Wczytanie zaszyfrowanych danych
		LARGE_INTEGER pos;
		SetFilePointerEx(hFileInput, {0}, &pos, FILE_CURRENT);
		gsEncryptedText.DDataLen = LIsizeFileInput.QuadPart - pos.QuadPart;
		gsEncryptedText.pBData = static_cast<BYTE*>(HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, gsEncryptedText.DDataLen));

		if(!ReadFile(hFileInput, gsEncryptedText.pBData, gsEncryptedText.DDataLen, &DRead, nullptr))
		{
			MessageBox(nullptr, TEXT("Błąd odczytu pliku wejściowego!"), TEXT("Błąd"), MB_ICONERROR);
			// Czyszczenie po sobie
			CleanupDecrypt();
			return false;
		}
		if(DRead != gsEncryptedText.DDataLen)
		{
			MessageBox(nullptr, TEXT("Błąd odczytu pliku wejściowego!"), TEXT("Błąd"), MB_ICONERROR);
			// Czyszczenie po sobie
			CleanupDecrypt();
			return false;
		}

		// Otwórz algorytm AES.
		status = BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_AES_ALGORITHM, nullptr, 0);
		if(!BCRYPT_SUCCESS(status))
		{
			MessageBox(nullptr, TEXT("Błąd funkcji BCryptOpenAlgorithmProvider()!"), TEXT("Błąd"), MB_ICONERROR);
			// Czyszczenie po sobie
			CleanupDecrypt();
			return false;
		}
		// Ustaw tryb na CBC.
		status = BCryptSetProperty(hAlg, BCRYPT_CHAINING_MODE, (PUCHAR)BCRYPT_CHAIN_MODE_CBC, sizeof(BCRYPT_CHAIN_MODE_CBC), 0);
		if(!BCRYPT_SUCCESS(status))
		{
			MessageBox(nullptr, TEXT("Błąd funkcji BCryptSetProperty()!"), TEXT("Błąd"), MB_ICONERROR);
			// Czyszczenie po sobie
			CleanupDecrypt();
			return false;
		}
		// Utwórz klucz.
		status = BCryptGenerateSymmetricKey(hAlg, &hKey, nullptr, 0, (PUCHAR)gsKEY.pBData, gsKEY.DDataLen, 0);
		if(!BCRYPT_SUCCESS(status))
		{
			MessageBox(nullptr, TEXT("Błąd funkcji BCryptGenerateSymmetricKey()!"), TEXT("Błąd"), MB_ICONERROR);
			// Czyszczenie po sobie
			CleanupDecrypt();
			return false;
		}
		// Przygotowanie bufora na odszyfrowane dane
		constexpr ULONG cULBlockSize = 16; // Rozmiar bloku AES
		const ULONG cULPlainTextSize = ((gsEncryptedText.DDataLen + cULBlockSize - 1) / cULBlockSize) * cULBlockSize; // Rozmiar bufora dla danych odszyfrowanych
		gsPlainText.DDataLen = cULPlainTextSize;
		gsPlainText.pBData = static_cast<BYTE*>(HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, gsPlainText.DDataLen));
		if(!gsPlainText.pBData)
		{
			MessageBox(nullptr, TEXT("Błąd alokacji pamięci!"), TEXT("Błąd"), MB_ICONERROR);
			// Czyszczenie po sobie
			CleanupDecrypt();
			return false;
		}
		ULONG ULDataLength = 0;
		// Deszyfrowanie danych
		status = BCryptDecrypt(hKey, gsEncryptedText.pBData, gsEncryptedText.DDataLen, nullptr, gsIV.pBData, gsIV.DDataLen,
				gsPlainText.pBData, gsPlainText.DDataLen, &ULDataLength, BCRYPT_BLOCK_PADDING);
		if(!BCRYPT_SUCCESS(status))
		{
			MessageBox(nullptr, TEXT("Błąd funkcji BCryptDecrypt()!"), TEXT("Błąd"), MB_ICONERROR);
			// Czyszczenie po sobie
			CleanupDecrypt();
			return false;
		}
		// Stworzenie pliku wyjściowego
		if(!GsWriteDataToFile(lpcszFileOutput, gsPlainText.pBData, ULDataLength))
		{
			MessageBox(nullptr, TEXT("Błąd zapisu zaszyfrowanych danych!"), TEXT("Błąd"), MB_ICONERROR);
			// Czyszczenie po sobie
			CleanupDecrypt();
			return false;
		}
	}

	// Czyszczenie po sobie
	CleanupDecrypt();
	return bResult;
}
//---------------------------------------------------------------------------

//---------------------------------------------------------------------------
// Klas:	GsAESPro
// Cel:		Szyfrowanie pliku z KEY, IV i Salt.
// Uwagi:	Każdy nagłówek zaszyfrowanego pliku jest inny.
//---------------------------------------------------------------------------

__fastcall bool GsAESPro::GsAESProCryptFile(const GsStoreData &gsHash, LPCWSTR lpcszFileInput, LPCWSTR lpcszFileOutput, const enSizeKey enAESKey)
/**
	OPIS METOD(FUNKCJI): Funkcja do generowania klucza AES-128 i IV z hasła
	OPIS ARGUMENTÓW: [in] - const SHAResult &Hash - Wygenerowany hash z hasła w funkcji ComputeSHAHash().
													LPCWSTR lpszFileInput-Ścieżka dostępu do pliku, który będzie zaszyfrowany
													LPCWSTR lpszFileOutput-Ścieżka dostępu do zaszyfrowanego pliku
	OPIS ZMIENNYCH:
	OPIS WYNIKU METODY(FUNKCJI): Struktura SHAResult zawierająca 32 bajty, lub 64 bajty skrótu
	UWAGI:
*/
{
	bool bResult=false;
	NTSTATUS status=1;
	GsStoreData gsPlain={nullptr, 0};
	BCRYPT_ALG_HANDLE hKdf=nullptr;
	BCRYPT_ALG_HANDLE hAes=nullptr;
	BCRYPT_KEY_HANDLE hKey=nullptr;
	BYTE *pBOutput=nullptr, *pBFinal=nullptr;
	GsAESHeader MyAESHeader;

	// Walidacja argumentów
	if (!gsHash.pBData || gsHash.DDataLen == 0 || !lpcszFileInput || !lpcszFileOutput) return false;
	// Wersja w nagłówku
	MyAESHeader.Version = CPB_VERSIONCRYPTPROFF;

	// Wybór algorytmu PRF
	const DWORD cDKeyLen	 = (enAESKey == enSizeKey_128) ? CI_KEYLEN_128 : CI_KEYLEN_256;
	const DWORD cDDerivedLen	 = cDKeyLen + CI_SIZEIV; // Key + IV
	BYTE *pBderived = static_cast<BYTE*>(HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, cDDerivedLen));
	if(!pBderived) return false;
	const LPCWSTR lpcszAlg = (enAESKey == enSizeKey_128) ? BCRYPT_SHA256_ALGORITHM : BCRYPT_SHA512_ALGORITHM;
	// StringCchPrintf(Gl_szInfoDebug, glMaxIfoDebug, TEXT("PRF: %s, Długość hasha: %d"), prfAlg, Hash.cbDataLength);
	// MessageBox(nullptr, Gl_szInfoDebug, TEXT("Informacja"), MB_ICONINFORMATION);

	auto CleanupCryptPro = [&]()
	/**
		OPIS METOD(FUNKCJI): Funkcja zwalniająca zarezerwowane zasoby podczas błędu
												 lub zakończenia nadrzędnej funkcji typu lambda
	*/
	{
		if(hKey) {BCryptDestroyKey(hKey); hKey = nullptr;}
		//if(gsPlain.pbData) {HeapFree(GetProcessHeap(), 0, gsPlain.pbData); gsPlain.pbData = nullptr;}
		if(hKdf) {BCryptCloseAlgorithmProvider(hKdf, 0); hKdf = nullptr;}
		if(hAes) {BCryptCloseAlgorithmProvider(hAes, 0); hAes = nullptr;}
		if(pBOutput) {HeapFree(GetProcessHeap(), 0, pBOutput); pBOutput = nullptr;}
		if(pBderived)
		{
			SecureZeroMemory(pBderived, sizeof(cDDerivedLen));
			HeapFree(GetProcessHeap(), 0, pBderived); pBderived = nullptr;
		}
		if(pBFinal) {HeapFree(GetProcessHeap(), 0, pBFinal); pBFinal = nullptr;}
	};

	// Opcjonalna walidacja długości ścieżek (bez używania A/W sufiksów)
	size_t cchInSize=0, cchOutSize=0;
	if(FAILED(StringCchLength(lpcszFileInput, MAX_PATH, &cchInSize))) return false;
	if(FAILED(StringCchLength(lpcszFileOutput, MAX_PATH, &cchOutSize))) return false;

	// 1) Wczytaj cały plik źródłowy do pamięci.
	if(!GsReadDataFromFile(lpcszFileInput, &gsPlain))
	{
		MessageBox(nullptr, TEXT("Błąd funkcji GsReadDataFromFile!"), TEXT("Błąd"), MB_ICONERROR);
		CleanupCryptPro(); return false;
	}

	// 2) Przygotuj Salt (16 bajtów) zapisany razem z plikiem.
	BYTE BSalt[CI_SIZESALT] = {};
	if(BCryptGenRandom(nullptr, BSalt, sizeof(BSalt), BCRYPT_USE_SYSTEM_PREFERRED_RNG) != 0)
	{
		MessageBox(nullptr, TEXT("Błąd funkcji BCryptGenRandom!"), TEXT("Błąd"), MB_ICONERROR);
		CleanupCryptPro(); return false;
	}

	// 3) PBKDF2: Hash + Salt + Iteracje → Derived (Key 32B + IV 16B)
	status = BCryptOpenAlgorithmProvider(&hKdf, lpcszAlg, MS_PRIMITIVE_PROVIDER, BCRYPT_ALG_HANDLE_HMAC_FLAG);
	if(!BCRYPT_SUCCESS(status))
	{
		MessageBox(nullptr, TEXT("Błąd funkcji BCryptOpenAlgorithmProvider!"), TEXT("Błąd"), MB_ICONERROR);
		CleanupCryptPro(); return false;
	}

	status = BCryptDeriveKeyPBKDF2(hKdf, (PUCHAR)gsHash.pBData, (ULONG)gsHash.DDataLen, (PUCHAR)BSalt,
		(ULONG)sizeof(BSalt), CUL_ITERATIONS, (PUCHAR)pBderived, (ULONG)cDDerivedLen, 0);
	BCryptCloseAlgorithmProvider(hKdf, 0); hKdf = nullptr;
	if(!BCRYPT_SUCCESS(status))
	{
		TCHAR szError[MAX_PATH];
		StringCchPrintf(szError, MAX_PATH, TEXT("Błąd funkcji BCryptDeriveKeyPBKDF2! Nr: 0x%X. Długość hasha: %d"), status, gsHash.DDataLen);
		MessageBox(nullptr, szError, TEXT("Błąd"), MB_ICONERROR);
		CleanupCryptPro(); return false;
	}

	BYTE *pBKey = pBderived;				 // 16B lub 32B
	BYTE *pBIV	 = pBderived + cDKeyLen;	 // 16B

	// 4) Przygotuj AES-256 CBC.
	status = BCryptOpenAlgorithmProvider(&hAes, BCRYPT_AES_ALGORITHM, MS_PRIMITIVE_PROVIDER, 0);
	if(!BCRYPT_SUCCESS(status))
	{
		MessageBox(nullptr, TEXT("Błąd funkcji BCryptOpenAlgorithmProvider!"), TEXT("Błąd"), MB_ICONERROR);
		CleanupCryptPro(); return false;
	}

	// Ustaw tryb CBC (zalecany klasyczny blokowy z paddingiem).
	status = BCryptSetProperty(hAes, BCRYPT_CHAINING_MODE, (PUCHAR)BCRYPT_CHAIN_MODE_CBC,
		(ULONG)(sizeof(WCHAR) * (lstrlen(BCRYPT_CHAIN_MODE_CBC) + 1)), 0);
	if(!BCRYPT_SUCCESS(status))
	{
		MessageBox(nullptr, TEXT("Błąd funkcji BCryptSetProperty!"), TEXT("Błąd"), MB_ICONERROR);
		CleanupCryptPro(); return false;
	}

	// Utworzenie klucza symetrycznego z pKey (16B dla AES-128, 32B dla AES-256)
	status = BCryptGenerateSymmetricKey(hAes, &hKey, nullptr, 0, pBKey, cDKeyLen, 0);
	//if(status != 0)
	if(!BCRYPT_SUCCESS(status))
	{
		MessageBox(nullptr, TEXT("Błąd funkcji BCryptGenerateSymmetricKey!"), TEXT("Błąd"), MB_ICONERROR);
		CleanupCryptPro(); return false;
	}

	// 5) Wyznacz rozmiar ciphertext (z paddingiem).
	DWORD DCipher = 0;
	BYTE BCopyIV[CI_SIZEIV]; memcpy(BCopyIV, pBIV, CI_SIZEIV); // KOPIA IV dla query
	status = BCryptEncrypt(hKey, (PUCHAR)gsPlain.pBData, gsPlain.DDataLen, nullptr, BCopyIV, CI_SIZEIV,
		nullptr, 0, &DCipher, BCRYPT_BLOCK_PADDING);
	if(!BCRYPT_SUCCESS(status) || DCipher == 0)
	{
		MessageBox(nullptr, TEXT("Błąd funkcji BCryptEncrypt!"), TEXT("Błąd"), MB_ICONERROR);
		CleanupCryptPro(); return false;
	}

	// 6) Alokuj bufor na [Salt + Ciphertext]
	if(DCipher > (MAXDWORD - static_cast<DWORD>(sizeof(BSalt))))
	{
		MessageBox(nullptr, TEXT("Zbyt duży rozmiar danych do zapisu."), TEXT("Błąd"), MB_ICONERROR);
		CleanupCryptPro(); return false;
	}
	// Zapisujemy Salt (16B) przed ciphertext – minimalny, bezpieczny nagłówek.
	const DWORD cDOutputTotal = static_cast<DWORD>(sizeof(BSalt)) + DCipher;
	pBOutput = static_cast<BYTE*>(HeapAlloc(GetProcessHeap(), 0, cDOutputTotal));
	if(!pBOutput)
	{
		MessageBox(nullptr, TEXT("Błąd funkcji HeapAlloc!"), TEXT("Błąd"), MB_ICONERROR);
		CleanupCryptPro(); return false;
	}

	// 7) Skopiuj Salt do wyjścia.
	memcpy(pBOutput, BSalt, sizeof(BSalt));

	// 8) Wykonaj szyfrowanie do bufora wyjściowego (za Salt).
	DWORD DWritten = 0;
	BYTE BRunIV[CI_SIZEIV]; memcpy(BRunIV, pBIV, CI_SIZEIV); // DRUGA KOPIA IV dla właściwego szyfrowania
	status = BCryptEncrypt(hKey, (PUCHAR)gsPlain.pBData, gsPlain.DDataLen, nullptr, BRunIV,
		CI_SIZEIV, pBOutput + sizeof(BSalt), DCipher, &DWritten, BCRYPT_BLOCK_PADDING);
	if(!BCRYPT_SUCCESS(status) || DWritten != DCipher)
	{
		MessageBox(nullptr, TEXT("Błąd funkcji BCryptEncrypt!"), TEXT("Błąd"), MB_ICONERROR);
		CleanupCryptPro(); return false;
	}
	// Tworzenie HMAC do weryfikacji
	BYTE Bhmac[CI_SIZEHMAC] = {};
	if(!GsAESPro::_GsAESProComputeHMAC(pBKey, cDKeyLen, pBOutput, cDOutputTotal, Bhmac))
	{CleanupCryptPro(); return false;}

	const DWORD cDFinalTotal = cDOutputTotal + sizeof(Bhmac) + sizeof(GsAESHeader);
	pBFinal = static_cast<BYTE*>(HeapAlloc(GetProcessHeap(), 0, cDFinalTotal));
	if(!pBFinal) { CleanupCryptPro(); return false; }

	memcpy(pBFinal, &MyAESHeader, sizeof(GsAESHeader)); // Wklejenie nagłówka na początek pliku
	memcpy(pBFinal + sizeof(GsAESHeader), pBOutput, cDOutputTotal); // Wklejenie zaszyfrowanych danych, po nagłówku
	memcpy(pBFinal + cDOutputTotal + sizeof(GsAESHeader), Bhmac, sizeof(Bhmac)); // Wklejenie HMAC po nagłówku i zaszyfrowanych danych, czyli na końcu.

	// 9) Zapisz [Salt + Ciphertext] do pliku wyjściowego.
	if(!GsWriteDataToFile(lpcszFileOutput, pBFinal, cDFinalTotal))
	{
		MessageBox(nullptr, TEXT("Błąd funkcji GsWriteDataToFile()!"), TEXT("Błąd"), MB_ICONERROR);
		CleanupCryptPro(); return false;
	}

	CleanupCryptPro();
	bResult = true;
	return bResult;
	/* STRUKTURA ZASZYFROWANYCH DANYCH
	[ GsAESHeader ] // 6 bajtów: "GSAE", wersja, flagi
	[ Salt ] // 16 bajtów PBKDF2
	[ Ciphertext ] // zaszyfrowane dane AES-CBC + padding
	[ HMAC ] // 32 bajty HMAC-SHA256
	*/
}
//---------------------------------------------------------------------------
__fastcall bool GsAESPro::GsAESProDecryptFile(const GsStoreData &gsHash, LPCWSTR lpcszFileInput, LPCWSTR lpcszFileOutput, const enSizeKey enAESKey)
/**
	OPIS METOD(FUNKCJI): Odszyfrowuje plik AES-256 CBC z PBKDF2 (Hash jako „password bytes”)
	OPIS ARGUMENTÓW: [in] - const SHAResult &Hash - Wygenerowany hash z hasła w funkcji ComputeSHAHash().
													LPCWSTR lpcszFileInput-Ścieżka dostępu do pliku, który będzie zaszyfrowany
													LPCWSTR lpcszFileOutput-Ścieżka dostępu do zaszyfrowanego pliku
	OPIS ZMIENNYCH:
	OPIS WYNIKU METODY(FUNKCJI): Struktura SHAResult zawierająca 32 bajty, lub 64 bajty skrótu
															 TRUE: sukces, plik odszyfrowany i zapisany
															 FALSE: błąd
	UWAGI:
	STRUKTURA ZASZYFROWANYCH DANYCH:
	[GsAESHeader ] // 6 bajtów: "GSAE", wersja, flagi
	[Salt ] // 16 bajtów PBKDF2
	[Ciphertext ] // zaszyfrowane dane AES-CBC + padding
	[HMAC ] // 32 bajty HMAC-SHA256
*/
{
	bool bResult=false;
	NTSTATUS status=1;
	GsStoreData gsFullReadFile = {nullptr, 0}; // Cały odczytany plik wejściowy
	BCRYPT_ALG_HANDLE hKdf=nullptr;
	BCRYPT_ALG_HANDLE hAes=nullptr;
	BCRYPT_KEY_HANDLE hKey=nullptr;
	BYTE *pBPlain=nullptr, *pBEnc=nullptr;
	DWORD DPlainLen = 0, DEncLen=0;
	GsAESHeader MyAESHeader;

	// Walidacja argumentów
	if (!gsHash.pBData || gsHash.DDataLen == 0 || !lpcszFileInput || !lpcszFileOutput) return false;

	// Wybór algorytmu PRF
	const DWORD cDKeyLen	 = (enAESKey == enSizeKey_128) ? CI_KEYLEN_128 : CI_KEYLEN_256;
	const DWORD cDDerivedLen	 = cDKeyLen + CI_SIZEIV; // Key + IV
	BYTE *pBDerived	= static_cast<BYTE*>(HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, cDDerivedLen));
	if(!pBDerived) return false;
	const LPCWSTR lpcszAlg = (enAESKey == enSizeKey_128) ? BCRYPT_SHA256_ALGORITHM : BCRYPT_SHA512_ALGORITHM;
	// StringCchPrintf(Gl_szInfoDebug, glMaxIfoDebug, TEXT("PRF: %s, Długość hasha: %d"), prfAlg, Hash.cbDataLength);
	// MessageBox(nullptr, Gl_szInfoDebug, TEXT("Informacja"), MB_ICONINFORMATION);

	if(!gsHash.pBData || gsHash.DDataLen == 0 || !lpcszFileInput || !lpcszFileOutput) return false;

	auto CleanupDecryptPro = [&]()
	/**
		OPIS METOD(FUNKCJI): Funkcja zwalniająca zarezerwowane zasoby podczas błędu
												 lub zakończenia nadrzędnej funkcji typu lambda
	*/
	{
		if(hKey) {BCryptDestroyKey(hKey); hKey = nullptr;}
		//if(gsFullReadFile.pbData) {HeapFree(GetProcessHeap(), 0, gsFullReadFile.pbData); gsFullReadFile.pbData = nullptr;}
		if(pBPlain)
		{
			SecureZeroMemory(pBPlain, DPlainLen);
			HeapFree(GetProcessHeap(), 0, pBPlain); pBPlain = nullptr;
		}
		if(hKdf) {BCryptCloseAlgorithmProvider(hKdf, 0); hKdf = nullptr;}
		if(hAes) {BCryptCloseAlgorithmProvider(hAes, 0); hAes = nullptr;}
		if(pBDerived)
		{
			SecureZeroMemory(pBDerived, sizeof(cDDerivedLen)); // AI [23-12-2025]
			HeapFree(GetProcessHeap(), 0, pBDerived); pBDerived = nullptr;
		}
	};

	size_t cchInSize=0, cchOutSize=0;
	if(FAILED(StringCchLength(lpcszFileInput, MAX_PATH, &cchInSize))) return false;
	if(FAILED(StringCchLength(lpcszFileOutput, MAX_PATH, &cchOutSize))) return false;

	// 1) Wczytaj plik wejściowy.
	if(!GsReadDataFromFile(lpcszFileInput, &gsFullReadFile)) {CleanupDecryptPro(); return false;} // Cały odczytany plik wejściowy
	if(gsFullReadFile.DDataLen < sizeof(GsAESHeader) + CI_SIZESALT + 16 + CI_SIZEHMAC) // AI [23-12-2023]
	// Musi być co najmniej Salt + coś.
	{
		MessageBox(nullptr, TEXT("Błąd funkcji GsReadDataFromFile!"), TEXT("Błąd"), MB_ICONERROR);
		CleanupDecryptPro(); return false;
	}
	// Odczyt nagłówka
	memcpy(&MyAESHeader, gsFullReadFile.pBData, sizeof(GsAESHeader));
	// Porównanie odczytanego nagłówka ze wzorem.
	if(memcmp(Gl_GsAESHeader.Magic, MyAESHeader.Magic, sizeof(Gl_GsAESHeader.Magic)) != 0)
	{
		MessageBox(nullptr, TEXT("Plik ten nie został zaszyfrowany w tej aplikacji!"), TEXT("Błąd"), MB_ICONERROR);
		// Czyszczenie po sobie
		CleanupDecryptPro();
		return false;
	}

	// Wskaźnik na dane za nagłówkiem
	DEncLen = gsFullReadFile.DDataLen - sizeof(GsAESHeader);
	pBEnc = gsFullReadFile.pBData + sizeof(GsAESHeader);

	// 2) Rozdziel Salt i Ciphertext
	BYTE BSalt[CI_SIZESALT] = {};
	memcpy(BSalt, pBEnc, sizeof(BSalt));

	const DWORD cDCipher = DEncLen - sizeof(BSalt) - CI_SIZEHMAC; // dane odszyfrowane - wielkość Salt(16) - wielkość Hmac(32) // - sizeof(MyGsAESHeader)
	BYTE *pBCipher = pBEnc + sizeof(BSalt);
	const BYTE *pBHmacStored = pBEnc + sizeof(BSalt) + cDCipher;
	if(cDCipher < 16 || (cDCipher % 16) != 0)
	{
		MessageBox(nullptr, TEXT("Plik jest uszkodzony, lub nie jest z tego formatu!"), TEXT("Błąd"), MB_ICONERROR);
		CleanupDecryptPro(); return false;
	}

	// 3) PBKDF2: Hash + Salt → Derived (Key (16B)32B + IV 16B)
	status = BCryptOpenAlgorithmProvider(&hKdf, lpcszAlg, MS_PRIMITIVE_PROVIDER, BCRYPT_ALG_HANDLE_HMAC_FLAG);
	if(!BCRYPT_SUCCESS(status))
	{
		MessageBox(nullptr, TEXT("Błąd funkcji BCryptOpenAlgorithmProvider!"), TEXT("Błąd"), MB_ICONERROR);
		CleanupDecryptPro(); return false;
	}

	status = BCryptDeriveKeyPBKDF2(hKdf, (PUCHAR)gsHash.pBData, (ULONG)gsHash.DDataLen,	 (PUCHAR)BSalt,
		(ULONG)sizeof(BSalt), CUL_ITERATIONS, (PUCHAR)pBDerived, (ULONG)cDDerivedLen, 0);

	BCryptCloseAlgorithmProvider(hKdf, 0);
	if(!BCRYPT_SUCCESS(status))
	{
		MessageBox(nullptr, TEXT("Błąd funkcji BCryptDeriveKeyPBKDF2!"), TEXT("Błąd"), MB_ICONERROR);
		CleanupDecryptPro(); return false;
	}

	BYTE *pBKey = pBDerived;			 // 16B lub 32B
	const BYTE *pcBIV	 = pBDerived + cDKeyLen; // 16B

	// 3b) Weryfikacja HMAC
	BYTE Bhmac[CI_SIZEHMAC] = {};
	if(!GsAESPro::_GsAESProComputeHMAC(pBKey, cDKeyLen, pBEnc, sizeof(BSalt) + cDCipher, Bhmac))
	{
		CleanupDecryptPro(); return false;
	}
	if (memcmp(Bhmac, pBHmacStored, sizeof(Bhmac)) != 0)
	{
		MessageBox(nullptr, TEXT("Nieprawidłowe hasło lub plik uszkodzony (HMAC niezgodny)!"), TEXT("Błąd weryfikacji"), MB_ICONERROR);
		CleanupDecryptPro(); return false;
	}

	// 4) AES-256 lub AES-128 CBC
	status = BCryptOpenAlgorithmProvider(&hAes, BCRYPT_AES_ALGORITHM, MS_PRIMITIVE_PROVIDER, 0);
	if(!BCRYPT_SUCCESS(status))
	{
		MessageBox(nullptr, TEXT("Błąd funkcji BCryptOpenAlgorithmProvider!"), TEXT("Błąd"), MB_ICONERROR);
		CleanupDecryptPro(); return false;
	}

	status = BCryptSetProperty(hAes, BCRYPT_CHAINING_MODE, (PUCHAR)BCRYPT_CHAIN_MODE_CBC,
		(ULONG)(sizeof(WCHAR) * (lstrlen(BCRYPT_CHAIN_MODE_CBC) + 1)), 0);
	if(!BCRYPT_SUCCESS(status))
	{
		MessageBox(nullptr, TEXT("Błąd funkcji BCryptSetProperty!"), TEXT("Błąd"), MB_ICONERROR);
		CleanupDecryptPro(); return false;
	}

	status = BCryptGenerateSymmetricKey(hAes, &hKey, nullptr, 0, pBKey, cDKeyLen, 0);
	if(!BCRYPT_SUCCESS(status))
	{
		MessageBox(nullptr, TEXT("Błąd funkcji BCryptGenerateSymmetricKey!"), TEXT("Błąd"), MB_ICONERROR);
		CleanupDecryptPro(); return false;
	}

	// 5) Wyznacz rozmiar plaintext.
	BYTE BCopyIV[CI_SIZEIV]; memcpy(BCopyIV, pcBIV, CI_SIZEIV); // PIERWSZA, niezależna kopia IV
	status = BCryptDecrypt(hKey, pBCipher, cDCipher, nullptr, BCopyIV, CI_SIZEIV, nullptr, 0,
		&DPlainLen, BCRYPT_BLOCK_PADDING);
	if(!BCRYPT_SUCCESS(status)) // || cbPlain == 0)
	{
		MessageBox(nullptr, TEXT("Błąd funkcji BCryptDecrypt() (zapytanie o rozmiar).!"), TEXT("Błąd"), MB_ICONERROR);
		CleanupDecryptPro(); return false;
	}
	// if(cbCipher < 16)
	// {
	//	MessageBox(nullptr, TEXT("Błąd funkcji BCryptDecrypt() (błąd formatu).!"), TEXT("Błąd"), MB_ICONERROR);
	//	CleanupDecryptPro(); return false;
	//	/* błąd formatu */
	// }
	// 6) Odszyfruj do bufora.
	pBPlain = static_cast<BYTE*>(HeapAlloc(GetProcessHeap(), 0, DPlainLen));
	if(!pBPlain)
	{
		MessageBox(nullptr, TEXT("Błąd funkcji HeapAlloc!"), TEXT("Błąd"), MB_ICONERROR);
		CleanupDecryptPro(); return false;
	}

	DWORD DOut = 0;
	BYTE BRunIV[CI_SIZEIV]; memcpy(BRunIV, pcBIV, CI_SIZEIV); // DRUGA, niezależna kopia IV
	status = BCryptDecrypt(hKey, pBCipher, cDCipher, nullptr, BRunIV, CI_SIZEIV, pBPlain,
		DPlainLen, &DOut, BCRYPT_BLOCK_PADDING);
	if(!BCRYPT_SUCCESS(status)) // || cbOut != cbPlain)
	{
		MessageBox(nullptr, TEXT("Błąd funkcji BCryptDecrypt() podczas deszyfracji!"), TEXT("Błąd"), MB_ICONERROR);
		CleanupDecryptPro(); return false;
	}

	// 7) Zapisz plaintext do pliku wyjściowego.
	if(!GsWriteDataToFile(lpcszFileOutput, pBPlain, DOut))
	{
		MessageBox(nullptr, TEXT("Błąd funkcji _WriteWholeFile!"), TEXT("Błąd"), MB_ICONERROR);
		CleanupDecryptPro(); return false;
	}

	// Wymazanie materiału kluczowego
	SecureZeroMemory(pBDerived, cDDerivedLen); // AI [23-12-2025]
	SecureZeroMemory(pBPlain, DPlainLen); // AI [23-12-2025]

	CleanupDecryptPro();
	bResult = true;
	return bResult;
}	
//---------------------------------------------------------------------------
__fastcall bool GsAESPro::_GsAESProComputeHMAC(const BYTE *pBKey, const DWORD DKeyLen, const BYTE *pcBData, const DWORD cDDataLen,
	BYTE *pBhmacOut, DWORD DHmacOut)
/**
	OPIS METOD(FUNKCJI): Oblicza HMAC-SHA256 dla bufora danych przy użyciu klucza.
	OPIS ARGUMENTÓW: [in] - const BYTE *pBKey-Wskaźnik na klucz (16B dla AES-128, 32B dla AES-256).
									 [in] - const DWORD DKeyLen-Długość klucza w bajtach.
									 [in] - const BYTE *pcBData-Wskaźnik na dane wejściowe (Salt + Ciphertext).
									 [in] - DWORD DDataLen-Długość danych wejściowych.
									 [out] - BYTE *pBhmacOut-Bufor wyjściowy na HMAC (32 bajty).
									 [in] - DWORD DHmacOut-Długość bufora wyjściowego na HMAC, domyślnie 32b.
	OPIS ZMIENNYCH:
	OPIS WYNIKU METODY(FUNKCJI): true, jeśli sukces, false, jeśli błąd.
	UWAGI:
*/
{
	NTSTATUS status;
	BCRYPT_ALG_HANDLE hHmacAlg = nullptr;
	BCRYPT_HASH_HANDLE hHash = nullptr;

	// Wyzeruj bufor wyjściowy na początku
	if(pBhmacOut && DHmacOut > 0) SecureZeroMemory(pBhmacOut, DHmacOut);

	status = BCryptOpenAlgorithmProvider(&hHmacAlg, BCRYPT_SHA256_ALGORITHM, MS_PRIMITIVE_PROVIDER, BCRYPT_ALG_HANDLE_HMAC_FLAG);
	if(!BCRYPT_SUCCESS(status))
	{
		if(pBhmacOut && DHmacOut > 0) SecureZeroMemory(pBhmacOut, DHmacOut);
		return false;
	}

	status = BCryptCreateHash(hHmacAlg, &hHash, nullptr, 0, const_cast<PUCHAR>(pBKey), DKeyLen, 0);
	if(!BCRYPT_SUCCESS(status))
	{
		BCryptCloseAlgorithmProvider(hHmacAlg,0); hHmacAlg = nullptr;
		if(pBhmacOut && DHmacOut > 0) SecureZeroMemory(pBhmacOut, DHmacOut);
		return false;
	}

	status = BCryptHashData(hHash, const_cast<PUCHAR>(pcBData), cDDataLen, 0);
	if(!BCRYPT_SUCCESS(status))
	{
		BCryptDestroyHash(hHash); hHash = nullptr;
		BCryptCloseAlgorithmProvider(hHmacAlg,0); hHmacAlg = nullptr;
		if(pBhmacOut && DHmacOut > 0) SecureZeroMemory(pBhmacOut, DHmacOut);
		return false;
	}

	status = BCryptFinishHash(hHash, pBhmacOut, DHmacOut, 0);
	BCryptDestroyHash(hHash);
	BCryptCloseAlgorithmProvider(hHmacAlg,0);

	if(!BCRYPT_SUCCESS(status))
	{
		if(pBhmacOut && DHmacOut > 0) SecureZeroMemory(pBhmacOut, DHmacOut); // opcjonalne wymazanie przy błędzie
		return false;
	}

	return BCRYPT_SUCCESS(status);
}
//---------------------------------------------------------------------------
//============================== METODY POMOCNICZE ==========================
__fastcall TCHAR *GsAESFunEncodeBase64(LPCWSTR lpcszPassword)
/**
	OPIS METOD(FUNKCJI): Szyfrowanie tekstu za pomocą Base64.
	OPIS ARGUMENTÓW: [in] - LPCWSTR pszPassword-Tekst do zakodowania.
	OPIS ZMIENNYCH:
	UWAGI: Bufor wynikowy, pszOut należy zwolnić przez HeapFree(GetProcessHeap(),0,pszOut).
*/
{
	TCHAR *pszOut=nullptr;
	DWORD DOut=0;
	int iUtf8=0;
	BYTE* pBUtf8=nullptr;

	if(!lpcszPassword) return nullptr; // AI [23-12-2025]
	auto CleanupCryptBase64 = [&]()
	/**
		OPIS METOD(FUNKCJI): Funkcja zwalniająca zarezerwowane zasoby podczas błędu
												 lub zakończenia nadrzędnej funkcji typu lambda
	*/
	{
		if(pBUtf8) {HeapFree(GetProcessHeap(), 0, pBUtf8); pBUtf8 = nullptr;}
	};

	// Konwersja do UTF-8 bajtów
	iUtf8 = WideCharToMultiByte(CP_UTF8, 0, lpcszPassword, -1, nullptr, 0, nullptr, nullptr);
	pBUtf8 = static_cast<BYTE*>(HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, iUtf8));
	if(!pBUtf8) {CleanupCryptBase64(); return nullptr;}
	WideCharToMultiByte(CP_UTF8, 0, lpcszPassword, -1, reinterpret_cast<LPSTR>(pBUtf8), iUtf8, nullptr, nullptr);
	// Najpierw sprawdzamy wymaganą długość.
	if(!CryptBinaryToString(pBUtf8, iUtf8 - 1, CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF, nullptr, &DOut))
		{CleanupCryptBase64(); return nullptr;}
	// Alokujemy bufor
	pszOut = static_cast<TCHAR*>(HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, DOut * sizeof(TCHAR)));
	if(!pszOut) {CleanupCryptBase64(); return nullptr;}
	// Właściwe kodowanie
	if(!CryptBinaryToString(pBUtf8, iUtf8 - 1,CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF, pszOut, &DOut))
	{CleanupCryptBase64(); return nullptr;}

	CleanupCryptBase64();
	return pszOut;
}
//---------------------------------------------------------------------------
__fastcall bool GsAESFunDecodeBase64(LPCWSTR lpcszPasswordBase64, TCHAR *pszOut, const DWORD cDOutSize)
/**
	OPIS METOD(FUNKCJI): Odszyfrowanie tekstu za pomocą Base64.
	OPIS ARGUMENTÓW: [in]LPCWSTR pszPasswordBase64 - Zakodowany ciąg.
					 [out]TCHAR *pszOut-Wskażnik na zdekodowane hasło.
					 [in]DWORD OutSize-Wielkość pszOut.
	OPIS ZMIENNYCH:
*/
{
	DWORD DBinary=0, DSkip=0, DFlags=0;
	BYTE *pBData=nullptr;

	if(!lpcszPasswordBase64 || !pszOut || cDOutSize == 0) return false; // AI [23-12-2025]
	auto CleanupDecryptBase64 = [&]()
	/**
		OPIS METOD(FUNKCJI): Funkcja zwalniająca zarezerwowane zasoby podczas błędu
												 lub zakończenia nadrzędnej funkcji typu lambda
	*/
	{
		if(pBData) {HeapFree(GetProcessHeap(), 0, pBData); pBData = nullptr;}
	};

	// Najpierw sprawdzamy wymaganą długość bufora.
	if (!CryptStringToBinary(lpcszPasswordBase64, 0, CRYPT_STRING_BASE64, nullptr,&DBinary,
		&DSkip, &DFlags)) return false;
	// Alokujemy bufor
	pBData = static_cast<BYTE*>(HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, DBinary));
	if(!pBData) {CleanupDecryptBase64(); return false;}
	// Właściwe dekodowanie
	if (!CryptStringToBinary(lpcszPasswordBase64, 0, CRYPT_STRING_BASE64, pBData, &DBinary,
		&DSkip,&DFlags)) {CleanupDecryptBase64(); return false;}
	// Wyświetlenie jako tekst (UTF-8 → WideChar).
	if(MultiByteToWideChar(CP_UTF8, 0, reinterpret_cast<LPCSTR>(pBData), DBinary, pszOut, cDOutSize) == 0) return false; // AI [23-12-2025]

	CleanupDecryptBase64();
	return true;
}
//---------------------------------------------------------------------------
