// Copyright (c) Grzegorz Sołtysik
// Nazwa projektu: AESManager
// Nazwa pliku: GsAES.cpp
// Data: 20.11.2025, 07:13

//
// Created by GrzegorzS on 17.10.2025.
//
#define UNICODE
#include "GsAES.h"
#include <bcrypt.h>
#include <wincrypt.h>
#include <Strsafe.h>
#include <stdexcept>

#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
__fastcall void Global_Debug(const AESResult &Hash, const AESResult &KEY, const AESResult &IV);

__fastcall AESResult GsAES::GsAESComputeSHAHash(LPCWSTR pszText, enSizeSHABit enTypeHash)
/**
	OPIS METOD(FUNKCJI): Oblicza skrót SHA-256, lub SHA-512 dla tekstu Unicode (LPCWSTR)
	OPIS ARGUMENTÓW: [in] - LPCWSTR pszText - wskaźnik do szerokoznakowego łańcucha wejściowego
					 [in] - enSizeSHABit enTypeHash - typ haszowania, SHA-256 lub SHA-512
	OPIS ZMIENNYCH:
	OPIS WYNIKU METODY(FUNKCJI): Struktura SHAResult zawierająca 32 bajty, lub 64 bajty skrótu
	UWAGI: Bufor pbData należy zwolnić przez HeapFree(GetProcessHeap(),0,pbData)
*/
{
	AESResult result = { nullptr, 0 };
	BYTE* utf8Data=nullptr;
	BCRYPT_ALG_HANDLE hAlg=nullptr;
	BCRYPT_HASH_HANDLE hHash=nullptr;
	PBYTE pbHashObject=nullptr;
	DWORD cbHashObject=0, cbData=0, cbHash=0;
	NTSTATUS status=1;

	auto CleanupHash = [&]()
	{
		if(hHash) {BCryptDestroyHash(hHash); hHash = nullptr;}
		if(pbHashObject) {HeapFree(GetProcessHeap(), 0, pbHashObject); pbHashObject = nullptr;}
		if(hAlg) {BCryptCloseAlgorithmProvider(hAlg, 0); hAlg = nullptr;}
		if(utf8Data) {HeapFree(GetProcessHeap(), 0, utf8Data); hAlg = nullptr;}
	};

	if(pszText == nullptr)
	{
		MessageBox(nullptr, TEXT("Nie wprowadziłeś hasła!"), TEXT("Błąd"), MB_ICONERROR);
		// Czyszczenie po sobie
		CleanupHash();
		return result;
	}

	// Bezpieczne obliczenie długości
	size_t cchLen = 0;
	HRESULT hr = StringCchLength(pszText, STRSAFE_MAX_CCH, &cchLen);
	if(FAILED(hr))
	{
		MessageBox(nullptr, TEXT("Błąd funkcji StringCchLength()!"), TEXT("Błąd"), MB_ICONERROR);
		// Czyszczenie po sobie
		CleanupHash();
		return result;
	}

	// Konwersja do UTF-8
	const int cbUtf8 = WideCharToMultiByte(CP_UTF8, 0, pszText, static_cast<int>(cchLen),
									 nullptr, 0, nullptr, nullptr);
	if(cbUtf8 <= 0)
	{
		MessageBox(nullptr, TEXT("Błąd funkcji WideCharToMultiByte()!"), TEXT("Błąd"), MB_ICONERROR);
		// Czyszczenie po sobie
		CleanupHash();
		return result;
	}

	utf8Data = static_cast<BYTE*>(HeapAlloc(GetProcessHeap(), 0, cbUtf8));
	if(!utf8Data)
	{
		MessageBox(nullptr, TEXT("Błąd funkcji HeapAlloc()!"), TEXT("Błąd"), MB_ICONERROR);
		// Czyszczenie po sobie
		CleanupHash();
		return result;
	}

	if(WideCharToMultiByte(CP_UTF8, 0, pszText, static_cast<int>(cchLen),
		reinterpret_cast<LPSTR>(utf8Data), cbUtf8, nullptr, nullptr) <= 0)
	{
		MessageBox(nullptr, TEXT("Błąd funkcji WideCharToMultiByte()!"), TEXT("Błąd"), MB_ICONERROR);
		// Czyszczenie po sobie
		CleanupHash();
		return result;
	}

	// Hashowanie SHA-256, lub SHA-512
	if(enTypeHash == enSizeSHABit_256) // SHA-256
		status = BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_SHA256_ALGORITHM, nullptr, 0);
	else if(enTypeHash == enSizeSHABit_512) // SHA-512
		status = BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_SHA512_ALGORITHM, nullptr, 0);
	if(status != 0)
	{
		MessageBox(nullptr, TEXT("Błąd funkcji BCryptOpenAlgorithmProvider()!"), TEXT("Błąd"), MB_ICONERROR);
		// Czyszczenie po sobie
		CleanupHash();
		return result;
	}

	status = BCryptGetProperty(hAlg, BCRYPT_OBJECT_LENGTH,
		reinterpret_cast<PUCHAR>(&cbHashObject), sizeof(cbHashObject), &cbData, 0);
	if(status != 0)
	{
		MessageBox(nullptr, TEXT("Błąd funkcji BCryptGetProperty()!"), TEXT("Błąd"), MB_ICONERROR);
		// Czyszczenie po sobie
		CleanupHash();
		return result;
	}

	status = BCryptGetProperty(hAlg, BCRYPT_HASH_LENGTH,
		reinterpret_cast<PUCHAR>(&cbHash), sizeof(cbHash), &cbData, 0);
	if(status != 0)
	{
		MessageBox(nullptr, TEXT("Błąd funkcji BCryptGetProperty()!"), TEXT("Błąd"), MB_ICONERROR);
		// Czyszczenie po sobie
		CleanupHash();
		return result;
	}

	pbHashObject = static_cast<PBYTE>(HeapAlloc(GetProcessHeap(), 0, cbHashObject));
	if(!pbHashObject)
	{
		MessageBox(nullptr, TEXT("Błąd funkcji HeapAlloc()!"), TEXT("Błąd"), MB_ICONERROR);
		// Czyszczenie po sobie
		CleanupHash();
		return result;
	}

	status = BCryptCreateHash(hAlg, &hHash, pbHashObject, cbHashObject, nullptr, 0, 0);
	if(status != 0)
	{
		MessageBox(nullptr, TEXT("Błąd funkcji BCryptCreateHash()!"), TEXT("Błąd"), MB_ICONERROR);
		// Czyszczenie po sobie
		CleanupHash();
		return result;
	}

	if(cbUtf8 > 0)
	{
		status = BCryptHashData(hHash, utf8Data, cbUtf8, 0);
		if(status != 0)
		{
			MessageBox(nullptr, TEXT("Błąd funkcji BCryptHashData()!"), TEXT("Błąd"), MB_ICONERROR);
			// Czyszczenie po sobie
			CleanupHash();
			return result;
		}
	}

	result.pbData = static_cast<BYTE*>(HeapAlloc(GetProcessHeap(), 0, cbHash));
	if(!result.pbData)
	{
		MessageBox(nullptr, TEXT("Błąd funkcji HeapAlloc()!"), TEXT("Błąd"), MB_ICONERROR);
		// Czyszczenie po sobie
		CleanupHash();
		return result;
	}

	result.cbDataLength = cbHash;
	status = BCryptFinishHash(hHash, result.pbData, cbHash, 0);
	if(status != 0)
	{
		MessageBox(nullptr, TEXT("Błąd funkcji BCryptFinishHash()!"), TEXT("Błąd"), MB_ICONERROR);
		// Czyszczenie po sobie
		CleanupHash();
		result.cbDataLength = 0;
		return result;
	}

	CleanupHash();

	return result;
}
//---------------------------------------------------------------------------
__fastcall bool GsAES::_GsAESGenerateKeyAndIV_128(const AESResult &Hash, AESResult &Key, AESResult &IV)
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
	Key.cbDataLength = 16;
	Key.pbData = static_cast<BYTE*>(HeapAlloc(GetProcessHeap(), 0, Key.cbDataLength));
	IV.cbDataLength = 16;
	IV.pbData = static_cast<BYTE*>(HeapAlloc(GetProcessHeap(), 0, IV.cbDataLength));

	if(Key.pbData && IV.pbData)
	{
		bResult = true;
		for(int i = 0; i < Key.cbDataLength; ++i)
		{
			Key.pbData[i] = Hash.pbData[i];
			IV.pbData[i] = Hash.pbData[i + Key.cbDataLength];
		}
	}
	return bResult;
}
//---------------------------------------------------------------------------
__fastcall bool GsAES::_GsAESGenerateKeyAndIV_256(const AESResult &Hash, AESResult &Key, AESResult &IV)
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
	Key.cbDataLength = 32;
	Key.pbData = static_cast<BYTE*>(HeapAlloc(GetProcessHeap(), 0, Key.cbDataLength));
	IV.cbDataLength = 16;
	IV.pbData = static_cast<BYTE*>(HeapAlloc(GetProcessHeap(), 0, IV.cbDataLength));

	if(Key.pbData && IV.pbData)
	{
		bResult = true;
		for(int i = 0; i < Key.cbDataLength; ++i)
			Key.pbData[i] = Hash.pbData[i];
		//---
		for(int i=0; i < IV.cbDataLength; ++i)
			IV.pbData[i] = Hash.pbData[i + Key.cbDataLength];
	}
	return bResult;
}
//---------------------------------------------------------------------------
__fastcall bool GsAES::GsAESCryptFile(const AESResult &Hash, LPCWSTR lpszFileInput, LPCWSTR lpszFileOutput, enSizeKey enAESKey)
/**
	OPIS METOD(FUNKCJI): Właściwe szyfrowanie, lub odszyfrowywania.
	OPIS ARGUMENTÓW: [in] - const SHAResult &Hash - Wygenerowany wcześnie hash z hasła w funkcji ComputeSHAHash().
					 [in] - LPCWSTR lpszFileInput - ścieżka dostępu do pliku wejściowego.
					 [in] - LPCWSTR lpszFileOutput - ścieżka dostępu do pliku wyjściowego.
					 [in] - enSizeKey enAESKey - Typ (De)Szyfrowania AES, enSizeKey_128 - 128 bitowe,
							enSizeKey_256 - 256 bitowe.
	OPIS ZMIENNYCH:
*/
{
	// Szyfrowanie za pomocą BCrypt
	BCRYPT_ALG_HANDLE hAlg = nullptr;
	BCRYPT_KEY_HANDLE hKey = nullptr;
	NTSTATUS status;
	ULONG DataLength=0, ulWyliczone=0;
	HANDLE hFileInput = INVALID_HANDLE_VALUE,
		   hFileOutput = INVALID_HANDLE_VALUE;
	LARGE_INTEGER sizeFileInput;
	DWORD dwRead=0, dwWritten=0;

	bool bResult = false;
	AESResult KEY = { nullptr, 0 },
			  IV = {nullptr, 0},
			  PlainText = { nullptr, 0 },
			  CipherText = { nullptr, 0 };

	auto CleanupCrypt = [&]()
	{
		if(hFileInput != INVALID_HANDLE_VALUE) {CloseHandle(hFileInput); hFileInput = INVALID_HANDLE_VALUE;}
		if(hFileOutput != INVALID_HANDLE_VALUE) {CloseHandle(hFileOutput); hFileOutput = INVALID_HANDLE_VALUE;}
		// zwolnienie pamięci
		if(KEY.pbData) {HeapFree(GetProcessHeap(), 0, KEY.pbData); KEY.pbData = nullptr;}
		if(IV.pbData) {HeapFree(GetProcessHeap(), 0, IV.pbData); IV.pbData = nullptr;}
		if(PlainText.pbData) {HeapFree(GetProcessHeap(), 0, PlainText.pbData); PlainText.pbData = nullptr;}
		if(CipherText.pbData) {HeapFree(GetProcessHeap(), 0, CipherText.pbData); CipherText.pbData = nullptr;}
		// Sprzatanie po BCrypt
		if(hKey) {BCryptDestroyKey(hKey); hKey = nullptr;}
		if(hAlg) {BCryptCloseAlgorithmProvider(hAlg, 0); hAlg = nullptr;}

		//MessageBox(nullptr, TEXT("Wywołanie funkcji Cleanup()!"), TEXT("Cleanup()"), MB_ICONINFORMATION);
	};
	// Długość klucza
	switch(enAESKey)
	{
		case enSizeKey_128:
			bResult = GsAES::_GsAESGenerateKeyAndIV_128(Hash, KEY, IV);
		break;
		//---
		case enSizeKey_256:
			bResult = GsAES::_GsAESGenerateKeyAndIV_256(Hash, KEY, IV);
		break;
		//---
		default: bResult = false;
	}

	if(bResult)
	{
		// Wyświetlanie danych - TYMCZASOWO
		//Global_Debug(Hash, KEY, IV)
		// Wczytanie danych wejściowych
		hFileInput = CreateFile(lpszFileInput, GENERIC_READ, FILE_SHARE_READ, nullptr,
			OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
		if(hFileInput == INVALID_HANDLE_VALUE)
		{
			MessageBox(nullptr, TEXT("Błąd otwarcia pliku wejściowego!"), TEXT("Błąd"), MB_ICONERROR);
			// Czyszczenie po sobie
			CleanupCrypt();
			return false;
		}
		if(!GetFileSizeEx(hFileInput, &sizeFileInput))
		{
			MessageBox(nullptr, TEXT("Błąd odczytu wielkości pliku wejściowego!"), TEXT("Błąd"), MB_ICONERROR);
				// Czyszczenie po sobie
			CleanupCrypt();
			return false;
		}

		PlainText.cbDataLength = sizeFileInput.QuadPart;
		PlainText.pbData = static_cast<BYTE*>(HeapAlloc(GetProcessHeap(), 0, PlainText.cbDataLength));
		if(!PlainText.pbData)
		{
			MessageBox(nullptr, TEXT("Błąd alokacji pamięci!"), TEXT("Błąd"), MB_ICONERROR);
			// Czyszczenie po sobie
			CleanupCrypt();
			return false;
		}
		if(!ReadFile(hFileInput, PlainText.pbData, PlainText.cbDataLength, &dwRead, nullptr))
		{
			MessageBox(nullptr, TEXT("Błąd odczytu pliku wejściowego!"), TEXT("Błąd"), MB_ICONERROR);
				// Czyszczenie po sobie
			CleanupCrypt();
			return false;
		}
		if(dwRead != PlainText.cbDataLength)
		{
			MessageBox(nullptr, TEXT("Błąd odczytu pliku wejściowego!"), TEXT("Błąd"), MB_ICONERROR);
				// Czyszczenie po sobie
			CleanupCrypt();
			return false;
		}
		// Stworzenie pliku wyjściowego
		hFileOutput = CreateFile(lpszFileOutput, GENERIC_WRITE, 0, nullptr,
			CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
		if(hFileOutput == INVALID_HANDLE_VALUE)
		{
			MessageBox(nullptr, TEXT("Błąd otwarcia pliku wyjściowego!"), TEXT("Błąd"), MB_ICONERROR);
				// Czyszczenie po sobie
			CleanupCrypt();
			return false;
		}
		if(!WriteFile(hFileOutput, IV.pbData, IV.cbDataLength, &dwWritten, nullptr))
		{
			MessageBox(nullptr, TEXT("Błąd zapisu IV do pliku wyjściowego!"), TEXT("Błąd"), MB_ICONERROR);
				// Czyszczenie po sobie
			CleanupCrypt();
			return false;
		}
		if(dwWritten != IV.cbDataLength)
		{
			MessageBox(nullptr, TEXT("Błąd zapisu danych do pliku wyjściowego!"), TEXT("Błąd"), MB_ICONERROR);
			// Czyszczenie po sobie
			CleanupCrypt();
			return false;
		}
		// Otwórz algorytm AES
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
		status = BCryptGenerateSymmetricKey(hAlg, &hKey, nullptr, 0, (PUCHAR)KEY.pbData, KEY.cbDataLength, 0);
		if(!BCRYPT_SUCCESS(status))
		{
			MessageBox(nullptr, TEXT("Błąd funkcji BCryptGenerateSymmetricKey()!"), TEXT("Błąd"), MB_ICONERROR);
			// Czyszczenie po sobie
			CleanupCrypt();
			return false;
		}
		// Wywołanie wstępne — poznaj rozmiar bufora -> ulWyliczone
		status = BCryptEncrypt(hKey, PlainText.pbData, PlainText.cbDataLength, nullptr, IV.pbData, IV.cbDataLength, nullptr,
			0, &ulWyliczone, BCRYPT_BLOCK_PADDING);
		if(!BCRYPT_SUCCESS(status))
		{
			MessageBox(nullptr, TEXT("Błąd funkcji BCryptEncrypt()!"), TEXT("Błąd"), MB_ICONERROR);
			// Czyszczenie po sobie
			CleanupCrypt();
			return false;
		}
		// Przygotowanie bufora na zaszyfrowane dane.
		CipherText.cbDataLength = ulWyliczone;
		CipherText.pbData = static_cast<BYTE*>(HeapAlloc(GetProcessHeap(), 0, CipherText.cbDataLength));
		if(!CipherText.pbData)
		{
			MessageBox(nullptr, TEXT("Błąd alokacji pamięci!"), TEXT("Błąd"), MB_ICONERROR);
			// Czyszczenie po sobie
			CleanupCrypt();
			return false;
		}
		// Szyfrowanie danych
		status = BCryptEncrypt(hKey, PlainText.pbData, PlainText.cbDataLength, nullptr, IV.pbData, IV.cbDataLength, CipherText.pbData,
			CipherText.cbDataLength, &DataLength, BCRYPT_BLOCK_PADDING);
		if(!BCRYPT_SUCCESS(status))
		{
			MessageBox(nullptr, TEXT("Błąd funkcji BCryptEncrypt()!"), TEXT("Błąd"), MB_ICONERROR);
			// Czyszczenie po sobie
			CleanupCrypt();
			return false;
		}
		if(!WriteFile(hFileOutput, CipherText.pbData, DataLength, &dwWritten, nullptr))
		{
			MessageBox(nullptr, TEXT("Błąd zapisu zaszyfrowanych danych!"), TEXT("Błąd"), MB_ICONERROR);
			// Czyszczenie po sobie
			CleanupCrypt();
			return false;
		}
		if(DataLength !=dwWritten)
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
__fastcall bool GsAES::GsAESDecryptFile(const AESResult &Hash, LPCWSTR lpszFileInput, LPCWSTR lpszFileOutput, enSizeKey enAESKey)
/**
	OPIS METOD(FUNKCJI): Właściwe szyfrowanie, lub odszyfrowywania.
	OPIS ARGUMENTÓW: [in] - const SHAResult &Hash - Wygenerowany wcześnie hash z hasła w funkcji ComputeSHAHash().
					 [in] - LPCWSTR lpszFileInput - ścieżka dostępu do pliku wejściowego.
					 [in] - LPCWSTR lpszFileOutput - ścieżka dostępu do pliku wyjściowego.
					 [in] - enSizeKey enAESKey - Typ (De)Szyfrowania AES, enSizeKey_128 - 128 bitowe,
							enSizeKey_256 - 256 bitowe.
	OPIS ZMIENNYCH:
*/
{
	// Odszyfrowywaanie za pomocą BCrypt
	BCRYPT_ALG_HANDLE hAlg = nullptr;
	BCRYPT_KEY_HANDLE hKey = nullptr;
	NTSTATUS status;
	HANDLE hFileInput = INVALID_HANDLE_VALUE,
		   hFileOutput = INVALID_HANDLE_VALUE;
	LARGE_INTEGER sizeFileInput;
	DWORD dwRead=0, dwWritten=0;
	bool bResult = false;
	AESResult KEY = { nullptr, 0 },
			  IV = {nullptr, 0},
			  PlainText = { nullptr, 0 },
			  CipherText = { nullptr, 0 },
			  FileIV = { nullptr, 0 },
			  EncryptedText = { nullptr, 0 };

	auto CleanupDecrypt = [&]()
	{
		if(hFileInput != INVALID_HANDLE_VALUE) {CloseHandle(hFileInput); hFileInput = INVALID_HANDLE_VALUE;}
		if(hFileOutput != INVALID_HANDLE_VALUE) {CloseHandle(hFileOutput); hFileOutput = INVALID_HANDLE_VALUE;}
		// zwolnienie pamięci
		if(KEY.pbData) {HeapFree(GetProcessHeap(), 0, KEY.pbData); KEY.pbData = nullptr;}
		if(IV.pbData) {HeapFree(GetProcessHeap(), 0, IV.pbData); IV.pbData = nullptr;}
		if(PlainText.pbData) {HeapFree(GetProcessHeap(), 0, PlainText.pbData); PlainText.pbData = nullptr;}
		if(CipherText.pbData) {HeapFree(GetProcessHeap(), 0, CipherText.pbData); CipherText.pbData = nullptr;}
		if(FileIV.pbData) {HeapFree(GetProcessHeap(), 0, FileIV.pbData); FileIV.pbData = nullptr;}
		if(EncryptedText.pbData) {HeapFree(GetProcessHeap(), 0, EncryptedText.pbData); EncryptedText.pbData = nullptr;}
		// Sprzatanie po BCrypt
		if(hKey) {BCryptDestroyKey(hKey); hKey = nullptr;}
		if(hAlg) {BCryptCloseAlgorithmProvider(hAlg, 0); hAlg = nullptr;}

		//MessageBox(nullptr, TEXT("Wywołanie funkcji Cleanup()!"), TEXT("Cleanup()"), MB_ICONINFORMATION);
	};
	// Długość klucza
	switch(enAESKey)
	{
		case enSizeKey_128:
			bResult = GsAES::_GsAESGenerateKeyAndIV_128(Hash, KEY, IV);
		break;
		//---
		case enSizeKey_256:
			bResult = GsAES::_GsAESGenerateKeyAndIV_256(Hash, KEY, IV);
		break;
		//---
		default: bResult = false;
	}

	if(bResult)
	{
		// Wczytanie danych wejściowych
		hFileInput = CreateFile(lpszFileInput, GENERIC_READ, FILE_SHARE_READ, nullptr,
			OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
		if(hFileInput == INVALID_HANDLE_VALUE)
		{
			MessageBox(nullptr, TEXT("Błąd otwarcia pliku wejściowego!"), TEXT("Błąd"), MB_ICONERROR);
			// Czyszczenie po sobie
			CleanupDecrypt();
			return false;
		}
		if(!GetFileSizeEx(hFileInput, &sizeFileInput))
		{
			MessageBox(nullptr, TEXT("Błąd odczytu wielkości pliku wejściowego!"), TEXT("Błąd"), MB_ICONERROR);
			// Czyszczenie po sobie
			CleanupDecrypt();
			return false;
		}
		// Odczytanie IV z początku pliku
		FileIV.cbDataLength = 16; // Długość IV dla AES
		FileIV.pbData = static_cast<BYTE*>(HeapAlloc(GetProcessHeap(), 0, FileIV.cbDataLength));
		if(!FileIV.pbData)
		{
			MessageBox(nullptr, TEXT("Błąd alokacji pamięci!"), TEXT("Błąd"), MB_ICONERROR);
			// Czyszczenie po sobie
			CleanupDecrypt();
			return false;
		}
		if(!ReadFile(hFileInput, FileIV.pbData, FileIV.cbDataLength, &dwRead, nullptr))
		{
			MessageBox(nullptr, TEXT("Błąd odczytu pliku wejściowego!"), TEXT("Błąd"), MB_ICONERROR);
			// Czyszczenie po sobie
			CleanupDecrypt();
			return false;
		}
		if(dwRead != FileIV.cbDataLength)
		{
			MessageBox(nullptr, TEXT("Błąd odczytu pliku wejściowego!"), TEXT("Błąd"), MB_ICONERROR);
			// Czyszczenie po sobie
			CleanupDecrypt();
			return false;
		}
		// Porównanie IV z oczekiwanym
		if(memcmp(FileIV.pbData, IV.pbData, IV.cbDataLength) != 0)
		{
			MessageBox(nullptr, TEXT("Nieprawidłowy klucz lub IV!"), TEXT("Błąd"), MB_ICONERROR);
			// Czyszczenie po sobie
			CleanupDecrypt();
			return false;
		}
		// Wczytanie zaszyfrowanych danych
		TCHAR szTemp[MAX_PATH]; // Zmianna dla komunikatu(tymczasowa)
		LARGE_INTEGER pos;
		SetFilePointerEx(hFileInput, {0}, &pos, FILE_CURRENT);
		EncryptedText.cbDataLength = sizeFileInput.QuadPart - pos.QuadPart;
		EncryptedText.pbData = static_cast<BYTE*>(HeapAlloc(GetProcessHeap(), 0, EncryptedText.cbDataLength));

		if(!ReadFile(hFileInput, EncryptedText.pbData, EncryptedText.cbDataLength, &dwRead, nullptr))
		{
			MessageBox(nullptr, TEXT("Błąd odczytu pliku wejściowego!"), TEXT("Błąd"), MB_ICONERROR);
			// Czyszczenie po sobie
			CleanupDecrypt();
			return false;
		}
		if(dwRead != EncryptedText.cbDataLength)
		{
			MessageBox(nullptr, TEXT("Błąd odczytu pliku wejściowego!"), TEXT("Błąd"), MB_ICONERROR);
			// Czyszczenie po sobie
			CleanupDecrypt();
			return false;
		}
		// Stworzenie pliku wyjściowego
		hFileOutput = CreateFile(lpszFileOutput, GENERIC_WRITE, 0, nullptr,
			CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
		if(hFileOutput == INVALID_HANDLE_VALUE)
		{
			MessageBox(nullptr, TEXT("Błąd otwarcia pliku wyjściowego!"), TEXT("Błąd"), MB_ICONERROR);
			// Czyszczenie po sobie
			CleanupDecrypt();
			return false;
		}
		// Otwórz algorytm AES
		status = BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_AES_ALGORITHM, nullptr, 0);
		if(!BCRYPT_SUCCESS(status))
		{
			MessageBox(nullptr, TEXT("Błąd funkcji BCryptOpenAlgorithmProvider()!"), TEXT("Błąd"), MB_ICONERROR);
			// Czyszczenie po sobie
			CleanupDecrypt();
			return false;
		}
		// Ustaw tryb na CBC
		status = BCryptSetProperty(hAlg, BCRYPT_CHAINING_MODE, (PUCHAR)BCRYPT_CHAIN_MODE_CBC, sizeof(BCRYPT_CHAIN_MODE_CBC), 0);
		if(!BCRYPT_SUCCESS(status))
		{
			MessageBox(nullptr, TEXT("Błąd funkcji BCryptSetProperty()!"), TEXT("Błąd"), MB_ICONERROR);
			// Czyszczenie po sobie
			CleanupDecrypt();
			return false;
		}
		// Utwórz klucz
		status = BCryptGenerateSymmetricKey(hAlg, &hKey, nullptr, 0, (PUCHAR)KEY.pbData, KEY.cbDataLength, 0);
		if(!BCRYPT_SUCCESS(status))
		{
			MessageBox(nullptr, TEXT("Błąd funkcji BCryptGenerateSymmetricKey()!"), TEXT("Błąd"), MB_ICONERROR);
			// Czyszczenie po sobie
			CleanupDecrypt();
			return false;
		}
		// Przygotowanie bufora na odszyfrowane dane
		ULONG BlockSize = 16; // Rozmiar bloku AES
		ULONG PlainTextSize = ((EncryptedText.cbDataLength + BlockSize - 1) / BlockSize) * BlockSize; // Rozmiar bufora dla danych odszyfrowanych
		PlainText.cbDataLength = PlainTextSize;
		PlainText.pbData = static_cast<BYTE*>(HeapAlloc(GetProcessHeap(), 0, PlainText.cbDataLength));
		if(!PlainText.pbData)
		{
			MessageBox(nullptr, TEXT("Błąd alokacji pamięci!"), TEXT("Błąd"), MB_ICONERROR);
			// Czyszczenie po sobie
			CleanupDecrypt();
			return false;
		}
		ULONG DataLength = 0;
		// Deszyfrowanie danych
		status = BCryptDecrypt(hKey, EncryptedText.pbData, EncryptedText.cbDataLength, nullptr, IV.pbData, IV.cbDataLength,
			  PlainText.pbData, PlainText.cbDataLength, &DataLength, BCRYPT_BLOCK_PADDING);
		if(!BCRYPT_SUCCESS(status))
		{
			MessageBox(nullptr, TEXT("Błąd funkcji BCryptDecrypt()!"), TEXT("Błąd"), MB_ICONERROR);
			// Czyszczenie po sobie
			CleanupDecrypt();
			return false;
		}
		// Zapisz odszyfrowane dane
		if(!WriteFile(hFileOutput, PlainText.pbData, DataLength, &dwWritten, nullptr))
		{
			MessageBox(nullptr, TEXT("Błąd zapisu zaszyfrowanych danych!"), TEXT("Błąd"), MB_ICONERROR);
			// Czyszczenie po sobie
			CleanupDecrypt();
			return false;
		}
		if(DataLength !=dwWritten)
		{
			MessageBox(nullptr, TEXT("Błąd zapisu odszyfrowanych danych!"), TEXT("Błąd"), MB_ICONERROR);
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
__fastcall TCHAR *GsAES::GsAESEncodeBase64(LPCWSTR pszPassword)
/**
	OPIS METOD(FUNKCJI): Szyfrowanie tekstu za pomocą Base64.
	OPIS ARGUMENTÓW: [in] - LPCWSTR pszPassword - Tekst do zakodowania.
	OPIS ZMIENNYCH:
	UWAGI: Bufor wynikowy, pszOut należy zwolnić przez HeapFree(GetProcessHeap(),0,pszOut).
*/
{
	TCHAR *pszOut=nullptr;
	DWORD cchOut=0;
	int cbUtf8;
	BYTE* pbUtf8=nullptr;

	auto CleanupCryptBase64 = [&]()
	{
		if(pbUtf8) {HeapFree(GetProcessHeap(), 0, pbUtf8); pbUtf8 = nullptr;}
	};

	// Konwersja do UTF-8 bajtów
	cbUtf8 = WideCharToMultiByte(CP_UTF8, 0, pszPassword, -1, nullptr, 0, nullptr, nullptr);
	pbUtf8 = static_cast<BYTE*>(HeapAlloc(GetProcessHeap(), 0, cbUtf8));
	if(!pbUtf8) {CleanupCryptBase64(); return nullptr;}
	WideCharToMultiByte(CP_UTF8, 0, pszPassword, -1, (LPSTR)pbUtf8, cbUtf8, nullptr, nullptr);
	// Najpierw sprawdzamy wymaganą długość.
	if(!CryptBinaryToString(pbUtf8, cbUtf8 - 1, CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF, nullptr, &cchOut))
		{CleanupCryptBase64(); return nullptr;}
	// Alokujemy bufor
	pszOut = static_cast<TCHAR*>(HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, cchOut * sizeof(TCHAR)));
	if(!pszOut) {CleanupCryptBase64(); return nullptr;}
	// Właściwe kodowanie
	if(!CryptBinaryToString(pbUtf8, cbUtf8 - 1,CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF, pszOut, &cchOut))
	{CleanupCryptBase64(); return nullptr;}

	CleanupCryptBase64();
	return pszOut;
}
//---------------------------------------------------------------------------
__fastcall bool GsAES::GsAESDecodeBase64(LPCWSTR pszPasswordBase64, TCHAR *pszOut, DWORD OutSize)
/**
	OPIS METOD(FUNKCJI): Odszyfrowanie tekstu za pomocą Base64.
	OPIS ARGUMENTÓW: [in]LPCWSTR pszPasswordBase64 - Zakodowany ciąg.
					 [out]TCHAR *pszOut - Wskażnik na zdekodowane hasło.
					 [in]DWORD OutSize - Wielkość pszOut.
	OPIS ZMIENNYCH:
*/
{
	DWORD cbBinary=0, dwSkip=0, dwFlags=0;
	BYTE *pbData=nullptr;

	auto CleanupDecryptBase64 = [&]()
	{
		if(pbData) {HeapFree(GetProcessHeap(), 0, pbData); pbData = nullptr;}
	};

	// Najpierw sprawdzamy wymaganą długość bufora.
	if (!CryptStringToBinary(pszPasswordBase64, 0, CRYPT_STRING_BASE64, nullptr,&cbBinary,
		&dwSkip, &dwFlags)) return false;
	// Alokujemy bufor
	pbData = static_cast<BYTE*>(HeapAlloc(GetProcessHeap(), 0, cbBinary));
	if(!pbData) {CleanupDecryptBase64(); return false;}
	// Właściwe dekodowanie
	if (!CryptStringToBinary(pszPasswordBase64, 0, CRYPT_STRING_BASE64, pbData, &cbBinary,
		&dwSkip,&dwFlags)) {CleanupDecryptBase64(); return false;}
	// Wyświetlenie jako tekst (UTF-8 → WideChar).
	MultiByteToWideChar(CP_UTF8, 0, reinterpret_cast<LPCSTR>(pbData), cbBinary, pszOut, OutSize);

	CleanupDecryptBase64();
	return true;
}
//---------------------------------------------------------------------------
__fastcall GsAES::GsAES()
/**
	OPIS METOD(FUNKCJI):
	OPIS ARGUMENTÓW:
	OPIS ZMIENNYCH:
	OPIS WYNIKU METODY(FUNKCJI):
*/
{

}
//---------------------------------------------------------------------------
__fastcall GsAES::~GsAES()
/**
	OPIS METOD(FUNKCJI):
	OPIS ARGUMENTÓW:
	OPIS ZMIENNYCH:
	OPIS WYNIKU METODY(FUNKCJI):
*/
{

}
//--------------- FUNKCJE PRYWATNE, POMOCNICZE DLA BIBLIOTEKI----------------
__fastcall void Global_Debug(const AESResult &Hash, const AESResult &KEY, const AESResult &IV)
/**
	OPIS METOD(FUNKCJI):
	OPIS ARGUMENTÓW:
	OPIS ZMIENNYCH:
	OPIS WYNIKU METODY(FUNKCJI):
*/
{
	constexpr int cLenTemp = 6 * MAX_PATH;
	TCHAR szTemp[cLenTemp], // Zmianna dla komunikatu(tymczasowa)
		  szTempStrToInt[4], // Tymczasowo
		  szTempHashText[cLenTemp], // Tymczasowo
		  szTempKeyText[cLenTemp], // Tymczasowo
		  szTempIVText[cLenTemp]; // Tymczasowo

	SecureZeroMemory(&szTempHashText, sizeof(szTempHashText));
	SecureZeroMemory(&szTempKeyText, sizeof(szTempKeyText));
	SecureZeroMemory(&szTempIVText, sizeof(szTempIVText));

	for(DWORD i = 0; i < Hash.cbDataLength; ++i)
	{
		StringCchPrintf(szTempStrToInt, 4, TEXT("%02X "), Hash.pbData[i]);
		StringCchCat(szTempHashText, cLenTemp, szTempStrToInt);
	}
	for(DWORD i = 0; i < KEY.cbDataLength; ++i)
	{
		StringCchPrintf(szTempStrToInt, 4, TEXT("%02X "), KEY.pbData[i]);
		StringCchCat(szTempKeyText, cLenTemp, szTempStrToInt);
	}
	for(DWORD i = 0; i < IV.cbDataLength; ++i)
	{
		StringCchPrintf(szTempStrToInt, 4, TEXT("%02X "), IV.pbData[i]);
		StringCchCat(szTempIVText, cLenTemp, szTempStrToInt);
	}

	StringCchPrintf(szTemp, cLenTemp, TEXT("Długość skrótu(haszu): %d\nHashText: \"%s\"\nDługość KEY: %d\nKEY: \"%s\"\nDługość IV: %d\nIV: \"%s\""),
		Hash.cbDataLength, szTempHashText, KEY.cbDataLength, szTempKeyText, IV.cbDataLength, szTempIVText);
	MessageBox(nullptr, szTemp, TEXT("Długość"), MB_ICONINFORMATION);
}
//---------------------------------------------------------------------------