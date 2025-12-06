// Copyright (c) Grzegorz Sołtysik
// Nazwa projektu: AESManager
// Nazwa pliku: GsAESCrypt.cpp
// Data: 6.12.2025, 17:41

//
// Created by GrzegorzS on 17.10.2025.
//
/* OPISY SPECJALISTYCZNYCH FUNKCJI, KTÓRE WYSTĘPUJĄ W BIERZĄCYM PLIKU
	1.Funkcja BCryptOpenAlgorithmProvider ładuje i inicjalizuje dostawcę algorytmu CNG.
	NTSTATUS BCryptOpenAlgorithmProvider(
  [out] BCRYPT_ALG_HANDLE *phAlgorithm, - Wskaźnik do zmiennej BCRYPT_ALG_HANDLE, która otrzymuje handle dostawcy CNG.
																					Po zakończeniu używania tego uchwytu zwolnij go, przekazując do funkcji BCryptCloseAlgorithmProvider.
  [in] LPCWSTR pszAlgId, - Wskaźnik do ciągu Unicode zakończonego zerem, który identyfikuje żądany algorytm kryptograficzny.
													 Może to być jeden ze standardowych identyfikatorów algorytmu CNG lub identyfikator innego zarejestrowanego algorytmu.
  [in, optional] LPCWSTR pszImplementation, - Wskaźnik do ciągu Unicode zakończonego zerem, który identyfikuje konkretnego dostawcę do załadowania.
																						  Jest to zarejestrowany alias dostawcy kryptograficznych prymitywów. Ten parametr jest opcjonalny i może być,
																							jeśli nie jest potrzebny. Jeśli ten parametr to, zostanie załadowany domyślny dostawca dla określonego algorytmu.
  [in] ULONG dwFlags-Flagi modyfikujące zachowanie funkcji. Może to być zero lub kombinacja jednej, lub więcej z następujących wartości
	);
	===========================================================================
	2.Funkcja BCryptGetProperty pobiera wartość nazwanej właściwości dla obiektu CNG.
	*NTSTATUS BCryptGetProperty(
	[in] BCRYPT_HANDLE hObject, - Uchwyt reprezentujący obiekt CNG do uzyskania wartości właściwości.
	[in] LPCWSTR pszProperty, - Wskaźnik do ciągu Unicode zakończonego zerem, który zawiera nazwę własności do pobrania
	[out] PUCHAR pbOutput, - Adres bufora, który otrzymuje wartość właściwości. Parametr cbOutput zawiera rozmiar tego bufora.
	[in] ULONG cbOutput, - Rozmiar bufora pbOutput w bajtach.
	[out] ULONG *pcbResult, - Wskaźnik do zmiennej ULONG, który otrzymuje liczbę bajtów skopiowanych do bufora pbOutput.
														Jeśli parametr pbOutput to, funkcja ta umieszcza wymagany rozmiar, w bajtach,
														w miejscu wskazanym przez ten parametr.NULL
	[in] ULONG dwFlags, - Zestaw flag, które modyfikują zachowanie tej funkcji. Dla tej funkcji nie są zdefiniowane żadne flagi.
	);
	===========================================================================
	3.Funkcja BCryptCreateHash jest wywoływana do utworzenia obiektu hash lub Message Authentication Code (MAC).
	NTSTATUS BCryptCreateHash(
	[in, out] BCRYPT_ALG_HANDLE hAlgorithm, - Handle dostawcy algorytmu obsługującego interfejs hash lub MAC.
																						 Ten uchwyt uzyskuje się przez wywołanie funkcji BCryptOpenAlgorithmProvider
																						 lub może być pseudo-uchwytem algorytmu CNG.
	[out] BCRYPT_HASH_HANDLE *phHash, - Wskaźnik do wartości BCRYPT_HASH_HANDLE, który otrzymuje uchwyt reprezentujący hash lub obiekt MAC.
																			Ten uchwyt jest używany w kolejnych funkcjach haszujących lub MAC,
																			takich jak funkcja BCryptHashData. Gdy skończysz używać tego uchwytu, zwolnij go,
																			przekazując do funkcji BCryptDestroyHash.
	[out, optional] PUCHAR pbHashObject, - Wskaźnik do bufora, który odbiera hash lub obiekt MAC. Parametr cbHashObject zawiera rozmiar tego bufora.
																				 Wymagany rozmiar tego bufora można uzyskać, wywołując funkcję BCryptGetProperty,
																				 aby uzyskać właściwość BCRYPT_OBJECT_LENGTH z uchwytu algorytmu.
																				 To poda rozmiar hashu lub obiektu MAC dla określonego algorytmu.
																				 Ta pamięć może zostać zwolniona dopiero po zniszczeniu uchwytu wskazanego przez parametr phHash.
																				 Jeśli wartość tego parametru wynosi, a wartość parametru cbHashObject jest równa zeru,
																				 pamięć dla obiektu skrótu jest przydzielana przez tę funkcję i uwalniana przez BCryptDestroyHash.
																				 Windows 7: Ta funkcja zarządzania pamięcią jest dostępna od Windows 7.NULL
	[in] ULONG cbHashObject, - Rozmiar bufora pbHashObject w bajtach. Jeśli wartość tego parametru wynosi zero,
														 a wartość parametru pbHashObject to, pamięć dla kluczowego obiektu jest alokowana przez tę funkcję
														 i uwalniana przez BCryptDestroyHash. Windows 7: Ta funkcja zarządzania pamięcią jest dostępna od Windows 7.NULL
	[in, optional] PUCHAR pbSecret, - Wskaźnik do bufora zawierającego klucz do użycia dla MAC. Parametr cbSecret zawiera rozmiar tego bufora.
																		Jeśli jest używany z algorytmem skrótu, algorytm musi zostać promowany do HMAC
																		za pomocą flagi BCRYPT_ALG_HANDLE_HMAC w BCryptOpenAlgorithmProvider.
																		Aby obliczyć skrót, ustaw ten parametr na .NULL
	[in] ULONG cbSecret, - Rozmiar bufora pbSecret, wyrażony w bajtach. Jeśli nie używamy klucza, ustaw ten parametr na zero.
	[in] ULONG dwFlags-Flagi modyfikujące zachowanie funkcji. Może to być wartość zerowa.
	);
	===========================================================================
	4.Funkcja BCryptHashData dodaje dane do bieżącego obliczenia kryptograficznego skrótu lub kodu uwierzytelniania wiadomości (MAC).
	NTSTATUS BCryptHashData(
  [in, out] BCRYPT_HASH_HANDLE hhash, - Uchwyt hashu lub obiektu MAC, którego używa się do wykonania operacji.
																				Ten uchwyt uzyskuje się, wywołując funkcje BCryptCreateHash lub BCryptDuplicateHash.
  [in] PUCHAR pbinput, - Wskaźnik do bufora zawierającego dane do przetworzenia. Parametr cbInput zawiera liczbę bajtów w tym buforze.
												 Funkcja ta nie modyfikuje zawartości tego bufora.
  [in] ULONG cbInput, - Rozmiar bufora pbInput w bajtach.
  [in] ULONG dwFlags-Zestaw flag, które modyfikują zachowanie tej funkcji. Obecnie nie ma żadnych flag, więc ten parametr powinien być zerowy.
	);
	===========================================================================
	5.Funkcja BCryptFinishHash pobiera wartość skrótu lub kodu uwierzytelniania wiadomości (MAC) dla danych zgromadzonych podczas wcześniejszych wywołań do BCryptHashData.
	NTSTATUS BCryptFinishHash(
  [in, out] BCRYPT_HASH_HANDLE hHash, - Uchwyt hashu lub obiektu MAC, którego używa się do wykonania operacji. Ten uchwyt uzyskuje się, wywołując funkcje BCryptCreateHash
																				lub BCryptDuplicateHash. Po wywołaniu tej funkcji uchwyt hHash nie może być ponownie użyty,
																				chyba że został utworzony z flagą BCRYPT_HASH_REUSABLE_FLAG.
  [out] PUCHAR pbOutput, - Wskaźnik do bufora, który otrzymuje wartość skrótu lub MAC. Parametr cbOutput zawiera rozmiar tego bufora.
  [in] ULONG cbOutput, - Rozmiar bufora pbOutput w bajtach. Ten rozmiar musi dokładnie odpowiadać rozmiarowi hasha lub wartości MAC,
												 jeśli ma stały rozmiar. Rozmiar można uzyskać, wywołując funkcję BCryptGetProperty, aby uzyskać własność BCRYPT_HASH_LENGTH.
												 To poda rozmiar hashu lub wartości MAC dla określonego algorytmu. Funkcje rozszerzalne (XOF), takie jak SHAKE256,
												 mogą obsługiwać zmienny rozmiar wyjścia, ale domyślny rozmiar zapewniający pełne bezpieczeństwo XOF może być zapytywany za pomocą BCRYPT_HASH_LENGTH.
  [in] ULONG dwFlags-Zestaw flag, które modyfikują zachowanie tej funkcji. Może to być zero lub kombinacja jednej lub więcej z następujących wartości
	);
	===========================================================================
	6.BCryptCloseAlgorithmProvider
	===========================================================================
	7.BCryptGenerateSymmetricKey
	===========================================================================
	8.BCryptDestroyKey
	===========================================================================
	9.BCryptEncrypt
	===========================================================================
	10.BCryptDecrypt
	===========================================================================
	11.CryptBinaryToString
	===========================================================================
	12.CryptStringToBinary
	===========================================================================
	13.MultiByteToWideChar
*/
#define UNICODE
#include "GsAESCrypt.h"
#include <bcrypt.h>
#include <wincrypt.h>
#include <Strsafe.h>

#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)

//=========================== METODY PRYWATNE POMOCNICZE ====================
static __fastcall bool _ReadWholeFile(LPCWSTR lpszFilePath, AESResult* pOut);
static __fastcall bool _WriteWholeFile(LPCWSTR lpszFilePath, const BYTE* pData, DWORD cbData);

//---------------------------------------------------------------------------
// Klas:	GsAESBasic
// Cel:		Proste szyfrowanie pliku z KEY i IV, ale bez Salt.
// Uwagi:	Przy niezmienionym haśle nagłówki zakodowanych plików są
//				identyczne.
//---------------------------------------------------------------------------

__fastcall AESResult GsAESFunComputeSHAHash(LPCWSTR pszText, const enSizeSHABit enTypeHash)
/**
	OPIS METOD(FUNKCJI): Oblicza skrót SHA-256 lub SHA-512 dla tekstu Unicode (LPCWSTR)
	OPIS ARGUMENTÓW: [in] - LPCWSTR pszText-wskaźnik do szerokoznakowego łańcucha wejściowego
					 [in] - enSizeSHABit enTypeHash-typ haszowania, SHA-256 lub SHA-512
	OPIS ZMIENNYCH:
	OPIS WYNIKU METODY(FUNKCJI): Struktura SHAResult zawierająca 32 bajty, lub 64 bajty skrótu.
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
	/**
		OPIS METOD(FUNKCJI): Funkcja zwalniająca zarezerwowane zasoby podczas błędu
												 lub zakończenia nadrzędnej funkcji typu lambda
	*/
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

	utf8Data = static_cast<BYTE*>(HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, cbUtf8));
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

	pbHashObject = static_cast<PBYTE>(HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, cbHashObject));
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

	result.pbData = static_cast<BYTE*>(HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, cbHash));
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
__fastcall bool GsAESBasic::_GsAESBasicGenerateKeyAndIV_128(const AESResult &Hash, AESResult &Key, AESResult &IV)
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
	Key.pbData = static_cast<BYTE*>(HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, Key.cbDataLength));
	IV.cbDataLength = 16;
	IV.pbData = static_cast<BYTE*>(HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, IV.cbDataLength));

	if(Key.pbData && IV.pbData)
	{
		bResult = true;
		memcpy(Key.pbData, Hash.pbData, Key.cbDataLength);
		memcpy(IV.pbData, Hash.pbData + Key.cbDataLength, Key.cbDataLength);
		//CopyMemory(Key.pbData, Hash.pbData, Key.cbDataLength);
		//CopyMemory(IV.pbData, Hash.pbData + Key.cbDataLength, Key.cbDataLength);
	}

	return bResult;
}
//---------------------------------------------------------------------------
__fastcall bool GsAESBasic::_GsAESBasicGenerateKeyAndIV_256(const AESResult &Hash, AESResult &Key, AESResult &IV)
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
	Key.pbData = static_cast<BYTE*>(HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, Key.cbDataLength));
	IV.cbDataLength = 16;
	IV.pbData = static_cast<BYTE*>(HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, IV.cbDataLength));

	if(Key.pbData && IV.pbData)
	{
		bResult = true;
		memcpy(Key.pbData, Hash.pbData, Key.cbDataLength);
		memcpy(IV.pbData, Hash.pbData + Key.cbDataLength, IV.cbDataLength);
		//CopyMemory(Key.pbData, Hash.pbData, Key.cbDataLength);
		//CopyMemory(IV.pbData, Hash.pbData + Key.cbDataLength, Key.cbDataLength);
	}
	return bResult;
}
//---------------------------------------------------------------------------
__fastcall bool GsAESBasic::GsAESBasicCryptFile(const AESResult &Hash, LPCWSTR lpszFileInput, LPCWSTR lpszFileOutput, enSizeKey enAESKey)
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
	/**
		OPIS METOD(FUNKCJI): Funkcja zwalniająca zarezerwowane zasoby podczas błędu
												 lub zakończenia nadrzędnej funkcji typu lambda
	*/
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
			bResult = GsAESBasic::_GsAESBasicGenerateKeyAndIV_128(Hash, KEY, IV);
		break;
		//---
		case enSizeKey_256:
			bResult = GsAESBasic::_GsAESBasicGenerateKeyAndIV_256(Hash, KEY, IV);
		break;
		//---
		default: bResult = false;
	}

	if(bResult)
	{
		// Wyświetlanie danych-TYMCZASOWO
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
		PlainText.pbData = static_cast<BYTE*>(HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, PlainText.cbDataLength));
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
		CipherText.pbData = static_cast<BYTE*>(HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, CipherText.cbDataLength));
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
__fastcall bool GsAESBasic::GsAESBasicDecryptFile(const AESResult &Hash, LPCWSTR lpszFileInput, LPCWSTR lpszFileOutput, enSizeKey enAESKey)
/**
	OPIS METOD(FUNKCJI): Właściwe szyfrowanie, lub odszyfrowywania.
	OPIS ARGUMENTÓW: [in] - const SHAResult &Hash - Wygenerowany wcześnie hash z hasła w funkcji ComputeSHAHash().
					 [in] - LPCWSTR lpszFileInput-ścieżka dostępu do pliku wejściowego.
					 [in] - LPCWSTR lpszFileOutput-ścieżka dostępu do pliku wyjściowego.
					 [in] - enSizeKey enAESKey-Typ (De)Szyfrowania AES, enSizeKey_128 - 128-bitowe,
							enSizeKey_256 - 256-bitowe.
	OPIS ZMIENNYCH:
*/
{
	// Odszyfrowywaanie za pomocą BCrypt
	BCRYPT_ALG_HANDLE hAlg = nullptr;
	BCRYPT_KEY_HANDLE hKey = nullptr;
	NTSTATUS status=1;
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
			bResult = GsAESBasic::_GsAESBasicGenerateKeyAndIV_128(Hash, KEY, IV);
		break;
		//---
		case enSizeKey_256:
			bResult = GsAESBasic::_GsAESBasicGenerateKeyAndIV_256(Hash, KEY, IV);
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
		FileIV.pbData = static_cast<BYTE*>(HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, FileIV.cbDataLength));
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
		LARGE_INTEGER pos;
		SetFilePointerEx(hFileInput, {0}, &pos, FILE_CURRENT);
		EncryptedText.cbDataLength = sizeFileInput.QuadPart - pos.QuadPart;
		EncryptedText.pbData = static_cast<BYTE*>(HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, EncryptedText.cbDataLength));

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
		PlainText.pbData = static_cast<BYTE*>(HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, PlainText.cbDataLength));
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

//---------------------------------------------------------------------------
// Klas:	GsAESPro
// Cel:		Szyfrowanie pliku z KEY, IV i Salt.
// Uwagi:	Każdy nagłówek zaszyfrowanego pliku jest inny.
//---------------------------------------------------------------------------

__fastcall bool GsAESPro::GsAESProCryptFile(const AESResult &Hash, LPCWSTR lpszFileInput, LPCWSTR lpszFileOutput, enSizeKey enAESKey)
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
	AESResult Plain={nullptr, 0};
	BCRYPT_ALG_HANDLE hKdf=nullptr;
	BCRYPT_ALG_HANDLE hAes=nullptr;
	BCRYPT_KEY_HANDLE hKey=nullptr;
	BYTE derived[48] = {};           // 32B Key + 16B IV.
	BYTE *pOutput=nullptr;

	// Walidacja argumentów
	if (!Hash.pbData || Hash.cbDataLength == 0 || !lpszFileInput || !lpszFileOutput) return false;

	auto CleanupCryptPro = [&]()
	/**
		OPIS METOD(FUNKCJI): Funkcja zwalniająca zarezerwowane zasoby podczas błędu
												 lub zakończenia nadrzędnej funkcji typu lambda
	*/
	{
		if(hKey) {BCryptDestroyKey(hKey); hKey = nullptr;}
		if(Plain.pbData) {HeapFree(GetProcessHeap(), 0, Plain.pbData); Plain.pbData = nullptr;}
		if(hKdf) {BCryptCloseAlgorithmProvider(hKdf, 0); hKdf = nullptr;}
		if(hAes) {BCryptCloseAlgorithmProvider(hAes, 0); hAes = nullptr;}
		SecureZeroMemory(&derived, sizeof(derived));
		if(pOutput) {HeapFree(GetProcessHeap(), 0, pOutput); pOutput = nullptr;}
	};
	
	// Opcjonalna walidacja długości ścieżek (bez używania A/W sufiksów)
	size_t cchIn=0, cchOut=0;
	if(FAILED(StringCchLength(lpszFileInput, MAX_PATH, &cchIn))) return false;
	if(FAILED(StringCchLength(lpszFileOutput, MAX_PATH, &cchOut))) return false;
	
	// 1) Wczytaj cały plik źródłowy do pamięci.
	if(!_ReadWholeFile(lpszFileInput, &Plain)) {CleanupCryptPro(); return false;}

	// 2) Przygotuj Salt (16 bajtów) zapisany razem z plikiem.
	BYTE Salt[16] = {};
	if(BCryptGenRandom(nullptr, Salt, sizeof(Salt), BCRYPT_USE_SYSTEM_PREFERRED_RNG) != 0)
		{CleanupCryptPro(); return false;}

	// 3) PBKDF2: Hash + Salt + Iteracje → Derived (Key 32B + IV 16B)
	const DWORD iterations = 100000; // Stała; można wpisać do nagłówka w przyszłości, jeśli zamienialna.


	status = BCryptOpenAlgorithmProvider(&hKdf, BCRYPT_PBKDF2_ALGORITHM, MS_PRIMITIVE_PROVIDER, 0);
	if(status != 0) {CleanupCryptPro(); return false;}

	status = BCryptDeriveKeyPBKDF2(hKdf, (PUCHAR)Hash.pbData, Hash.cbDataLength, Salt,
		(ULONG)sizeof(Salt), iterations, derived, (ULONG)sizeof(derived), 0);
	BCryptCloseAlgorithmProvider(hKdf, 0); hKdf = nullptr;
	if(status != 0) {CleanupCryptPro(); return false;}

	BYTE *pKey = derived;        // 32B
	BYTE *pIV  = derived + 32;   // 16B

	// 4) Przygotuj AES-256 CBC.
	status = BCryptOpenAlgorithmProvider(&hAes, BCRYPT_AES_ALGORITHM, MS_PRIMITIVE_PROVIDER, 0);
	if (status != 0) {CleanupCryptPro(); return false;}

	// Ustaw tryb CBC (zalecany klasyczny blokowy z paddingiem).
	status = BCryptSetProperty(hAes, BCRYPT_CHAINING_MODE, (PUCHAR)BCRYPT_CHAIN_MODE_CBC,
		(ULONG)sizeof(BCRYPT_CHAIN_MODE_CBC), 0);
	if (status != 0) {CleanupCryptPro(); return false;}

	// Utworzenie klucza symetrycznego z pKey (32B dla AES-256)
	status = BCryptGenerateSymmetricKey(hAes, &hKey, nullptr, 0, pKey, 32, 0);
		if (status != 0) {CleanupCryptPro(); return false;}

	// 5) Wyznacz rozmiar ciphertext (z paddingiem).
	DWORD cbCipher = 0;
	status = BCryptEncrypt(hKey, (PUCHAR)Plain.pbData, Plain.cbDataLength, nullptr, pIV, 16,
		nullptr, 0, &cbCipher, BCRYPT_BLOCK_PADDING);
	if (status != 0 || cbCipher == 0) {CleanupCryptPro(); return false;}

	// 6) Alokuj bufor na [Salt + Ciphertext]
	//    Zapisujemy Salt (16B) przed ciphertext – minimalny, bezpieczny nagłówek.
	DWORD cbOutputTotal = static_cast<DWORD>(sizeof(Salt)) + cbCipher;
	pOutput = static_cast<BYTE*>(HeapAlloc(GetProcessHeap(), 0, cbOutputTotal));
	if (!pOutput) {CleanupCryptPro(); return false;}

	// 7) Skopiuj Salt do wyjścia.
	memcpy(pOutput, Salt, sizeof(Salt));

	// 8) Wykonaj szyfrowanie do bufora wyjściowego (za Salt)
	DWORD cbWritten = 0;
	status = BCryptEncrypt(hKey, (PUCHAR)Plain.pbData, Plain.cbDataLength, nullptr, pIV,
		16, pOutput + sizeof(Salt), cbCipher, &cbWritten, BCRYPT_BLOCK_PADDING);
	if (status != 0 || cbWritten != cbCipher) {CleanupCryptPro(); return false;}

	// 9) Zapisz [Salt + Ciphertext] do pliku wyjściowego.
	if(!_WriteWholeFile(lpszFileOutput, pOutput, cbOutputTotal)) {CleanupCryptPro(); return false;}

	bResult = true;
	return bResult;
}
//---------------------------------------------------------------------------
//============================== METODY POMOCNICZE ==========================
__fastcall TCHAR *GsAESFunEncodeBase64(LPCWSTR pszPassword)
/**
	OPIS METOD(FUNKCJI): Szyfrowanie tekstu za pomocą Base64.
	OPIS ARGUMENTÓW: [in] - LPCWSTR pszPassword-Tekst do zakodowania.
	OPIS ZMIENNYCH:
	UWAGI: Bufor wynikowy, pszOut należy zwolnić przez HeapFree(GetProcessHeap(),0,pszOut).
*/
{
	TCHAR *pszOut=nullptr;
	DWORD cchOut=0;
	int cbUtf8;
	BYTE* pbUtf8=nullptr;

	auto CleanupCryptBase64 = [&]()
	/**
		OPIS METOD(FUNKCJI): Funkcja zwalniająca zarezerwowane zasoby podczas błędu
												 lub zakończenia nadrzędnej funkcji typu lambda
	*/
	{
		if(pbUtf8) {HeapFree(GetProcessHeap(), 0, pbUtf8); pbUtf8 = nullptr;}
	};

	// Konwersja do UTF-8 bajtów
	cbUtf8 = WideCharToMultiByte(CP_UTF8, 0, pszPassword, -1, nullptr, 0, nullptr, nullptr);
	pbUtf8 = static_cast<BYTE*>(HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, cbUtf8));
	if(!pbUtf8) {CleanupCryptBase64(); return nullptr;}
	WideCharToMultiByte(CP_UTF8, 0, pszPassword, -1, reinterpret_cast<LPSTR>(pbUtf8), cbUtf8, nullptr, nullptr);
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
__fastcall bool GsAESFunDecodeBase64(LPCWSTR pszPasswordBase64, TCHAR *pszOut, DWORD OutSize)
/**
	OPIS METOD(FUNKCJI): Odszyfrowanie tekstu za pomocą Base64.
	OPIS ARGUMENTÓW: [in]LPCWSTR pszPasswordBase64 - Zakodowany ciąg.
					 [out]TCHAR *pszOut-Wskażnik na zdekodowane hasło.
					 [in]DWORD OutSize-Wielkość pszOut.
	OPIS ZMIENNYCH:
*/
{
	DWORD cbBinary=0, dwSkip=0, dwFlags=0;
	BYTE *pbData=nullptr;

	auto CleanupDecryptBase64 = [&]()
	/**
		OPIS METOD(FUNKCJI): Funkcja zwalniająca zarezerwowane zasoby podczas błędu
												 lub zakończenia nadrzędnej funkcji typu lambda
	*/
	{
		if(pbData) {HeapFree(GetProcessHeap(), 0, pbData); pbData = nullptr;}
	};

	// Najpierw sprawdzamy wymaganą długość bufora.
	if (!CryptStringToBinary(pszPasswordBase64, 0, CRYPT_STRING_BASE64, nullptr,&cbBinary,
		&dwSkip, &dwFlags)) return false;
	// Alokujemy bufor
	pbData = static_cast<BYTE*>(HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, cbBinary));
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
//=========================== METODY PRYWATNE POMOCNICZE ====================
__fastcall bool _ReadWholeFile(LPCWSTR lpszFilePath, AESResult *pOut)
/**
	OPIS METOD(FUNKCJI): Wczytanie całego pliku do bufora (HeapAlloc)
	OPIS ARGUMENTÓW:
	OPIS ZMIENNYCH:
	OPIS WYNIKU METODY(FUNKCJI): Zwraca true w przypadku sukcesu, false w przypadku błędu.
	UWAGI:
*/
{
	BOOL bResult=false;
	HANDLE hFile=INVALID_HANDLE_VALUE;
	LARGE_INTEGER liSizeInput;
	LARGE_INTEGER liSize;
	BYTE* pBuf=nullptr;

	if (!lpszFilePath || !pOut) return false;

	auto CleanupRead = [&]()
	/**
		OPIS METOD(FUNKCJI): Funkcja zwalniająca zarezerwowane zasoby podczas błędu
												 lub zakończenia nadrzędnej funkcji typu lambda
	*/
	{
		if(hFile) {CloseHandle(hFile); hFile = INVALID_HANDLE_VALUE;}
		if(pBuf) {HeapFree(GetProcessHeap(), 0, pBuf); pBuf = nullptr;}
	};

	hFile = CreateFile(lpszFilePath, GENERIC_READ, FILE_SHARE_READ,
		nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
	if(hFile == INVALID_HANDLE_VALUE) {CleanupRead(); return false;}

	if(!GetFileSizeEx(hFile, &liSizeInput)) {CleanupRead(); return false;}

	// Ograniczenie: plik musi zmieścić się w DWORD.
	if(liSizeInput.QuadPart <= 0 || liSizeInput.QuadPart > 0xFFFFFFFFULL) {{CleanupRead(); return false;}}

	const DWORD cbSize = static_cast<DWORD>(liSize.QuadPart);
	pBuf = static_cast<BYTE*>(HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, cbSize));
	if(!pBuf) {CleanupRead(); return false;}

	DWORD cbRead = 0;
	if(!ReadFile(hFile, pBuf, cbSize, &cbRead, nullptr) || cbRead != cbSize)
		{CleanupRead(); return false;}

	pOut->pbData = pBuf;
	pOut->cbDataLength = cbSize;
	bResult = true;

	return bResult;
}
//---------------------------------------------------------------------------
__fastcall bool _WriteWholeFile(LPCWSTR lpszFilePath, const BYTE* pData, DWORD cbData)
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

	if (!lpszFilePath || !pData || cbData) return false;

	auto CleanupWrite = [&]()
	/**
		OPIS METOD(FUNKCJI): Funkcja zwalniająca zarezerwowane zasoby podczas błędu
												 lub zakończenia nadrzędnej funkcji typu lambda
	*/
	{if(hFile) {CloseHandle(hFile); hFile = INVALID_HANDLE_VALUE;}};

	hFile = CreateFile(lpszFilePath, GENERIC_WRITE, 0, nullptr,
		CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
	if(hFile == INVALID_HANDLE_VALUE) {CleanupWrite(); return false;}

	DWORD cbWritten = 0;
	if(!WriteFile(hFile, pData, cbData, &cbWritten, NULL) && cbWritten == cbData)
		{CleanupWrite(); return false;}

	bResult = true;
	return bResult;
}
//-------------------------------------------------------------------------