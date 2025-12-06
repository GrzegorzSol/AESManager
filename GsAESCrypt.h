// Copyright (c) Grzegorz Sołtysik
// Nazwa projektu: AESManager
// Nazwa pliku: GsAESCrypt.h
// Data: 6.12.2025, 17:41

//
// Created by GrzegorzS on 17.10.2025.
//

#ifndef GSAESCRYPT_H
#define GSAESCRYPT_H
#include <windows.h>

#ifdef __AESBASIC__
	#define GsAESCryptFile GsAESBasic::GsAESBasicCryptFile
	#define GsAESDecryptFile GsAESBasic::GsAESBasicDecryptFile
#else // #ifdef __AESBASIC__
	 #define GsAESCryptFile GsAESPro::GsAESProCryptFile
#endif //	#ifdef __AESBASIC__

enum enSizeSHABit {enSizeSHABit_256 = 100, enSizeSHABit_512};
enum enSizeKey {enSizeKey_128 = 128, enSizeKey_256 = 256};
enum enTypeProcess {enTypeProcess_Crypt = 500, enTypeProcess_Decrypt};
//---------------------------------------------------------------------------
/// Struktura: AESResult
/// Cel:			 Przechowuje wynik skrótu, lub inny (bufor + długość)
/// Uwagi:		 Bufor należy zwolnić przez HeapFree po użyciu
//---------------------------------------------------------------------------
struct AESResult
{
	BYTE*	 pbData; // Wskaźnik na dane
	DWORD	 cbDataLength; // Długość
};
//============================== METODY POMOCNICZE ==========================
extern __fastcall AESResult GsAESFunComputeSHAHash(LPCWSTR pszText, const enSizeSHABit enTypeHash=enSizeSHABit_256);
extern __fastcall TCHAR *GsAESFunEncodeBase64(LPCWSTR pszPassword);
extern __fastcall bool GsAESFunDecodeBase64(LPCWSTR pszPasswordBase64, TCHAR *pszOut, DWORD OutSize);
//---------------------------------------------------------------------------
// Klas:	GsAESBasic.
// Cel:		Proste szyfrowanie pliku z KEY i IV, ale bez Salt.
// Uwagi:	Przy niezmienionym haśle nagłówki zakodowanych plików są
//				identyczne.
//---------------------------------------------------------------------------
class GsAESBasic
{
	public:
		static __fastcall bool GsAESBasicCryptFile(const AESResult &Hash, LPCWSTR lpszFileInput, LPCWSTR lpszFileOutput, enSizeKey enAESKey);
		static __fastcall bool GsAESBasicDecryptFile(const AESResult &Hash, LPCWSTR lpszFileInput, LPCWSTR lpszFileOutput, enSizeKey enAESKey);
	private:
		static __fastcall bool _GsAESBasicGenerateKeyAndIV_128(const AESResult &Hash, AESResult &Key, AESResult &IV);
		static __fastcall bool _GsAESBasicGenerateKeyAndIV_256(const AESResult &Hash, AESResult &Key, AESResult &IV);
};

//---------------------------------------------------------------------------
// Klas:	GsAESPro
// Cel:		Szyfrowanie pliku z KEY, IV i Salt.
// Uwagi:	Każdy nagłówek zaszyfrowanego pliku jest inny.
//---------------------------------------------------------------------------
class GsAESPro
{
	public:
		static __fastcall bool GsAESProCryptFile(const AESResult &Hash, LPCWSTR lpszFileInput, LPCWSTR lpszFileOutput, enSizeKey enAESKey);
	private:

};

#endif //GSAESCRYPT_H