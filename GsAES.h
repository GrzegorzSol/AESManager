// Copyright (c) Grzegorz Sołtysik
// Nazwa projektu: AESManager
// Nazwa pliku: GsAES.h
// Data: 20.11.2025, 07:13

//
// Created by GrzegorzS on 17.10.2025.
//

#ifndef GSAES_H
#define GSAES_H
#include <windows.h>

enum enSizeSHABit {enSizeSHABit_256 = 100, enSizeSHABit_512};
enum enSizeKey {enSizeKey_128 = 128, enSizeKey_256 = 256};
//---------------------------------------------------------------------------
/// Struktura: AESResult
/// Cel:       Przechowuje wynik skrótu, lub inny (bufor + długość)
/// Uwagi:     Bufor należy zwolnić przez HeapFree po użyciu
//---------------------------------------------------------------------------
struct AESResult
{
	BYTE*  pbData; // Wskaźnik na dane
	DWORD  cbDataLength; // Długość
};

class GsAES
{
	public:
		__fastcall GsAES();
		__fastcall ~GsAES();
		//---
		static __fastcall AESResult GsAESComputeSHAHash(LPCWSTR pszText, enSizeSHABit enTypeHash=enSizeSHABit_256);
		static __fastcall bool GsAESCryptFile(const AESResult &Hash, LPCWSTR lpszFileInput, LPCWSTR lpszFileOutput, enSizeKey enAESKey);
		static __fastcall bool GsAESDecryptFile(const AESResult &Hash, LPCWSTR lpszFileInput, LPCWSTR lpszFileOutput, enSizeKey enAESKey);
		static __fastcall TCHAR *GsAESEncodeBase64(LPCWSTR pszPassword);
		static __fastcall bool GsAESDecodeBase64(LPCWSTR pszPasswordBase64, TCHAR *pszOut, DWORD OutSize);
	private:
		static __fastcall bool _GsAESGenerateKeyAndIV_128(const AESResult &Hash, AESResult &Key, AESResult &IV);
		static __fastcall bool _GsAESGenerateKeyAndIV_256(const AESResult &Hash, AESResult &Key, AESResult &IV);
};

#endif //GSAES_H