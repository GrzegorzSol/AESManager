// Copyright (c) Grzegorz Sołtysik
// Nazwa projektu: AESManager
// Nazwa pliku: GsAESCrypt.h
// Data: 1.01.2026, 06:04

//
// Created by GrzegorzS on 17.10.2025.
//

#ifndef GSAESCRYPT_H
#define GSAESCRYPT_H

#include <windows.h>
#include "GsWinLibrary.h"

enum enSizeSHABit {enSizeSHABit_256 = 100, enSizeSHABit_512};
enum enSizeKey {enSizeKey_128 = 128, enSizeKey_256 = 256};
enum enTypeProcess {enTypeProcess_Crypt = 500, enTypeProcess_Decrypt};
// Stałe
constexpr int CI_SIZEIV=16, // Wielkość IV
							CI_SIZEHMAC=32, // Wielkość HMAC
							CI_SIZESALT=16, // Wielkość Salt
							CI_KEYLEN_128 = 16, CI_KEYLEN_256 = 32; // enSizeKey_128->CI_KEYLEN_128, enSizeKey_256->CI_KEYLEN_256
constexpr ULONGLONG CUL_ITERATIONS=100000; // Stała; można wpisać do nagłówka w przyszłości, jeśli zamienialna.
// Typy szyfrowania AES
enum enListTypeAES {enListTypeAES_CBC_HMAC, enListTypeAES_GCM_TAG, enListTypeAES_Count};
inline LPCWSTR GS_StringListAESTypes[] = {TEXT("AES-CBC+HMAC"), TEXT("AES-GCM+TAG")};
// Struktura nagłówka pliku zaszyfrowanego -> w konstrukcji
constexpr BYTE CPB_VERSIONCRYPTBASIC = 0x00, CPB_VERSIONCRYPTPROFF_CBC = 0x10, CPB_VERSIONCRYPTPROFF_GCM = 0x11;
struct GsAESHeader
{
	BYTE Magic[4] = {'G', 'C', 'R', 'P'}; //"Magiczny" identyfikator.
	BYTE Version = 0;	 										// 0x00 - proste
																				// 0x10 - zaawansowane AES-CBC+HMAC.
																				// 0x11 - zaawansowane AES-GCM+TAG
	BYTE BSizeKey = CI_KEYLEN_256;				// Wielkość klucza w bajtach
	BYTE bReserved[2] = {0, 0}; // Na przyszłość
};
//============================== METODY POMOCNICZE ==========================
extern __fastcall GsStoreData GsAESFunComputeSHAHash(LPCWSTR lpcszText, const enSizeSHABit enTypeHash=enSizeSHABit_256);
extern __fastcall TCHAR *GsAESFunEncodeBase64(LPCWSTR lpcszPassword);
extern __fastcall bool GsAESFunDecodeBase64(LPCWSTR lpcszPasswordBase64, TCHAR *pszOut, const DWORD cDOutSize);
//---------------------------------------------------------------------------
// Klasa:	GsAESBasic.
// Cel:		Proste szyfrowanie pliku z KEY i IV, ale bez Salt.
// Uwagi:	Przy niezmienionym haśle nagłówki zakodowanych plików są
//				identyczne.
//---------------------------------------------------------------------------
class GsAESBasic
{
	public:
		static __fastcall bool GsAESBasicCryptFile(const GsStoreData &gsHash, LPCWSTR lpcszFileInput, LPCWSTR lpcszFileOutput, const enSizeKey enAESKey);
		static __fastcall bool GsAESBasicDecryptFile(const GsStoreData &gsHash, LPCWSTR lpcszFileInput, LPCWSTR lpcszFileOutput, const enSizeKey enAESKey);
	private:
		static __fastcall bool _GsAESBasicGenerateKeyAndIV_128(const GsStoreData &gsHash, GsStoreData &gsKey, GsStoreData &gsIV);
		static __fastcall bool _GsAESBasicGenerateKeyAndIV_256(const GsStoreData &gsHash, GsStoreData &gsKey, GsStoreData &gsIV);
};

//---------------------------------------------------------------------------
// Klas:	GsAESPro
// Cel:		Szyfrowanie pliku z KEY, IV i Salt.
// Uwagi:	Każdy nagłówek zaszyfrowanego pliku jest inny.
//---------------------------------------------------------------------------
class GsAESPro
{
	public:
		// Szyfrowanie i deszyfrowanie metodą AES-CBC+HMAC
		static __fastcall bool GsAESPro_CBC_HMAC_CryptFile(const GsStoreData &gsHash, LPCWSTR lpcszFileInput, LPCWSTR lpcszFileOutput, const enSizeKey enAESKey);
		static __fastcall bool GsAESPro_CBC_HMAC_DecryptFile(const GsStoreData &gsHash, LPCWSTR lpcszFileInput, LPCWSTR lpcszFileOutput, const enSizeKey enAESKey);
		// Szyfrowanie i deszyfrowanie metodą AES-GCM+TAG
		static __fastcall bool GsAESPro_GCM_TAG_CryptFile(const GsStoreData &gsHash, LPCWSTR lpcszFileInput, LPCWSTR lpcszFileOutput, const enSizeKey enAESKey);
		static __fastcall bool GsAESPro_GCM_TAG_DecryptFile(const GsStoreData &gsHash, LPCWSTR lpcszFileInput, LPCWSTR lpcszFileOutput, const enSizeKey enAESKey);
	private:
		static __fastcall bool _GsAESProComputeHMAC(const BYTE *pBKey, const DWORD DKeyLen, const BYTE *pcBData, const DWORD cDDataLen,
				BYTE *pBhmacOut, DWORD cbHmacOut=32);
};

#endif //GSAESCRYPT_H