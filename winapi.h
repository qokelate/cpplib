

#ifndef _winapi_H_
#define _winapi_H_

#include <windows.h>
#include <wincrypt.h>


#pragma comment(lib, "crypt32.lib")


//Returns the last Win32 error, in string format. Returns an empty string if there is no error.
std::string GetLastErrorAsString()
{
    //Get the error message ID, if any.
    DWORD errorMessageID = ::GetLastError();
    if (errorMessageID == 0) {
        return std::string(); //No error message has been recorded
    }

    LPSTR messageBuffer = nullptr;

    //Ask Win32 to give us the string version of that message ID.
    //The parameters we pass in, tell Win32 to create the buffer that holds the message for us (because we don't yet know how long the message string will be).
    size_t size = FormatMessageA(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
        NULL, errorMessageID, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), (LPSTR)&messageBuffer, 0, NULL);

    //Copy the error message into a std::string.
    std::string message(messageBuffer, size);

    //Free the Win32's string's buffer.
    LocalFree(messageBuffer);

    return message;
}

std::string sign(const void *data, int datalen, const char *rsa_privatekey_pem)
{
    std::string s;

    DWORD dwBufferLen = 0, cbKeyBlob = 0, cbSignature = 0;
    LPBYTE pbBuffer = NULL, pbKeyBlob = NULL, pbSignature = NULL;
    HCRYPTPROV hProv = NULL;
    HCRYPTKEY hKey = NULL;
    HCRYPTHASH hHash = NULL;

    const char *szPemPrivKey = rsa_privatekey_pem;

    if (!CryptStringToBinaryA(szPemPrivKey, 0, CRYPT_STRING_BASE64HEADER, NULL, &dwBufferLen, NULL, NULL))
    {
        printf("Failed to convert BASE64 private key. Error 0x%.8X\n", GetLastError());
        goto main_exit;
    }

    pbBuffer = (LPBYTE)LocalAlloc(0, dwBufferLen);
    if (!pbBuffer)
    {
        printf("Failed to allocate memory %u bytes. Error 0x%.8X\n", dwBufferLen, GetLastError());
        goto main_exit;
    }

    if (!CryptStringToBinaryA(szPemPrivKey, 0, CRYPT_STRING_BASE64HEADER, pbBuffer, &dwBufferLen, NULL, NULL))
    {
        printf("Failed to convert BASE64 private key. Error 0x%.8X\n", GetLastError());
        goto main_exit;
    }

    if (!CryptDecodeObjectEx(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, PKCS_RSA_PRIVATE_KEY, pbBuffer, dwBufferLen, 0, NULL, NULL, &cbKeyBlob))
    {
        printf("Failed to parse private key. Error 0x%.8X\n", GetLastError());
        goto main_exit;
    }

    pbKeyBlob = (LPBYTE)LocalAlloc(0, cbKeyBlob);
    if (!pbKeyBlob)
    {
        printf("Failed to allocate memory %u bytes. Error 0x%.8X\n", cbKeyBlob, GetLastError());
        goto main_exit;
    }

    if (!CryptDecodeObjectEx(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, PKCS_RSA_PRIVATE_KEY, pbBuffer, dwBufferLen, 0, NULL, pbKeyBlob, &cbKeyBlob))
    {
        printf("Failed to parse private key. Error 0x%.8X\n", GetLastError());
        goto main_exit;
    }

    // Create a temporary and volatile CSP context in order to import
    // the key and use for signing
    if (!CryptAcquireContext(&hProv, NULL, MS_ENHANCED_PROV, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT))
    {
        printf("CryptAcquireContext failed with error 0x%.8X\n", GetLastError());
        goto main_exit;
    }

    if (!CryptImportKey(hProv, pbKeyBlob, cbKeyBlob, NULL, 0, &hKey))
    {
        printf("CryptImportKey for private key failed with error 0x%.8X\n", GetLastError());
        goto main_exit;
    }

    // Hash the data
    if (!CryptCreateHash(hProv, CALG_SHA1, NULL, 0, &hHash))
    {
        printf("CryptCreateHash failed with error 0x%.8X\n", GetLastError());
        goto main_exit;
    }

    if (!CryptHashData(hHash, (LPCBYTE)data, datalen, 0))
    {
        printf("CryptHashData failed with error 0x%.8X\n", GetLastError());
        goto main_exit;
    }

    // Sign the hash using our imported key
    if (!CryptSignHash(hHash, AT_KEYEXCHANGE, NULL, 0, NULL, &cbSignature))
    {
        printf("CryptSignHash failed with error 0x%.8X\n", GetLastError());
        goto main_exit;
    }

    pbSignature = (LPBYTE)LocalAlloc(0, cbSignature);
    if (!CryptSignHash(hHash, AT_KEYEXCHANGE, NULL, 0, pbSignature, &cbSignature))
    {
        printf("CryptSignHash failed with error 0x%.8X\n", GetLastError());
        goto main_exit;
    }

    s.assign((char *)pbSignature, cbSignature);

main_exit:
    if (pbBuffer) LocalFree(pbBuffer);
    if (pbKeyBlob) LocalFree(pbKeyBlob);
    if (pbSignature) LocalFree(pbSignature);
    if (hHash) CryptDestroyHash(hHash);
    if (hKey) CryptDestroyKey(hKey);
    if (hProv) CryptReleaseContext(hProv, 0);

    return s;
}

bool verify(const void* data, int datalen, const void* sig, int siglen, const char* rsa_publickey_pem)
{
    bool s = false;
    DWORD dwBufferLen = 0, cbKeyBlob = 0, cbSignature = 0;
    LPBYTE pbBuffer = NULL, pbKeyBlob = NULL, pbSignature = NULL;
    HCRYPTPROV hProv = NULL;
    HCRYPTKEY hKey = NULL;
    HCRYPTHASH hHash = NULL;

    pbSignature = (LPBYTE)sig;
    cbSignature = siglen;

    const char *szPemPubKey = rsa_publickey_pem;


    /***************************************************
     * Import the public key and verify the signature
     ***************************************************/

    if (!CryptStringToBinaryA(szPemPubKey, 0, CRYPT_STRING_BASE64HEADER, NULL, &dwBufferLen, NULL, NULL))
    {
        printf("Failed to convert BASE64 public key. Error 0x%.8X\n", GetLastError());
        goto main_exit;
    }

    LocalFree(pbBuffer);
    pbBuffer = (LPBYTE)LocalAlloc(0, dwBufferLen);
    if (!pbBuffer)
    {
        printf("Failed to allocate memory %u bytes. Error 0x%.8X\n", dwBufferLen, GetLastError());
        goto main_exit;
    }

    if (!CryptStringToBinaryA(szPemPubKey, 0, CRYPT_STRING_BASE64HEADER, pbBuffer, &dwBufferLen, NULL, NULL))
    {
        printf("Failed to convert BASE64 public key. Error 0x%.8X\n", GetLastError());
        goto main_exit;
    }

    if (!CryptDecodeObjectEx(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, RSA_CSP_PUBLICKEYBLOB, pbBuffer, dwBufferLen, 0, NULL, NULL, &cbKeyBlob))
    {
        printf("Failed to parse public key. Error 0x%.8X\n", GetLastError());
        goto main_exit;
    }

    LocalFree(pbKeyBlob);
    pbKeyBlob = (LPBYTE)LocalAlloc(0, cbKeyBlob);
    if (!pbKeyBlob)
    {
        printf("Failed to allocate memory %u bytes. Error 0x%.8X\n", cbKeyBlob, GetLastError());
        goto main_exit;
    }

    if (!CryptDecodeObjectEx(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, RSA_CSP_PUBLICKEYBLOB, pbBuffer, dwBufferLen, 0, NULL, pbKeyBlob, &cbKeyBlob))
    {
        printf("Failed to parse public key. Error 0x%.8X\n", GetLastError());
        goto main_exit;
    }

    if (!CryptAcquireContext(&hProv, NULL, MS_ENHANCED_PROV, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT))
    {
        printf("CryptAcquireContext failed with error 0x%.8X\n", GetLastError());
        goto main_exit;
    }

    if (!CryptImportKey(hProv, pbKeyBlob, cbKeyBlob, NULL, 0, &hKey))
    {
        printf("CryptImportKey for public key failed with error 0x%.8X\n", GetLastError());
        goto main_exit;
    }

    // Hash the data
    if (!CryptCreateHash(hProv, CALG_SHA1, NULL, 0, &hHash))
    {
        printf("CryptCreateHash failed with error 0x%.8X\n", GetLastError());
        goto main_exit;
    }

    if (!CryptHashData(hHash, (LPCBYTE)data, datalen, 0))
    {
        printf("CryptHashData failed with error 0x%.8X\n", GetLastError());
        goto main_exit;
    }

    // Sign the hash using our imported key
    if (!CryptVerifySignature(hHash, pbSignature, cbSignature, hKey, NULL, 0))
    {
        printf("Signature verification failed with error 0x%.8X\n", GetLastError());
        goto main_exit;
    }

    s = true;
    printf("Signature verified successfully!\n\n");

main_exit:
    if (pbBuffer) LocalFree(pbBuffer);
    if (pbKeyBlob) LocalFree(pbKeyBlob);
    //if (pbSignature) LocalFree(pbSignature);
    if (hHash) CryptDestroyHash(hHash);
    if (hKey) CryptDestroyKey(hKey);
    if (hProv) CryptReleaseContext(hProv, 0);

    return s;
}

#endif
