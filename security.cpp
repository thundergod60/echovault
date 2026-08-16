//------------------------------------------------------------
// security.cpp  —  Cryptographic primitives via Windows CNG
//------------------------------------------------------------

#include "security.h"

#include <windows.h>
#include <bcrypt.h>
#include <algorithm>

// MinGW may not define NT_SUCCESS
#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#endif

static const ULONG     PBKDF2_ITERATIONS = 100000;
static const size_t    KEY_SIZE           = 32;
static const size_t    HASH_SIZE          = 32;
static const size_t    IV_SIZE            = 16;

//------------------------------------------------------------
// Random bytes
//------------------------------------------------------------

std::vector<unsigned char> GenerateRandomBytes(size_t count)
{
    std::vector<unsigned char> buf(count);
    NTSTATUS st = BCryptGenRandom(
        nullptr, buf.data(), static_cast<ULONG>(count),
        BCRYPT_USE_SYSTEM_PREFERRED_RNG);
    if (!NT_SUCCESS(st))
        return {};
    return buf;
}

//------------------------------------------------------------
// Internal PBKDF2-HMAC-SHA256 helper
//------------------------------------------------------------

static std::vector<unsigned char> PBKDF2(
    const unsigned char* pw,   size_t pwLen,
    const unsigned char* salt, size_t saltLen,
    ULONGLONG iterations,
    size_t    keyLen)
{
    BCRYPT_ALG_HANDLE hAlg = nullptr;
    NTSTATUS st = BCryptOpenAlgorithmProvider(
        &hAlg, BCRYPT_SHA256_ALGORITHM, nullptr,
        BCRYPT_ALG_HANDLE_HMAC_FLAG);
    if (!NT_SUCCESS(st)) return {};

    std::vector<unsigned char> derived(keyLen);
    st = BCryptDeriveKeyPBKDF2(
        hAlg,
        const_cast<PUCHAR>(pw),   static_cast<ULONG>(pwLen),
        const_cast<PUCHAR>(salt), static_cast<ULONG>(saltLen),
        iterations,
        derived.data(), static_cast<ULONG>(keyLen),
        0);

    BCryptCloseAlgorithmProvider(hAlg, 0);
    if (!NT_SUCCESS(st)) return {};
    return derived;
}

//------------------------------------------------------------
// Password hashing  (domain-separated: "verify")
//------------------------------------------------------------

std::vector<unsigned char> HashPassword(
    const std::wstring& password,
    const std::vector<unsigned char>& salt)
{
    // Domain-separate by appending "verify" to the salt
    std::vector<unsigned char> extSalt(salt);
    const char tag[] = "verify";
    extSalt.insert(extSalt.end(), tag, tag + 6);

    auto pwBytes = reinterpret_cast<const unsigned char*>(password.data());
    size_t pwLen = password.size() * sizeof(wchar_t);

    return PBKDF2(pwBytes, pwLen,
                  extSalt.data(), extSalt.size(),
                  PBKDF2_ITERATIONS, HASH_SIZE);
}

bool VerifyPassword(
    const std::wstring& password,
    const std::vector<unsigned char>& salt,
    const std::vector<unsigned char>& expectedHash)
{
    auto hash = HashPassword(password, salt);
    if (hash.size() != expectedHash.size()) return false;

    // Constant-time comparison
    unsigned char diff = 0;
    for (size_t i = 0; i < hash.size(); i++)
        diff |= hash[i] ^ expectedHash[i];
    return diff == 0;
}

//------------------------------------------------------------
// Key derivation  (domain-separated: "encrypt")
//------------------------------------------------------------

std::vector<unsigned char> DeriveKey(
    const std::wstring& password,
    const std::vector<unsigned char>& salt)
{
    std::vector<unsigned char> extSalt(salt);
    const char tag[] = "encrypt";
    extSalt.insert(extSalt.end(), tag, tag + 7);

    auto pwBytes = reinterpret_cast<const unsigned char*>(password.data());
    size_t pwLen = password.size() * sizeof(wchar_t);

    return PBKDF2(pwBytes, pwLen,
                  extSalt.data(), extSalt.size(),
                  PBKDF2_ITERATIONS, KEY_SIZE);
}

//------------------------------------------------------------
// AES-256-CBC  encrypt
//------------------------------------------------------------

std::vector<unsigned char> EncryptBuffer(
    const std::vector<unsigned char>& plaintext,
    const std::vector<unsigned char>& key)
{
    if (key.size() != KEY_SIZE) return {};

    BCRYPT_ALG_HANDLE hAlg = nullptr;
    BCRYPT_KEY_HANDLE hKey = nullptr;

    if (!NT_SUCCESS(BCryptOpenAlgorithmProvider(
            &hAlg, BCRYPT_AES_ALGORITHM, nullptr, 0)))
        return {};

    if (!NT_SUCCESS(BCryptSetProperty(
            hAlg, BCRYPT_CHAINING_MODE,
            (PUCHAR)BCRYPT_CHAIN_MODE_CBC,
            sizeof(BCRYPT_CHAIN_MODE_CBC), 0)))
    {
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return {};
    }

    if (!NT_SUCCESS(BCryptGenerateSymmetricKey(
            hAlg, &hKey, nullptr, 0,
            const_cast<PUCHAR>(key.data()),
            static_cast<ULONG>(key.size()), 0)))
    {
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return {};
    }

    // Random IV
    auto iv = GenerateRandomBytes(IV_SIZE);
    if (iv.empty()) {
        BCryptDestroyKey(hKey);
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return {};
    }

    // --- First call: query output size ---
    auto ivTmp = iv;
    ULONG ctLen = 0;
    BCryptEncrypt(hKey,
        const_cast<PUCHAR>(plaintext.data()),
        static_cast<ULONG>(plaintext.size()),
        nullptr,
        ivTmp.data(), static_cast<ULONG>(ivTmp.size()),
        nullptr, 0, &ctLen, BCRYPT_BLOCK_PADDING);

    // --- Second call: encrypt ---
    std::vector<unsigned char> ct(ctLen);
    ivTmp = iv;                                 // reset IV
    NTSTATUS st = BCryptEncrypt(hKey,
        const_cast<PUCHAR>(plaintext.data()),
        static_cast<ULONG>(plaintext.size()),
        nullptr,
        ivTmp.data(), static_cast<ULONG>(ivTmp.size()),
        ct.data(), ctLen, &ctLen, BCRYPT_BLOCK_PADDING);

    BCryptDestroyKey(hKey);
    BCryptCloseAlgorithmProvider(hAlg, 0);

    if (!NT_SUCCESS(st)) return {};

    // Return  IV || ciphertext
    std::vector<unsigned char> result;
    result.reserve(IV_SIZE + ctLen);
    result.insert(result.end(), iv.begin(), iv.end());
    result.insert(result.end(), ct.begin(), ct.begin() + ctLen);
    return result;
}

//------------------------------------------------------------
// AES-256-CBC  decrypt
//------------------------------------------------------------

std::vector<unsigned char> DecryptBuffer(
    const std::vector<unsigned char>& data,
    const std::vector<unsigned char>& key)
{
    if (key.size() != KEY_SIZE || data.size() <= IV_SIZE) return {};

    BCRYPT_ALG_HANDLE hAlg = nullptr;
    BCRYPT_KEY_HANDLE hKey = nullptr;

    if (!NT_SUCCESS(BCryptOpenAlgorithmProvider(
            &hAlg, BCRYPT_AES_ALGORITHM, nullptr, 0)))
        return {};

    if (!NT_SUCCESS(BCryptSetProperty(
            hAlg, BCRYPT_CHAINING_MODE,
            (PUCHAR)BCRYPT_CHAIN_MODE_CBC,
            sizeof(BCRYPT_CHAIN_MODE_CBC), 0)))
    {
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return {};
    }

    if (!NT_SUCCESS(BCryptGenerateSymmetricKey(
            hAlg, &hKey, nullptr, 0,
            const_cast<PUCHAR>(key.data()),
            static_cast<ULONG>(key.size()), 0)))
    {
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return {};
    }

    // Split IV and ciphertext
    std::vector<unsigned char> iv(data.begin(), data.begin() + IV_SIZE);
    ULONG ctLen = static_cast<ULONG>(data.size() - IV_SIZE);

    // --- First call: query output size ---
    auto ivTmp = iv;
    ULONG ptLen = 0;
    BCryptDecrypt(hKey,
        const_cast<PUCHAR>(data.data() + IV_SIZE), ctLen,
        nullptr,
        ivTmp.data(), static_cast<ULONG>(ivTmp.size()),
        nullptr, 0, &ptLen, BCRYPT_BLOCK_PADDING);

    // --- Second call: decrypt ---
    std::vector<unsigned char> pt(ptLen);
    ivTmp = iv;
    NTSTATUS st = BCryptDecrypt(hKey,
        const_cast<PUCHAR>(data.data() + IV_SIZE), ctLen,
        nullptr,
        ivTmp.data(), static_cast<ULONG>(ivTmp.size()),
        pt.data(), ptLen, &ptLen, BCRYPT_BLOCK_PADDING);

    BCryptDestroyKey(hKey);
    BCryptCloseAlgorithmProvider(hAlg, 0);

    if (!NT_SUCCESS(st)) return {};

    pt.resize(ptLen);
    return pt;
}

//------------------------------------------------------------
// Hex helpers
//------------------------------------------------------------

std::wstring BytesToHex(const std::vector<unsigned char>& bytes)
{
    static const wchar_t hex[] = L"0123456789ABCDEF";
    std::wstring out;
    out.reserve(bytes.size() * 2);
    for (auto b : bytes) {
        out += hex[b >> 4];
        out += hex[b & 0x0F];
    }
    return out;
}

std::vector<unsigned char> HexToBytes(const std::wstring& hex)
{
    if (hex.size() % 2 != 0) return {};

    std::vector<unsigned char> out;
    out.reserve(hex.size() / 2);

    for (size_t i = 0; i < hex.size(); i += 2) {
        auto nibble = [](wchar_t c) -> int {
            if (c >= L'0' && c <= L'9') return c - L'0';
            if (c >= L'A' && c <= L'F') return c - L'A' + 10;
            if (c >= L'a' && c <= L'f') return c - L'a' + 10;
            return -1;
        };
        int hi = nibble(hex[i]);
        int lo = nibble(hex[i + 1]);
        if (hi < 0 || lo < 0) return {};
        out.push_back(static_cast<unsigned char>((hi << 4) | lo));
    }
    return out;
}
