#pragma once

#include <string>
#include <vector>

// Generate cryptographically secure random bytes using BCryptGenRandom.
std::vector<unsigned char> GenerateRandomBytes(size_t count);

// Hash a password with PBKDF2-HMAC-SHA256 (for verification storage).
// Uses "verify" domain-separation suffix on the salt.
std::vector<unsigned char> HashPassword(
    const std::wstring& password,
    const std::vector<unsigned char>& salt
);

// Constant-time comparison of password hash against stored hash.
bool VerifyPassword(
    const std::wstring& password,
    const std::vector<unsigned char>& salt,
    const std::vector<unsigned char>& expectedHash
);

// Derive a 32-byte AES-256 key from a password and salt.
// Uses "encrypt" domain-separation suffix — different output than HashPassword.
std::vector<unsigned char> DeriveKey(
    const std::wstring& password,
    const std::vector<unsigned char>& salt
);

// AES-256-CBC encrypt.  Returns: IV (16 bytes) || ciphertext (with PKCS7 padding).
std::vector<unsigned char> EncryptBuffer(
    const std::vector<unsigned char>& plaintext,
    const std::vector<unsigned char>& key
);

// AES-256-CBC decrypt.  Expects: IV (16 bytes) || ciphertext.
// Returns empty vector on failure.
std::vector<unsigned char> DecryptBuffer(
    const std::vector<unsigned char>& data,
    const std::vector<unsigned char>& key
);

// Hex conversions for recovery key display / input.
std::wstring BytesToHex(const std::vector<unsigned char>& bytes);
std::vector<unsigned char> HexToBytes(const std::wstring& hex);