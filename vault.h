#pragma once

#include <cstdint>
#include <filesystem>
#include <string>
#include <vector>

// ---- On-disk vault.db header (fixed 240 bytes) ----

#pragma pack(push, 1)
struct VaultHeader
{
    char          magic[8];        // "ECHOVLT\0"
    uint32_t      version;         // 1
    uint32_t      iterations;      // 100 000

    unsigned char salt[32];        // PBKDF2 salt for password ops
    unsigned char pwHash[32];      // Password verification hash

    unsigned char encKey[64];      // IV(16) + AES(masterKey)(48) — password-derived
    unsigned char recSalt[32];     // PBKDF2 salt for recovery key
    unsigned char encKeyRec[64];   // IV(16) + AES(masterKey)(48) — recovery-derived
};
#pragma pack(pop)

static_assert(sizeof(VaultHeader) == 240, "VaultHeader must be exactly 240 bytes");

// ---- Vault paths ----

std::filesystem::path GetVaultDirectory();
std::filesystem::path GetVaultDBPath();

// ---- First-run / config ----

bool IsFirstRun();

bool FirstRunWizard();

bool SaveVaultHeader(const VaultHeader& header);
bool LoadVaultHeader(VaultHeader& header);
bool ValidateVaultHeader(const VaultHeader& header);

// Master password change and File password change
bool ChangeMasterPassword(VaultHeader& hdr, const std::vector<unsigned char>& masterKey);
bool ChangeFilePassword(const std::filesystem::path& target);

std::vector<unsigned char> GetMasterKeyOnDemand();

// ---- File / folder encryption ----

// Helper to detect if a file is already encrypted by checking the "EVF2" magic bytes.
bool IsEncrypted(const std::filesystem::path& target);

// Encrypts a single file or every file inside a folder (recursively) IN-PLACE.
// It retains the original file extension.
bool EncryptTarget(const std::filesystem::path& target);

// Decrypts a single file or every file inside a folder (recursively) IN-PLACE.
// Decryption is PERMANENT: the file stays plain until it is encrypted again.
// `showResult` controls the success confirmation box (the double-click flow
// suppresses it to avoid a redundant extra dialog).
// Returns false if decryption failed.
bool DecryptTarget(const std::filesystem::path& target, bool showResult = true);

// ---- Temporary unlock (auto re-lock on close) ----

// Everything needed to re-encrypt a file back to EVF2 with the SAME
// password: the original header fields plus the recovered file key.
struct UnlockResult
{
    bool success = false;
    std::vector<unsigned char> salt;
    std::vector<unsigned char> encKeyByPw;
    std::vector<unsigned char> encKeyByMaster;
    std::vector<unsigned char> fileKey;
};

// Prompts for the file's password (or Master Password), decrypts the file
// IN-PLACE, and returns the info needed to re-lock it. On cancel or any
// failure returns success=false and leaves the file untouched.
UnlockResult UnlockFileForOpen(const std::filesystem::path& target);

// Re-encrypts a plain file back into EVF2 using the ORIGINAL header, so
// the file keeps its existing password. No-op (returns true) if the file
// is already encrypted. Returns false if the file is locked or writing fails.
bool RelockFile(const std::filesystem::path& target, const UnlockResult& unlock);

// ---- Headless self-test (EchoVault.exe --selftest) ----

// Exercises the file-format layer with no UI: encrypt/decrypt round-trip,
// re-lock, recovery from a damaged signature (leading magic / salt edited),
// and refusal when both header copies are destroyed. Returns 0 on success,
// non-zero if any check failed; writes a log next to vault.db.
int RunSelfTest();