//------------------------------------------------------------
// vault.cpp  —  Vault DB management + per-file encryption
//------------------------------------------------------------

#include "vault.h"
#include "security.h"
#include "ui.h"
#include "filterio.h"

#include <windows.h>
#include <filesystem>
#include <fstream>
#include <cstring>

namespace fs = std::filesystem;

// ---- Driver gate (Phase 2) --------------------------------------
// With the minifilter loaded, a locked path is DENIED to every opener —
// including EchoVault itself. So each operation allow-lists the target
// for its duration, and re-locks it when done (RAII). Best-effort and
// completely inert when the driver is not loaded.
class EvGate {
    std::wstring path_;
    bool armed_ = true;
public:
    explicit EvGate(const fs::path& p) : path_(p.wstring()) { EvAllowFor(path_); }
    ~EvGate() { if (armed_) EvDenyFor(path_); }
    // Keep the allow-list entry in place (e.g. after a temporary unlock
    // that the caller will re-lock explicitly).
    void disarm() { armed_ = false; }
};

// ---- Globals ----------------------------------------------------

static fs::path g_VaultDir;
static fs::path g_VaultDB;

// ---- Vault paths ------------------------------------------------

// Unique per-process temp path for atomic writes, so concurrent EchoVault
// processes never clobber each other's in-progress file.
static fs::path TempPathFor(const fs::path& filePath)
{
    fs::path tmp = filePath;
    tmp += L".evtmp.";
    tmp += std::to_wstring(GetCurrentProcessId());
    return tmp;
}

std::filesystem::path GetVaultDirectory()
{
    if (!g_VaultDir.empty()) return g_VaultDir;

    wchar_t buf[MAX_PATH];
    if (GetEnvironmentVariableW(L"LOCALAPPDATA", buf, MAX_PATH) == 0)
        return {};

    g_VaultDir = fs::path(buf) / L"EchoVault";
    g_VaultDB  = g_VaultDir / L"vault.db";
    return g_VaultDir;
}

std::filesystem::path GetVaultDBPath()
{
    GetVaultDirectory();
    return g_VaultDB;
}

// ---- First-run detection ----------------------------------------

bool IsFirstRun()
{
    GetVaultDirectory();
    if (g_VaultDir.empty()) return true;

    try {
        if (!fs::exists(g_VaultDir))
            fs::create_directories(g_VaultDir);
    } catch (...) {
        return true;
    }

    return !fs::exists(g_VaultDB);
}

// ---- Header I/O -------------------------------------------------

bool ValidateVaultHeader(const VaultHeader& h)
{
    return (std::memcmp(h.magic, "ECHOVLT", 8) == 0 && h.version == 1);
}

bool SaveVaultHeader(const VaultHeader& header)
{
    try {
        std::ofstream f(g_VaultDB, std::ios::binary | std::ios::trunc);
        if (!f) return false;
        f.write(reinterpret_cast<const char*>(&header), sizeof(VaultHeader));
        return f.good();
    } catch (...) {
        return false;
    }
}

bool LoadVaultHeader(VaultHeader& header)
{
    try {
        if (!fs::exists(g_VaultDB)) return false;

        auto sz = fs::file_size(g_VaultDB);
        if (sz != sizeof(VaultHeader)) return false;

        std::ifstream f(g_VaultDB, std::ios::binary);
        if (!f) return false;

        f.read(reinterpret_cast<char*>(&header), sizeof(VaultHeader));
        if (!f.good()) return false;

        return ValidateVaultHeader(header);
    } catch (...) {
        return false;
    }
}

// ---- First-run wizard -------------------------------------------

bool FirstRunWizard()
{
    ShowInfo(L"EchoVault",
        L"Welcome to EchoVault!\n\n"
        L"You'll now create a Master Password. This acts as a\n"
        L"recovery key in case you forget the password of a\n"
        L"specific encrypted file.\n\n"
        L"You will also receive a Master Recovery Key to\n"
        L"recover your Master Password if you forget it.");

    // --- Master password (with confirmation) ---
    std::wstring pw;
    for (;;)
    {
        auto a1 = PromptPassword(
            L"EchoVault \u2014 Master Password",
            L"Create your Master Password:");
        if (a1.result != PasswordResult::OK) return false;
        if (a1.password.empty()) {
            ShowError(L"EchoVault", L"Password cannot be empty.");
            continue;
        }

        auto a2 = PromptPassword(
            L"EchoVault \u2014 Confirm Password",
            L"Confirm your Master Password:");
        if (a2.result != PasswordResult::OK) return false;

        if (a1.password != a2.password) {
            ShowError(L"EchoVault", L"Passwords do not match. Try again.");
            continue;
        }
        pw = a1.password;
        break;
    }
    // --- Generate master key & recovery key ---
    auto masterKey   = GenerateRandomBytes(32);
    auto recoveryKey = GenerateRandomBytes(32);
    auto salt        = GenerateRandomBytes(32);
    auto recSalt     = GenerateRandomBytes(32);

    if (masterKey.empty() || recoveryKey.empty() ||
        salt.empty() || recSalt.empty())
    {
        ShowError(L"EchoVault",
            L"Failed to generate cryptographic material.\n"
            L"Setup cannot continue.");
        return false;
    }

    // --- Derive keys & build header ---
    auto pwHash = HashPassword(pw, salt);
    auto pwKey  = DeriveKey(pw, salt);

    std::wstring recHex = BytesToHex(recoveryKey);
    auto recKey = DeriveKey(recHex, recSalt);

    auto encMK    = EncryptBuffer(masterKey, pwKey);
    auto encMKRec = EncryptBuffer(masterKey, recKey);

    if (pwHash.empty() || pwKey.empty() || recKey.empty() ||
        encMK.size() != 64 || encMKRec.size() != 64)
    {
        ShowError(L"EchoVault",
            L"Encryption setup failed.\nSetup cannot continue.");
        return false;
    }

    VaultHeader hdr = {};
    std::memcpy(hdr.magic, "ECHOVLT", 8);
    hdr.version    = 1;
    hdr.iterations = 100000;
    std::memcpy(hdr.salt,      salt.data(),    32);
    std::memcpy(hdr.pwHash,    pwHash.data(),  32);
    std::memcpy(hdr.encKey,    encMK.data(),   64);
    std::memcpy(hdr.recSalt,   recSalt.data(), 32);
    std::memcpy(hdr.encKeyRec, encMKRec.data(),64);

    if (!SaveVaultHeader(hdr)) {
        ShowError(L"EchoVault", L"Could not write vault.db.\nSetup failed.");
        return false;
    }

    // --- Show recovery key ---
    ShowRecoveryKey(recHex);
    return true;
}

// ---- Change Master Password -------------------------------------

bool ChangeMasterPassword(VaultHeader& hdr, const std::vector<unsigned char>& masterKey)
{
    auto a0 = PromptPassword(
        L"EchoVault \u2014 Change Master Password",
        L"Enter your CURRENT Master Password:");
    
    if (a0.result != PasswordResult::OK) return false;
    std::vector<unsigned char> oldSalt(hdr.salt, hdr.salt + 32);
    if (!VerifyPassword(a0.password, oldSalt,
            std::vector<unsigned char>(hdr.pwHash, hdr.pwHash + 32)))
    {
        ShowError(L"EchoVault", L"Incorrect Master Password.");
        return false;
    }

    std::wstring newPw;
    for (;;)
    {
        auto a1 = PromptPassword(
            L"EchoVault \u2014 New Master Password",
            L"Enter your NEW Master Password:");
        if (a1.result != PasswordResult::OK) return false;
        if (a1.password.empty()) {
            ShowError(L"EchoVault", L"Password cannot be empty.");
            continue;
        }

        auto a2 = PromptPassword(
            L"EchoVault \u2014 Confirm New",
            L"Confirm your NEW Master Password:");
        if (a2.result != PasswordResult::OK) return false;

        if (a1.password != a2.password) {
            ShowError(L"EchoVault", L"Passwords do not match. Try again.");
            continue;
        }
        newPw = a1.password;
        break;
    }

    auto newSalt = GenerateRandomBytes(32);
    if (newSalt.empty()) return false;

    auto newHash = HashPassword(newPw, newSalt);
    auto newKey  = DeriveKey(newPw, newSalt);
    auto newEnc  = EncryptBuffer(masterKey, newKey);

    if (newHash.empty() || newKey.empty() || newEnc.size() != 64) {
        ShowError(L"EchoVault", L"Failed to re-encrypt with new password.");
        return false;
    }

    std::memcpy(hdr.salt,   newSalt.data(), 32);
    std::memcpy(hdr.pwHash, newHash.data(), 32);
    std::memcpy(hdr.encKey, newEnc.data(),  64);

    if (!SaveVaultHeader(hdr)) {
        ShowError(L"EchoVault", L"Failed to save updated vault.db.");
        return false;
    }

    ShowInfo(L"EchoVault", L"Master Password updated successfully!");
    SecureZeroMemory(newKey.data(), newKey.size());
    return true;
}

// ---- Resilient EVF file format ---------------------------------
//
// Every encrypted file carries the primary header at offset 0:
//     magic "EVF3"(4) + salt(32) + encKeyByPw(64) + encKeyByMaster(64)
// and a redundant TRAILER at the very end of the file:
//     magic "EVFT"(4) + salt(32) + encKeyByPw(64) + encKeyByMaster(64)
//     + crcPrimary(4) + crcTrailer(4)
// The trailer is a backup of the decryption-critical header fields plus
// CRC32 checksums, so accidentally deleting/editing the leading signature
// (or the primary header) no longer destroys the file: EchoVault detects
// the file via the trailer and recovers with it. The trailing region is
// always reserved for the trailer in EVF3 files, so a damaged trailer
// magic can never be mistaken for content. Files written by older builds
// ("EVF2", no trailer) are still read fine (the primary header is trusted
// on its own). Only if BOTH header copies are destroyed is the file
// unrecoverable — and it is then refused, never handed to another program.
// ------------------------------------------------------------------

static const size_t kPrimaryHeaderSize = 164;   // magic + salt + keys
static const size_t kTrailerSize       = 172;   // EVFT magic + salt + keys + 2 CRCs

#pragma pack(push, 1)
struct EvFileHeader
{
    unsigned char salt[32];
    unsigned char encKeyByPw[64];
    unsigned char encKeyByMaster[64];
};
struct EvTrailer
{
    char          magic[4];         // "EVFT"
    unsigned char salt[32];
    unsigned char encKeyByPw[64];
    unsigned char encKeyByMaster[64];
    uint32_t      crcPrimary;       // CRC32 of the primary header's salt+keys
    uint32_t      crcTrailer;       // CRC32 of THIS trailer's salt+keys
};
#pragma pack(pop)

static_assert(sizeof(EvTrailer) == kTrailerSize, "EvTrailer size");

// Standard CRC-32 (reflected polynomial 0xEDB88320). Used for corruption
// DETECTION of the header fields, not for security — the file's
// confidentiality comes from AES, not from this checksum.
static uint32_t Crc32(const unsigned char* data, size_t len)
{
    static uint32_t table[256];
    static bool init = false;
    if (!init)
    {
        for (uint32_t i = 0; i < 256; i++)
        {
            uint32_t c = i;
            for (int k = 0; k < 8; k++)
                c = (c & 1) ? (0xEDB88320u ^ (c >> 1)) : (c >> 1);
            table[i] = c;
        }
        init = true;
    }
    uint32_t crc = 0xFFFFFFFFu;
    for (size_t i = 0; i < len; i++)
        crc = table[(crc ^ data[i]) & 0xFFu] ^ (crc >> 8);
    return crc ^ 0xFFFFFFFFu;
}

static uint32_t CrcOfHeader(const EvFileHeader& h)
{
    return Crc32(reinterpret_cast<const unsigned char*>(&h), sizeof(h));
}

// Result of reading an encrypted file's header.
enum class EvHeaderState
{
    None,      // no encryption markers at all — looks plain
    Primary,   // primary header valid (and trailer, if present)
    Backup,    // primary damaged/absent, recovered from the trailer
    Corrupt    // encryption markers exist but both copies are damaged
};

// Reads the effective header (primary or trailer backup) of an encrypted
// file. On success fills out and returns Primary/Backup. `hasTrailer`
// reports whether a trailer region occupies the end of the file (it must
// be excluded from the encrypted-content size regardless of validity).
static EvHeaderState ReadEvHeader(const fs::path& filePath,
                                  EvFileHeader& out,
                                  bool& hasTrailer)
{
    hasTrailer = false;
    try
    {
        std::ifstream in(filePath, std::ios::binary | std::ios::ate);
        if (!in) return EvHeaderState::None;
        auto sz = static_cast<size_t>(in.tellg());
        if (sz < kPrimaryHeaderSize + 16) return EvHeaderState::None;

        EvFileHeader primary = {};
        in.seekg(0);
        char primMagic[4] = {};
        in.read(primMagic, 4);
        in.read(reinterpret_cast<char*>(&primary), sizeof(primary));
        bool primaryNew    = (std::memcmp(primMagic, "EVF3", 4) == 0);
        bool primaryLegacy = (std::memcmp(primMagic, "EVF2", 4) == 0);

        // Physical trailer region (magic "EVFT") at the very end.
        bool trailerSpace = (sz >= kPrimaryHeaderSize + 16 + kTrailerSize);
        EvTrailer trailer = {};
        bool trailerPhys = false;
        if (trailerSpace)
        {
            in.seekg(static_cast<std::streamoff>(sz) - kTrailerSize);
            in.read(reinterpret_cast<char*>(&trailer), sizeof(trailer));
            trailerPhys = (std::memcmp(trailer.magic, "EVFT", 4) == 0);
        }

        // EVF3 files ALWAYS reserve the trailing region for the trailer
        // (even if its magic was damaged), so content size stays correct.
        hasTrailer = (primaryNew && trailerSpace) || trailerPhys;
        bool trailerValid = trailerPhys &&
            (Crc32(reinterpret_cast<const unsigned char*>(&trailer.salt),
                   sizeof(trailer.salt) + sizeof(trailer.encKeyByPw) +
                   sizeof(trailer.encKeyByMaster)) == trailer.crcTrailer);

        if (primaryNew)
        {
            if (trailerPhys && CrcOfHeader(primary) != trailer.crcPrimary)
            {
                if (trailerValid)
                {
                    std::memcpy(out.salt, trailer.salt, 32);
                    std::memcpy(out.encKeyByPw, trailer.encKeyByPw, 64);
                    std::memcpy(out.encKeyByMaster, trailer.encKeyByMaster, 64);
                    return EvHeaderState::Backup;
                }
                // Both damaged: trust the primary (best chance); a later
                // password check will fail rather than write anything.
            }
            out = primary;
            return EvHeaderState::Primary;
        }
        if (primaryLegacy)
        {
            out = primary;   // older format, no trailer
            hasTrailer = false;
            return EvHeaderState::Primary;
        }
        if (trailerValid)
        {
            std::memcpy(out.salt, trailer.salt, 32);
            std::memcpy(out.encKeyByPw, trailer.encKeyByPw, 64);
            std::memcpy(out.encKeyByMaster, trailer.encKeyByMaster, 64);
            return EvHeaderState::Backup;
        }
        if (trailerPhys)
            return EvHeaderState::Corrupt;
        return EvHeaderState::None;
    }
    catch (...)
    {
        return EvHeaderState::None;
    }
}

// ---- Helper: IsEncrypted ----------------------------------------

// A directory counts as "encrypted" when any regular file inside it is,
// so the right-click flow offers Decrypt instead of Encrypt for a folder
// that has already been locked.
bool IsEncrypted(const std::filesystem::path& target)
{
    EvFileHeader h;
    bool hasTrailer = false;

    if (fs::is_directory(target))
    {
        try {
            for (auto& entry : fs::recursive_directory_iterator(
                    target, fs::directory_options::skip_permission_denied))
            {
                if (!entry.is_regular_file()) continue;
                if (ReadEvHeader(entry.path(), h, hasTrailer) != EvHeaderState::None)
                    return true;
            }
        } catch (...) {
            return false;
        }
        return false;
    }

    return ReadEvHeader(target, h, hasTrailer) != EvHeaderState::None;
}

// Writes the complete EVF2 structure to an open stream: primary header,
// encrypted content, then the redundant trailer (backup header + CRCs).
static bool WriteEvfFile(std::ofstream& out,
                         const EvFileHeader& hdr,
                         const std::vector<unsigned char>& enc)
{
    EvFileHeader primary = hdr;
    out.write("EVF3", 4);
    out.write(reinterpret_cast<const char*>(&primary), sizeof(primary));
    if (!enc.empty())
        out.write(reinterpret_cast<const char*>(enc.data()), enc.size());

    EvTrailer tr = {};
    std::memcpy(tr.magic, "EVFT", 4);
    std::memcpy(tr.salt, hdr.salt, 32);
    std::memcpy(tr.encKeyByPw, hdr.encKeyByPw, 64);
    std::memcpy(tr.encKeyByMaster, hdr.encKeyByMaster, 64);
    tr.crcPrimary = CrcOfHeader(primary);
    tr.crcTrailer = Crc32(reinterpret_cast<const unsigned char*>(&tr.salt),
                          sizeof(tr.salt) + sizeof(tr.encKeyByPw) +
                          sizeof(tr.encKeyByMaster));
    out.write(reinterpret_cast<const char*>(&tr), sizeof(tr));
    return out.good();
}

// ---- Encrypt a single file in-place (EVF2 format) ---------------

static bool EncryptSingleFile(
    const fs::path& filePath,
    const std::vector<unsigned char>& filePasswordKey,
    const std::vector<unsigned char>& fileSalt,
    const std::vector<unsigned char>& masterKey)
{
    try {
        if (IsEncrypted(filePath)) return true;

        std::ifstream inFile(filePath, std::ios::binary | std::ios::ate);
        if (!inFile) return false; // Handle permission issues
        
        auto sz = inFile.tellg();
        inFile.seekg(0);
        std::vector<unsigned char> plain(static_cast<size_t>(sz));
        if (sz > 0)
            inFile.read(reinterpret_cast<char*>(plain.data()), sz);
        inFile.close();

        auto fileKey = GenerateRandomBytes(32);
        if (fileKey.empty()) return false;

        auto encKeyByPw = EncryptBuffer(fileKey, filePasswordKey);
        auto encKeyByMaster = EncryptBuffer(fileKey, masterKey);
        
        if (encKeyByPw.size() != 64 || encKeyByMaster.size() != 64) {
            return false;
        }

        auto enc = EncryptBuffer(plain, fileKey);
        if (enc.empty() && sz > 0) return false;
        if (enc.empty() && sz == 0) {
            enc = EncryptBuffer({}, fileKey);
            if (enc.empty()) return false;
        }

        // Write atomically: temp file in the same directory, then replace
        // so a crash or full disk never leaves a half-written file.
        fs::path tmpPath = TempPathFor(filePath);
        {
            std::ofstream outFile(tmpPath, std::ios::binary | std::ios::trunc);
            if (!outFile) return false; // Handle permission issues

            EvFileHeader hdr = {};
            std::memcpy(hdr.salt, fileSalt.data(), 32);
            std::memcpy(hdr.encKeyByPw, encKeyByPw.data(), 64);
            std::memcpy(hdr.encKeyByMaster, encKeyByMaster.data(), 64);
            bool good = WriteEvfFile(outFile, hdr, enc);
            outFile.close();
            if (!good) {
                fs::remove(tmpPath);
                return false;
            }
        }

        if (!MoveFileExW(tmpPath.c_str(), filePath.c_str(),
                         MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH))
        {
            fs::remove(tmpPath);
            return false;
        }

        SecureZeroMemory(fileKey.data(), fileKey.size());
        return true;
    } catch (...) {
        return false;
    }
}

// ---- Decrypt a single file in-place (EVF2 format) ---------------

static int DecryptSingleFile(
    const fs::path& filePath,
    const std::vector<unsigned char>& pwKey, 
    const std::vector<unsigned char>& masterKey,
    bool usingMasterKey)
{
    try {
        EvFileHeader hdr;
        bool hasTrailer = false;
        EvHeaderState st = ReadEvHeader(filePath, hdr, hasTrailer);
        if (st == EvHeaderState::None || st == EvHeaderState::Corrupt)
            return -1;   // not encrypted, or both header copies damaged

        std::ifstream inFile(filePath, std::ios::binary | std::ios::ate);
        if (!inFile) return -1;
        auto sz = static_cast<size_t>(inFile.tellg());
        size_t encSize = sz - kPrimaryHeaderSize - (hasTrailer ? kTrailerSize : 0);
        if (encSize < 16) return 0;

        inFile.seekg(kPrimaryHeaderSize);
        std::vector<unsigned char> salt(hdr.salt, hdr.salt + 32);
        std::vector<unsigned char> encKeyByPw(hdr.encKeyByPw, hdr.encKeyByPw + 64);
        std::vector<unsigned char> encKeyByMaster(hdr.encKeyByMaster, hdr.encKeyByMaster + 64);

        std::vector<unsigned char> enc(encSize);
        inFile.read(reinterpret_cast<char*>(enc.data()), encSize);
        inFile.close();

        std::vector<unsigned char> fileKey;
        if (usingMasterKey) {
            fileKey = DecryptBuffer(encKeyByMaster, masterKey);
        } else {
            fileKey = DecryptBuffer(encKeyByPw, pwKey);
        }

        if (fileKey.empty() || fileKey.size() != 32) return 0;

        auto plain = DecryptBuffer(enc, fileKey);
        SecureZeroMemory(fileKey.data(), fileKey.size());

        if (plain.empty() && encSize > 16) return 0;

        // Write atomically: temp file in the same directory, then replace.
        fs::path tmpPath = TempPathFor(filePath);
        {
            std::ofstream outFile(tmpPath, std::ios::binary | std::ios::trunc);
            if (!outFile) return 0;
            if (!plain.empty())
                outFile.write(reinterpret_cast<const char*>(plain.data()), plain.size());

            bool good = outFile.good();
            outFile.close();
            if (!good) {
                fs::remove(tmpPath);
                return 0;
            }
        }

        if (!MoveFileExW(tmpPath.c_str(), filePath.c_str(),
                         MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH))
        {
            fs::remove(tmpPath);
            return 0;
        }

        return 1;
    } catch (...) {
        return 0;
    }
}

// ---- Public: encrypt target --------------------

bool EncryptTarget(const std::filesystem::path& target)
{
    EvGate gate(target);   // driver: allow reads during this operation

    if (fs::is_regular_file(target) && IsEncrypted(target)) {
        ShowInfo(L"EchoVault", L"This file is already encrypted.");
        return true;
    }

    std::wstring filePw;
    for (;;)
    {
        auto a1 = PromptPassword(
            L"EchoVault \u2014 File Password",
            L"Create a password to encrypt this item:");
        if (a1.result != PasswordResult::OK) return false;
        if (a1.password.empty()) {
            ShowError(L"EchoVault", L"Password cannot be empty.");
            continue;
        }

        auto a2 = PromptPassword(
            L"EchoVault \u2014 Confirm File Password",
            L"Confirm the password for this item:");
        if (a2.result != PasswordResult::OK) return false;

        if (a1.password != a2.password) {
            ShowError(L"EchoVault", L"Passwords do not match. Try again.");
            continue;
        }
        filePw = a1.password;
        break;
    }

    auto fileSalt = GenerateRandomBytes(32);
    auto pwKey = DeriveKey(filePw, fileSalt);

    try {
        if (fs::is_regular_file(target)) {
            if (!EncryptSingleFile(target, pwKey, fileSalt, GetMasterKeyOnDemand())) {
                ShowError(L"EchoVault", (L"Failed to encrypt (check permissions):\n" + target.wstring()).c_str());
                return false;
            }
            // Any encrypted file must be interceptable on double-click:
            // register its extension right away (covers types not in the
            // static list, e.g. .rb, .go, or anything else).
            EnsureExtensionIntercepted(target.extension().wstring());
            EvRegister(target.wstring());   // driver: gate this path
            ShowInfo(L"EchoVault", (L"Encrypted successfully:\n" + target.filename().wstring()).c_str());
            return true;
        }

        if (fs::is_directory(target)) {
            int ok = 0, fail = 0;
            for (auto& entry : fs::recursive_directory_iterator(target,
                    fs::directory_options::skip_permission_denied))
            {
                if (!entry.is_regular_file()) continue;
                if (IsEncrypted(entry.path())) continue;
                if (EncryptSingleFile(entry.path(), pwKey, fileSalt, GetMasterKeyOnDemand())) {
                    ++ok;
                    EnsureExtensionIntercepted(entry.path().extension().wstring());
                    EvRegister(entry.path().wstring());
                }
                else ++fail;
            }
            // The folder itself is gated too (prefix entry): opening it
            // (or anything under it) requires a password.
            EvRegister(target.wstring());

            std::wstring msg;
            if (ok == 0 && fail == 0)
            {
                msg = L"This folder is already encrypted, or contains no\n"
                      L"files to encrypt. Nothing was changed.";
            }
            else
            {
                msg = L"Encryption complete.\n\n"
                    L"Succeeded: " + std::to_wstring(ok) + L"\n"
                    L"Failed: "    + std::to_wstring(fail);
            }
            if (fail > 0) ShowError(L"EchoVault", msg);
            else ShowInfo(L"EchoVault", msg);
            return fail == 0;
        }

        ShowError(L"EchoVault", L"The selected path is not a file or folder.");
        return false;
    } catch (const std::exception& e) {
        std::string what = e.what();
        std::wstring wmsg(what.begin(), what.end());
        ShowError(L"EchoVault", (L"Encryption error:\n" + wmsg).c_str());
        return false;
    }
}

// ---- Extract salt to prompt for correct password ----
static bool ExtractSalt(const fs::path& filePath, std::vector<unsigned char>& outSalt)
{
    EvFileHeader hdr;
    bool hasTrailer = false;
    EvHeaderState st = ReadEvHeader(filePath, hdr, hasTrailer);
    if (st == EvHeaderState::None || st == EvHeaderState::Corrupt)
        return false;
    outSalt.assign(hdr.salt, hdr.salt + 32);
    return true;
}

// ---- Public: decrypt target --------------------

bool DecryptTarget(const std::filesystem::path& target, bool showResult)
{
    EvGate gate(target);   // driver: allow reads; re-deny if we bail out

    std::vector<unsigned char> sampleSalt;
    fs::path firstFile = target;
    if (fs::is_directory(target)) {
        for (auto& entry : fs::recursive_directory_iterator(target, fs::directory_options::skip_permission_denied)) {
            if (entry.is_regular_file() && IsEncrypted(entry.path())) {
                firstFile = entry.path();
                break;
            }
        }
    }
    
    if (firstFile.empty() || !ExtractSalt(firstFile, sampleSalt)) {
        ShowError(L"EchoVault", L"No valid EchoVault encrypted files found in the target.");
        return false;
    }

    std::vector<unsigned char> pwKey;
    bool usingMaster = false;

    for (;;) {
        auto a1 = PromptPassword(
            L"EchoVault \u2014 File Password",
            L"Enter the specific password for this file/folder:",
            true, L"Use Master Password");

        if (a1.result == PasswordResult::Cancel) return false;
        
        if (a1.result == PasswordResult::ForgotPassword) {
            usingMaster = true;
            break; 
        }

        pwKey = DeriveKey(a1.password, sampleSalt);
        
        // Testing with the file password never needs the master key — only
        // fetch it when the user explicitly chooses "Use Master Password".
        int res = DecryptSingleFile(firstFile, pwKey, {}, false);
        if (res == 1) {
            usingMaster = false;
            break;
        } else if (res == 0) {
            ShowError(L"EchoVault", L"Incorrect File Password or file corrupted. Try again.");
            continue;
        } else {
            ShowError(L"EchoVault", L"File format corrupted.");
            return false;
        }
    }

    try {
        if (fs::is_regular_file(target)) {
            if (usingMaster) {
                if (DecryptSingleFile(target, pwKey, GetMasterKeyOnDemand(), true) != 1) {
                    ShowError(L"EchoVault", L"Decryption failed. Check file permissions or Master Key.");
                    return false;
                }
            }
            EvUnregister(target.wstring());   // driver: permanently un-gate
            if (showResult)
                ShowInfo(L"EchoVault", (L"Decrypted successfully:\n" + target.filename().wstring()).c_str());
            return true;
        }

        if (fs::is_directory(target)) {
            int ok = 1; 
            if (usingMaster) {
                if (DecryptSingleFile(firstFile, pwKey, GetMasterKeyOnDemand(), true) == 1) ok = 1;
                else ok = 0;
            }
            
            int fail = 0;
            std::vector<fs::path> evFiles;
            for (auto& entry : fs::recursive_directory_iterator(target, fs::directory_options::skip_permission_denied))
            {
                if (entry.is_regular_file() && entry.path() != firstFile && IsEncrypted(entry.path()))
                    evFiles.push_back(entry.path());
            }

            // The master key is only needed (and only requested) on the
            // "Use Master Password" path.
            auto master = usingMaster ? GetMasterKeyOnDemand() : std::vector<unsigned char>{};
            for (auto& p : evFiles) {
                if (DecryptSingleFile(p, pwKey, master, usingMaster) == 1) {
                    ++ok;
                    EvUnregister(p.wstring());
                } else ++fail;
            }
            EvUnregister(target.wstring());

            std::wstring msg = L"Decryption complete.\n\n"
                L"Succeeded: " + std::to_wstring(ok) + L"\n"
                L"Failed: "    + std::to_wstring(fail);
            if (fail > 0) ShowError(L"EchoVault", msg);
            else ShowInfo(L"EchoVault", msg);
            return fail == 0;
        }
        return false;
    } catch (const std::exception& e) {
        std::string what = e.what();
        std::wstring wmsg(what.begin(), what.end());
        ShowError(L"EchoVault", (L"Decryption error:\n" + wmsg).c_str());
        return false;
    }
}

// ---- Temporary unlock (auto re-lock on close) --------------------

UnlockResult UnlockFileForOpen(const std::filesystem::path& target)
{
    UnlockResult out;
    EvGate gate(target);   // driver: allow us to read it; re-deny on failure

    // --- Read the effective header (primary or trailer backup) + content ---
    std::vector<unsigned char> encContent;
    try {
        EvFileHeader hdr;
        bool hasTrailer = false;
        EvHeaderState st = ReadEvHeader(target, hdr, hasTrailer);
        if (st == EvHeaderState::None || st == EvHeaderState::Corrupt)
            return out;

        std::ifstream in(target, std::ios::binary | std::ios::ate);
        if (!in) return out;
        auto sz = static_cast<size_t>(in.tellg());
        size_t encSize = sz - kPrimaryHeaderSize - (hasTrailer ? kTrailerSize : 0);
        if (encSize < 16) return out;

        out.salt.assign(hdr.salt, hdr.salt + 32);
        out.encKeyByPw.assign(hdr.encKeyByPw, hdr.encKeyByPw + 64);
        out.encKeyByMaster.assign(hdr.encKeyByMaster, hdr.encKeyByMaster + 64);

        in.seekg(kPrimaryHeaderSize);
        encContent.resize(encSize);
        in.read(reinterpret_cast<char*>(encContent.data()), encSize);
    } catch (...) {
        return out;
    }

    // --- Password loop (mirrors DecryptTarget for a single file) ---
    bool usingMaster = false;
    for (;;)
    {
        auto a1 = PromptPassword(
            L"EchoVault \u2014 Unlock",
            L"Enter the password for this file:",
            true, L"Use Master Password");

        if (a1.result == PasswordResult::Cancel)
            return out;
        if (a1.result == PasswordResult::ForgotPassword)
        {
            usingMaster = true;
            break;
        }

        auto pwKey = DeriveKey(a1.password, out.salt);
        out.fileKey = DecryptBuffer(out.encKeyByPw, pwKey);
        SecureZeroMemory(pwKey.data(), pwKey.size());

        if (out.fileKey.size() == 32)
            break;
        ShowError(L"EchoVault", L"Incorrect password. Try again.");
    }

    if (usingMaster)
    {
        auto mk = GetMasterKeyOnDemand();
        if (mk.empty()) return out;   // cancelled or failed
        out.fileKey = DecryptBuffer(out.encKeyByMaster, mk);
        if (out.fileKey.size() != 32)
        {
            ShowError(L"EchoVault",
                L"This file could not be unlocked with the Master Password.");
            return out;
        }
    }

    // --- Decrypt the content IN-PLACE (atomic) ---
    auto plain = DecryptBuffer(encContent, out.fileKey);
    if (plain.empty() && encContent.size() > 16)
    {
        ShowError(L"EchoVault",
            L"Decryption failed. The file may be corrupted.");
        return out;
    }

    fs::path tmpPath = TempPathFor(target);
    {
        std::ofstream o(tmpPath, std::ios::binary | std::ios::trunc);
        if (!o) return out;
        if (!plain.empty())
            o.write(reinterpret_cast<const char*>(plain.data()), plain.size());
        bool good = o.good();
        o.close();
        if (!good) { fs::remove(tmpPath); return out; }
    }
    if (!MoveFileExW(tmpPath.c_str(), target.c_str(),
            MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH))
    {
        fs::remove(tmpPath);
        return out;
    }

    out.success = true;
    gate.disarm();   // keep allow-listed: the viewer must be able to open it
    return out;
}

bool RelockFile(const std::filesystem::path& target, const UnlockResult& unlock)
{
    if (!unlock.success || unlock.fileKey.empty() ||
        unlock.salt.empty() || unlock.encKeyByPw.empty() || unlock.encKeyByMaster.empty())
        return false;
    if (IsEncrypted(target)) return true;   // already locked again

    try {
        std::ifstream inFile(target, std::ios::binary | std::ios::ate);
        if (!inFile) return false;
        auto sz = inFile.tellg();
        inFile.seekg(0);
        std::vector<unsigned char> plain(static_cast<size_t>(sz));
        if (sz > 0)
            inFile.read(reinterpret_cast<char*>(plain.data()), sz);
        inFile.close();

        auto enc = EncryptBuffer(plain, unlock.fileKey);
        if (enc.empty())
        {
            if (plain.empty()) enc = EncryptBuffer({}, unlock.fileKey);
            if (enc.empty()) return false;
        }

        // Rebuild the ORIGINAL header so the file keeps its password. The
        // trailer is written too, so a damaged primary header is repaired
        // the next time the file is unlocked and re-locked.
        fs::path tmpPath = TempPathFor(target);
        {
            std::ofstream o(tmpPath, std::ios::binary | std::ios::trunc);
            if (!o) return false;
            EvFileHeader hdr = {};
            std::memcpy(hdr.salt, unlock.salt.data(), 32);
            std::memcpy(hdr.encKeyByPw, unlock.encKeyByPw.data(), 64);
            std::memcpy(hdr.encKeyByMaster, unlock.encKeyByMaster.data(), 64);
            bool good = WriteEvfFile(o, hdr, enc);
            o.close();
            if (!good) { fs::remove(tmpPath); return false; }
        }
        if (!MoveFileExW(tmpPath.c_str(), target.c_str(),
                MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH))
        {
            fs::remove(tmpPath);
            return false;
        }
        return true;
    } catch (...) {
        return false;
    }
}

// ---- Change File Password ---------------------------------------

bool ChangeFilePassword(const std::filesystem::path& target)
{
    EvGate gate(target);   // driver: allow reads during this operation

    std::vector<fs::path> evFiles;
    if (fs::is_regular_file(target)) {
        if (!IsEncrypted(target)) {
            ShowError(L"EchoVault", L"Selected file is not an encrypted file.");
            return false;
        }
        evFiles.push_back(target);
    } else if (fs::is_directory(target)) {
        for (auto& entry : fs::recursive_directory_iterator(target, fs::directory_options::skip_permission_denied)) {
            if (entry.is_regular_file() && IsEncrypted(entry.path()))
                evFiles.push_back(entry.path());
        }
        if (evFiles.empty()) {
            ShowError(L"EchoVault", L"No encrypted files found in this folder.");
            return false;
        }
    } else {
        return false;
    }

    std::vector<unsigned char> sampleSalt;
    if (!ExtractSalt(evFiles[0], sampleSalt)) {
        ShowError(L"EchoVault", L"Could not read the encrypted file format.");
        return false;
    }

    std::vector<unsigned char> oldPwKey;
    bool usingMaster = false;
    for (;;) {
        auto a1 = PromptPassword(
            L"EchoVault \u2014 Change File Password",
            L"Enter the CURRENT password for this file/folder:",
            true, L"Use Master Password");

        if (a1.result == PasswordResult::Cancel) return false;
        if (a1.result == PasswordResult::ForgotPassword) {
            usingMaster = true;
            break;
        }

        oldPwKey = DeriveKey(a1.password, sampleSalt);
        
        std::ifstream in(evFiles[0], std::ios::binary);
        if (!in) continue;
        in.seekg(36); 
        std::vector<unsigned char> encKeyByPw(64);
        in.read(reinterpret_cast<char*>(encKeyByPw.data()), 64);
        in.close();

        auto fk = DecryptBuffer(encKeyByPw, oldPwKey);
        if (fk.size() == 32) {
            break; 
        } else {
            ShowError(L"EchoVault", L"Incorrect File Password. Try again.");
        }
    }

    std::wstring newPw;
    for (;;) {
        auto a1 = PromptPassword(
            L"EchoVault \u2014 New File Password",
            L"Enter the NEW password for this file/folder:");
        if (a1.result != PasswordResult::OK) return false;
        if (a1.password.empty()) {
            ShowError(L"EchoVault", L"Password cannot be empty.");
            continue;
        }
        auto a2 = PromptPassword(
            L"EchoVault \u2014 Confirm File Password",
            L"Confirm the NEW password:");
        if (a2.result != PasswordResult::OK) return false;
        if (a1.password != a2.password) {
            ShowError(L"EchoVault", L"Passwords do not match. Try again.");
            continue;
        }
        newPw = a1.password;
        break;
    }

    auto newSalt = GenerateRandomBytes(32);
    auto newPwKey = DeriveKey(newPw, newSalt);

    int ok = 0, fail = 0;
    auto master = usingMaster ? GetMasterKeyOnDemand() : std::vector<unsigned char>{};
    for (auto& p : evFiles) {
        try {
            EvFileHeader hdr;
            bool hasTrailer = false;
            EvHeaderState st = ReadEvHeader(p, hdr, hasTrailer);
            if (st == EvHeaderState::None || st == EvHeaderState::Corrupt)
            { fail++; continue; }

            std::ifstream in(p, std::ios::binary | std::ios::ate);
            if (!in) { fail++; continue; }
            auto sz = static_cast<size_t>(in.tellg());
            size_t contentSize = sz - kPrimaryHeaderSize - (hasTrailer ? kTrailerSize : 0);
            if (contentSize < 16) { fail++; continue; }
            in.seekg(kPrimaryHeaderSize);
            std::vector<unsigned char> content(contentSize);
            in.read(reinterpret_cast<char*>(content.data()), contentSize);
            in.close();

            std::vector<unsigned char> encKeyByPw(hdr.encKeyByPw, hdr.encKeyByPw + 64);
            std::vector<unsigned char> encKeyByMaster(hdr.encKeyByMaster, hdr.encKeyByMaster + 64);

            std::vector<unsigned char> fileKey;
            if (usingMaster)
                fileKey = DecryptBuffer(encKeyByMaster, master);
            else
                fileKey = DecryptBuffer(encKeyByPw, oldPwKey);
            if (fileKey.size() != 32) { fail++; continue; }

            auto newEncKeyByPw = EncryptBuffer(fileKey, newPwKey);
            if (newEncKeyByPw.size() != 64) { fail++; continue; }

            EvFileHeader newHdr = {};
            std::memcpy(newHdr.salt, newSalt.data(), 32);
            std::memcpy(newHdr.encKeyByPw, newEncKeyByPw.data(), 64);
            std::memcpy(newHdr.encKeyByMaster, hdr.encKeyByMaster, 64);

            // Rewrite the whole file atomically so BOTH header copies
            // (primary + trailer) carry the new password.
            fs::path tmpPath = TempPathFor(p);
            {
                std::ofstream o(tmpPath, std::ios::binary | std::ios::trunc);
                if (!o) { fail++; continue; }
                bool good = WriteEvfFile(o, newHdr, content);
                o.close();
                if (!good) { fs::remove(tmpPath); fail++; continue; }
            }
            if (!MoveFileExW(tmpPath.c_str(), p.c_str(),
                    MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH))
            {
                fs::remove(tmpPath);
                fail++;
                continue;
            }
            EvRegister(p.wstring());   // driver: keep the path gated
            ok++;
        } catch (...) {
            fail++;
        }
    }

    std::wstring msg = L"Password Change complete.\n\n"
        L"Succeeded: " + std::to_wstring(ok) + L"\n"
        L"Failed: "    + std::to_wstring(fail);
    if (fail > 0) ShowError(L"EchoVault", msg);
    else ShowInfo(L"EchoVault", msg);

    return fail == 0;
}

// ---- Headless self-test (EchoVault.exe --selftest) --------------

int RunSelfTest()
{
    int fails = 0;
    std::wstring log;
    auto line = [&](const wchar_t* what) { log += what; log += L"\n"; };
    auto check = [&](bool ok, const wchar_t* what)
    {
        log += ok ? L"PASS " : L"FAIL ";
        log += what;
        log += L"\n";
        if (!ok) fails++;
    };

    // ---- Isolated sandbox dir next to vault.db ----
    fs::path dir = GetVaultDirectory() / L"selftest";
    std::error_code ec;
    fs::remove_all(dir, ec);
    fs::create_directories(dir, ec);
    fs::path file = dir / L"data.txt";

    const std::wstring pw = L"selftest-pw-123";
    auto salt       = GenerateRandomBytes(32);
    auto masterKey  = GenerateRandomBytes(32);
    auto fileKey    = GenerateRandomBytes(32);
    auto pwKey      = DeriveKey(pw, salt);
    auto encKeyByPw = EncryptBuffer(fileKey, pwKey);
    auto encKeyByMaster = EncryptBuffer(fileKey, masterKey);

    const char* plain = "Hello EchoVault resilience self-test.\nSecond line 12345.\n";
    const size_t plainLen = std::strlen(plain);

    auto readAll = [&](const fs::path& p)
    {
        std::vector<unsigned char> v;
        std::ifstream in(p, std::ios::binary | std::ios::ate);
        auto s = in.tellg();
        in.seekg(0);
        v.resize(static_cast<size_t>(s));
        if (s > 0) in.read(reinterpret_cast<char*>(v.data()), s);
        return v;
    };
    auto contentMatches = [&](const std::vector<unsigned char>& v)
    {
        return v.size() == plainLen &&
               std::memcmp(v.data(), plain, plainLen) == 0;
    };
    auto damage = [&](const fs::path& p, std::streamoff off, size_t n)
    {
        std::fstream f(p, std::ios::in | std::ios::out | std::ios::binary);
        std::vector<unsigned char> junk(n, 0x5A);   // 'Z' — clearly not original
        f.seekp(off);
        f.write(reinterpret_cast<char*>(junk.data()), n);
    };

    line(L"== EchoVault self-test ==");

    // ---- Baseline: encrypt / decrypt round-trip ----
    {
        std::ofstream o(file, std::ios::binary);
        o.write(plain, plainLen);
    }
    check(!IsEncrypted(file), L"plain file not flagged as encrypted");
    check(EncryptSingleFile(file, pwKey, salt, masterKey), L"encrypt succeeds");
    check(IsEncrypted(file), L"encrypted file detected (EVF3)");
    check(DecryptSingleFile(file, pwKey, {}, false) == 1, L"decrypt round-trip succeeds");
    check(contentMatches(readAll(file)), L"round-trip content matches");
    check(!IsEncrypted(file), L"file plain after decrypt");

    // ---- Re-lock path (used after auto-unlock) ----
    {
        UnlockResult ul;
        ul.success = true;
        ul.salt = salt;
        ul.encKeyByPw = encKeyByPw;
        ul.encKeyByMaster = encKeyByMaster;
        ul.fileKey = fileKey;
        check(RelockFile(file, ul), L"relock succeeds");
        check(IsEncrypted(file), L"relocked file detected");
        check(DecryptSingleFile(file, pwKey, {}, false) == 1, L"decrypt after relock");
        check(contentMatches(readAll(file)), L"relock round-trip content matches");
    }

    // ---- Resilience: leading signature (magic) damaged ----
    {
        check(EncryptSingleFile(file, pwKey, salt, masterKey), L"re-encrypt for damage test");
        damage(file, 0, 4);
        check(IsEncrypted(file), L"still detected after leading magic damaged");
        check(DecryptSingleFile(file, pwKey, {}, false) == 1,
              L"decrypt recovers from trailer after magic damaged");
        check(contentMatches(readAll(file)), L"recovered content matches");
    }

    // ---- Resilience: primary header fields (salt) damaged ----
    {
        check(EncryptSingleFile(file, pwKey, salt, masterKey), L"re-encrypt for salt test");
        damage(file, 4 + 5, 1);
        check(IsEncrypted(file), L"still detected after primary salt damaged");
        check(DecryptSingleFile(file, pwKey, {}, false) == 1,
              L"decrypt recovers from trailer after salt damaged");
        check(contentMatches(readAll(file)), L"recovered content matches");
    }

    // ---- Resilience: trailer magic damaged (must not confuse content) ----
    {
        check(EncryptSingleFile(file, pwKey, salt, masterKey), L"re-encrypt for trailer test");
        damage(file, static_cast<std::streamoff>(fs::file_size(file)) -
                          static_cast<std::streamoff>(kTrailerSize), 4);
        check(IsEncrypted(file), L"still detected after trailer magic damaged");
        check(DecryptSingleFile(file, pwKey, {}, false) == 1,
              L"decrypt works after trailer magic damaged");
        check(contentMatches(readAll(file)), L"content matches after trailer damage");
    }

    // ---- Resilience: legacy EVF2 file (no trailer) still works ----
    {
        auto encContent = EncryptBuffer(
            std::vector<unsigned char>(plain, plain + plainLen), fileKey);
        {
            std::ofstream o(file, std::ios::binary | std::ios::trunc);
            o.write("EVF2", 4);
            o.write(reinterpret_cast<const char*>(salt.data()), 32);
            o.write(reinterpret_cast<const char*>(encKeyByPw.data()), 64);
            o.write(reinterpret_cast<const char*>(encKeyByMaster.data()), 64);
            o.write(reinterpret_cast<const char*>(encContent.data()), encContent.size());
        }
        check(IsEncrypted(file), L"legacy EVF2 file detected");
        check(DecryptSingleFile(file, pwKey, {}, false) == 1, L"legacy EVF2 decrypts");
        check(contentMatches(readAll(file)), L"legacy content matches");
    }

    // ---- Refusal: BOTH header copies destroyed ----
    {
        check(EncryptSingleFile(file, pwKey, salt, masterKey), L"re-encrypt for double-damage test");
        auto sz = fs::file_size(file);
        damage(file, 0, 4);
        damage(file, static_cast<std::streamoff>(sz) -
                          static_cast<std::streamoff>(kTrailerSize), 4);
        check(!IsEncrypted(file),
              L"both copies destroyed -> treated as plain (unrecoverable by design)");
        check(DecryptSingleFile(file, pwKey, {}, false) == -1,
              L"destroyed file refused, never written");
    }

    // ---- No stray temp files left behind ----
    {
        int temps = 0;
        for (auto& e : fs::directory_iterator(dir, ec))
            if (e.path().filename().wstring().find(L".evtmp.") != std::wstring::npos)
                temps++;
        check(temps == 0, L"no stray temp files left");
    }

    fs::remove_all(dir, ec);

    line(fails == 0 ? L"ALL TESTS PASSED" : L"SOME TESTS FAILED");

    // Write the log next to vault.db so it is easy to find.
    {
        std::ofstream f(GetVaultDirectory() / L"selftest.log", std::ios::trunc);
        for (auto& ch : log)
            f << static_cast<char>(ch);
    }
    return fails == 0 ? 0 : 1;
}