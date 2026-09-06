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
    tmp += std::to_wstring(GetCurrentProcessId()) + L"." + BytesToHex(GenerateRandomBytes(16));
    return tmp;
}

// Locked files deliberately keep their original extension. If Windows
// bypasses EchoVault through "Open with", an ordinary editor may display the
// ciphertext as garbage. Marking the locked file read-only does not provide a
// security boundary (the owner can remove the attribute), but it prevents the
// common and destructive accident of pressing Save over the encrypted data.
// EchoVault clears the attribute only for its atomic replacement and restores
// it whenever the result is encrypted.
static bool ReplaceAtomically(const fs::path& tempPath,
                              const fs::path& destination,
                              bool resultIsEncrypted)
{
    // Flush the complete temporary file before committing the rename.
    HANDLE h = CreateFileW(tempPath.c_str(), GENERIC_WRITE, 0, nullptr,
        OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) return false;
    bool flushed = FlushFileBuffers(h) != FALSE;
    CloseHandle(h);
    if (!flushed) return false;
    DWORD tempAttrs = GetFileAttributesW(tempPath.c_str());
    if (tempAttrs == INVALID_FILE_ATTRIBUTES) return false;
    DWORD wanted = resultIsEncrypted ? tempAttrs | FILE_ATTRIBUTE_READONLY
                                    : tempAttrs & ~FILE_ATTRIBUTE_READONLY;
    if (!SetFileAttributesW(tempPath.c_str(), wanted)) return false;
    DWORD oldAttrs = GetFileAttributesW(destination.c_str());
    bool hadAttrs = oldAttrs != INVALID_FILE_ATTRIBUTES;
    if (hadAttrs && (oldAttrs & FILE_ATTRIBUTE_READONLY))
    {
        if (!SetFileAttributesW(destination.c_str(),
                oldAttrs & ~FILE_ATTRIBUTE_READONLY))
        {
            SetFileAttributesW(tempPath.c_str(), tempAttrs);
            return false;
        }
    }

    if (!MoveFileExW(tempPath.c_str(), destination.c_str(),
            MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH))
    {
        if (hadAttrs && (oldAttrs & FILE_ATTRIBUTE_READONLY))
            SetFileAttributesW(destination.c_str(), oldAttrs);
        SetFileAttributesW(tempPath.c_str(), tempAttrs);
        return false;
    }

    return true;
}

static bool IsReadOnlyFile(const fs::path& path)
{
    DWORD attrs = GetFileAttributesW(path.c_str());
    return attrs != INVALID_FILE_ATTRIBUTES &&
           (attrs & FILE_ATTRIBUTE_READONLY) != 0;
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
        GetVaultDirectory();
        fs::path tmp = TempPathFor(g_VaultDB);
        std::ofstream f(tmp, std::ios::binary | std::ios::trunc);
        if (!f) return false;
        f.write(reinterpret_cast<const char*>(&header), sizeof(VaultHeader));
        f.flush();
        bool good = f.good();
        f.close();
        if (good && ReplaceAtomically(tmp, g_VaultDB, false)) return true;
        std::error_code ec;
        fs::remove(tmp, ec);
        return false;
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

    auto encMK    = EncryptAuthenticated(masterKey, pwKey);
    auto encMKRec = EncryptAuthenticated(masterKey, recKey);

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
    auto newEnc  = EncryptAuthenticated(masterKey, newKey);

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
                                  bool& hasTrailer, bool* authenticated = nullptr)
{
    hasTrailer = false;
    if (authenticated) *authenticated = false;
    try
    {
        std::ifstream in(filePath, std::ios::binary | std::ios::ate);
        if (!in) return EvHeaderState::None;
        auto sz = static_cast<size_t>(in.tellg());
        if (sz < kPrimaryHeaderSize + 32) {
            char marker[4] = {};
            in.seekg(0); in.read(marker, 4);
            return std::memcmp(marker, "EVF2", 4) == 0 ||
                   std::memcmp(marker, "EVF3", 4) == 0 ||
                   std::memcmp(marker, "EVF4", 4) == 0 ? EvHeaderState::Corrupt : EvHeaderState::None;
        }

        EvFileHeader primary = {};
        in.seekg(0);
        char primMagic[4] = {};
        in.read(primMagic, 4);
        in.read(reinterpret_cast<char*>(&primary), sizeof(primary));
        bool primaryAuth = (std::memcmp(primMagic, "EVF4", 4) == 0);
        bool primaryNew = primaryAuth || (std::memcmp(primMagic, "EVF3", 4) == 0);
        bool primaryLegacy = (std::memcmp(primMagic, "EVF2", 4) == 0);

        char payloadMarker[4] = {};
        in.read(payloadMarker, 4);
        bool payloadAuth = std::memcmp(payloadMarker, "EVG4", 4) == 0;

        // Physical trailer region (magic "EVFT") at the very end.
        bool trailerSpace = (sz >= kPrimaryHeaderSize + 16 + kTrailerSize);
        EvTrailer trailer = {};
        bool trailerPhys = false;
        if (trailerSpace)
        {
            in.seekg(static_cast<std::streamoff>(sz) - kTrailerSize);
            in.read(reinterpret_cast<char*>(&trailer), sizeof(trailer));
            trailerPhys = (std::memcmp(trailer.magic, "EVFT", 4) == 0) ||
                          (std::memcmp(trailer.magic, "EVT4", 4) == 0);
        }

        if (authenticated) *authenticated = primaryAuth || payloadAuth ||
            (trailerPhys && std::memcmp(trailer.magic, "EVT4", 4) == 0);

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
        if (payloadAuth && trailerSpace) {
            // A recognition hint only: GCM must still authenticate the header and data.
            hasTrailer = true;
            out = primary;
            return EvHeaderState::Primary;
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
                         const std::vector<unsigned char>& enc, bool authenticated = true)
{
    EvFileHeader primary = hdr;
    out.write(authenticated ? "EVF4" : "EVF3", 4);
    out.write(reinterpret_cast<const char*>(&primary), sizeof(primary));
    if (!enc.empty())
        out.write(reinterpret_cast<const char*>(enc.data()), enc.size());

    EvTrailer tr = {};
    std::memcpy(tr.magic, authenticated ? "EVT4" : "EVFT", 4);
    std::memcpy(tr.salt, hdr.salt, 32);
    std::memcpy(tr.encKeyByPw, hdr.encKeyByPw, 64);
    std::memcpy(tr.encKeyByMaster, hdr.encKeyByMaster, 64);
    tr.crcPrimary = CrcOfHeader(primary);
    tr.crcTrailer = Crc32(reinterpret_cast<const unsigned char*>(&tr.salt),
                          sizeof(tr.salt) + sizeof(tr.encKeyByPw) +
                          sizeof(tr.encKeyByMaster));
    out.write(reinterpret_cast<const char*>(&tr), sizeof(tr));
    out.flush();
    return out.good();
}

static constexpr size_t kMaxFileBytes = 128u * 1024u * 1024u;
static bool ReadBounded(const fs::path& path, std::vector<unsigned char>& bytes)
{
    // Atomic replacement cannot encrypt other hard-link names or silently drop
    // named streams. Refuse those cases rather than promise complete protection.
    DWORD attrs = GetFileAttributesW(path.c_str());
    if (attrs == INVALID_FILE_ATTRIBUTES || (attrs & FILE_ATTRIBUTE_REPARSE_POINT)) return false;
    HANDLE metadata = CreateFileW(path.c_str(), 0, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                                  nullptr, OPEN_EXISTING, 0, nullptr);
    if (metadata == INVALID_HANDLE_VALUE) return false;
    BY_HANDLE_FILE_INFORMATION info = {};
    bool ordinary = GetFileInformationByHandle(metadata, &info) && info.nNumberOfLinks == 1;
    CloseHandle(metadata);
    if (!ordinary) return false;
    WIN32_FIND_STREAM_DATA stream = {};
    HANDLE streams = FindFirstStreamW(path.c_str(), FindStreamInfoStandard, &stream, 0);
    if (streams != INVALID_HANDLE_VALUE) {
        bool unnamedOnly = true;
        do {
            if (wcscmp(stream.cStreamName, L"::$DATA") != 0) unnamedOnly = false;
        } while (FindNextStreamW(streams, &stream));
        DWORD end = GetLastError();
        FindClose(streams);
        if (!unnamedOnly || end != ERROR_HANDLE_EOF) return false;
    } else {
        DWORD error = GetLastError();
        if (error != ERROR_HANDLE_EOF && error != ERROR_INVALID_FUNCTION &&
            error != ERROR_NOT_SUPPORTED) return false;
    }
    std::ifstream in(path, std::ios::binary | std::ios::ate);
    auto size = in.tellg();
    if (!in || size < 0 || size > static_cast<std::streamoff>(kMaxFileBytes)) return false;
    bytes.resize(static_cast<size_t>(size));
    in.seekg(0);
    if (size > 0) in.read(reinterpret_cast<char*>(bytes.data()), size);
    return in.good();
}
static std::vector<unsigned char> HeaderAAD(const EvFileHeader& hdr)
{
    const auto* p = reinterpret_cast<const unsigned char*>(&hdr);
    return std::vector<unsigned char>(p, p + sizeof(hdr));
}
// Reading a file and decrypting must succeed completely before any output is written.
static bool ReadPayload(const fs::path& path, bool trailer, std::vector<unsigned char>& enc)
{
    std::vector<unsigned char> bytes;
    if (!ReadBounded(path, bytes)) return false;
    size_t overhead = kPrimaryHeaderSize + (trailer ? kTrailerSize : 0);
    if (bytes.size() < overhead + 32) return false;
    enc.assign(bytes.begin() + kPrimaryHeaderSize, bytes.end() - (trailer ? kTrailerSize : 0));
    return true;
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

        if (fileSalt.size() != 32 || filePasswordKey.size() != 32 || masterKey.size() != 32)
            return false;
        std::vector<unsigned char> plain;
        if (!ReadBounded(filePath, plain) || plain.size() > 127u * 1024u * 1024u) return false;

        auto fileKey = GenerateRandomBytes(32);
        if (fileKey.empty()) return false;

        auto encKeyByPw = EncryptAuthenticated(fileKey, filePasswordKey);
        auto encKeyByMaster = EncryptAuthenticated(fileKey, masterKey);
        
        if (encKeyByPw.size() != 64 || encKeyByMaster.size() != 64) {
            return false;
        }

        EvFileHeader hdr = {};
        std::memcpy(hdr.salt, fileSalt.data(), 32);
        std::memcpy(hdr.encKeyByPw, encKeyByPw.data(), 64);
        std::memcpy(hdr.encKeyByMaster, encKeyByMaster.data(), 64);
        auto enc = EncryptAuthenticated(plain, fileKey, HeaderAAD(hdr));
        SecureZeroMemory(plain.data(), plain.size());
        if (enc.empty()) return false;

        // Write atomically: temp file in the same directory, then replace
        // so a crash or full disk never leaves a half-written file.
        fs::path tmpPath = TempPathFor(filePath);
        {
            std::ofstream outFile(tmpPath, std::ios::binary | std::ios::trunc);
            if (!outFile) return false; // Handle permission issues

            bool good = WriteEvfFile(outFile, hdr, enc);
            outFile.close();
            if (!good) {
                fs::remove(tmpPath);
                return false;
            }
        }

        if (!ReplaceAtomically(tmpPath, filePath, true))
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
    bool usingMasterKey, bool verifyOnly = false)
{
    try {
        EvFileHeader hdr;
        bool hasTrailer = false, authenticated = false;
        EvHeaderState st = ReadEvHeader(filePath, hdr, hasTrailer, &authenticated);
        if (st == EvHeaderState::None || st == EvHeaderState::Corrupt) return -1;
        std::vector<unsigned char> enc;
        if (!ReadPayload(filePath, hasTrailer, enc)) return 0;
        std::vector<unsigned char> encKeyByPw(hdr.encKeyByPw, hdr.encKeyByPw + 64);
        std::vector<unsigned char> encKeyByMaster(hdr.encKeyByMaster, hdr.encKeyByMaster + 64);
        std::vector<unsigned char> fileKey;
        if (usingMasterKey) {
            fileKey = DecryptBuffer(encKeyByMaster, masterKey);
        } else {
            fileKey = DecryptBuffer(encKeyByPw, pwKey);
        }

        if (fileKey.empty() || fileKey.size() != 32) return 0;

        std::vector<unsigned char> plain;
        bool valid = DecryptChecked(enc, fileKey, plain,
            authenticated ? HeaderAAD(hdr) : std::vector<unsigned char>{}, authenticated);
        SecureZeroMemory(fileKey.data(), fileKey.size());
        if (!valid) return 0;
        if (verifyOnly) { SecureZeroMemory(plain.data(), plain.size()); return 1; }

        // Write atomically: temp file in the same directory, then replace.
        fs::path tmpPath = TempPathFor(filePath);
        {
            std::ofstream outFile(tmpPath, std::ios::binary | std::ios::trunc);
            if (!outFile) return 0;
            if (!plain.empty())
                outFile.write(reinterpret_cast<const char*>(plain.data()), plain.size());

            outFile.flush();
            bool good = outFile.good();
            outFile.close();
            if (!good) {
                fs::remove(tmpPath);
                return 0;
            }
        }

        if (!ReplaceAtomically(tmpPath, filePath, false))
        {
            fs::remove(tmpPath);
            return 0;
        }

        return 1;
    } catch (...) {
        return 0;
    }
}

// Refuse links/reparse points and inaccessible entries before a batch starts.
// This avoids silently declaring success over skipped subfolders or encrypting
// a linked file outside the selected folder.
static bool CollectTargetFiles(const fs::path& target, std::vector<fs::path>& files)
{
    auto add = [&](const fs::path& path) {
        DWORD attrs = GetFileAttributesW(path.c_str());
        if (attrs == INVALID_FILE_ATTRIBUTES || (attrs & FILE_ATTRIBUTE_REPARSE_POINT))
            throw std::runtime_error("inaccessible path or link");
        if (!(attrs & FILE_ATTRIBUTE_DIRECTORY)) files.push_back(path);
    };
    try {
        add(target);
        if (fs::is_directory(target))
            for (const auto& entry : fs::recursive_directory_iterator(target)) add(entry.path());
        return true;
    } catch (...) {
        ShowError(L"EchoVault", L"Folder scan failed: inaccessible entries or links were found. Nothing was changed. Select ordinary local files instead.");
        return false;
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

    std::vector<fs::path> targets;
    if (!CollectTargetFiles(target, targets)) return false;
    if (MessageBoxW(nullptr,
        L"Close programs using these files and keep a tested backup before continuing.\n\n"
        L"Files stay in their current locations and keep their names and extensions. "
        L"For a folder, only the existing file contents are encrypted; folder names and file names stay visible. "
        L"New files added later are not automatically encrypted.\n\nContinue?",
        L"EchoVault - Encrypt", MB_YESNO | MB_ICONWARNING | MB_DEFBUTTON2) != IDYES) return false;
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
    auto master = GetMasterKeyOnDemand();
    if (master.size() != 32 || fileSalt.size() != 32 || pwKey.size() != 32) return false;

    try {
        if (fs::is_regular_file(target)) {
            if (!EncryptSingleFile(target, pwKey, fileSalt, master)) {
                ShowError(L"EchoVault", (L"Failed to encrypt. Check free disk space, permissions, open programs, and the 127 MiB file limit:\n" + target.wstring()).c_str());
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
            for (const auto& p : targets) {
                if (IsEncrypted(p)) continue;
                if (EncryptSingleFile(p, pwKey, fileSalt, master)) {
                    ++ok;
                    EnsureExtensionIntercepted(p.extension().wstring());
                    EvRegister(p.wstring());
                } else ++fail;
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

    try {
        std::vector<fs::path> files;
        if (!CollectTargetFiles(target, files)) return false;
        std::vector<fs::path> encrypted;
        for (const auto& p : files) if (IsEncrypted(p)) encrypted.push_back(p);
        if (encrypted.empty()) {
            ShowError(L"EchoVault", L"No encrypted files found. Nothing was changed.");
            return false;
        }
        std::vector<unsigned char> sampleSalt;
        if (!ExtractSalt(encrypted.front(), sampleSalt)) return false;
        bool usingMaster = false;
        std::wstring password;
        std::vector<unsigned char> master;
        for (;;) {
            auto answer = PromptPassword(L"EchoVault - Decrypt",
                L"Enter the file password. Files with other passwords stay encrypted.",
                true, L"Use Master Password");
            if (answer.result == PasswordResult::Cancel) return false;
            usingMaster = answer.result == PasswordResult::ForgotPassword;
            if (usingMaster) {
                master = GetMasterKeyOnDemand();
                if (master.size() != 32) return false;
            } else password = answer.password;
            auto key = usingMaster ? std::vector<unsigned char>{} : DeriveKey(password, sampleSalt);
            int result = DecryptSingleFile(encrypted.front(), key, master, usingMaster, true);
            SecureZeroMemory(key.data(), key.size());
            if (result == 1) break;
            ShowError(L"EchoVault", L"Password incorrect, file damaged, or file exceeds the size limit. Nothing was changed.");
            if (usingMaster) return false;
        }
        int ok = 0, fail = 0;
        std::wstring failed;
        for (const auto& p : encrypted) {
            std::vector<unsigned char> salt;
            int result = 0;
            if (ExtractSalt(p, salt)) {
                auto key = usingMaster ? std::vector<unsigned char>{} : DeriveKey(password, salt);
                result = DecryptSingleFile(p, key, master, usingMaster);
                SecureZeroMemory(key.data(), key.size());
            }
            if (result == 1) { ++ok; EvUnregister(p.wstring()); }
            else { ++fail; if (fail <= 10) failed += L"\n" + p.wstring(); }
        }
        SecureZeroMemory(password.data(), password.size() * sizeof(wchar_t));
        SecureZeroMemory(master.data(), master.size());
        if (fail == 0) EvUnregister(target.wstring());
        std::wstring message = L"Decryption finished. These files remain unlocked until you encrypt them again.\n\nSucceeded: " +
            std::to_wstring(ok) + L"\nFailed (unchanged): " + std::to_wstring(fail) + failed;
        if (fail) ShowError(L"EchoVault", message);
        else if (showResult) ShowInfo(L"EchoVault", message);
        return fail == 0;
    } catch (...) {
        ShowError(L"EchoVault", L"Could not finish reading the folder. Some files may remain encrypted.");
        return false;
    }
}

// ---- Temporary unlock (auto re-lock on close) --------------------

UnlockResult UnlockFileForOpen(const std::filesystem::path& target)
{
    UnlockResult out;
    EvGate gate(target);   // driver: allow us to read it; re-deny on failure

    EvFileHeader hdr = {};
    bool hasTrailer = false, authenticated = false;
    std::vector<unsigned char> encContent;
    auto state = ReadEvHeader(target, hdr, hasTrailer, &authenticated);
    if (state == EvHeaderState::None || state == EvHeaderState::Corrupt ||
        !ReadPayload(target, hasTrailer, encContent)) return out;
    out.salt.assign(hdr.salt, hdr.salt + 32);
    out.encKeyByPw.assign(hdr.encKeyByPw, hdr.encKeyByPw + 64);
    out.encKeyByMaster.assign(hdr.encKeyByMaster, hdr.encKeyByMaster + 64);

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
    std::vector<unsigned char> plain;
    if (!DecryptChecked(encContent, out.fileKey, plain,
            authenticated ? HeaderAAD(hdr) : std::vector<unsigned char>{}, authenticated))
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
        o.flush();
        bool good = o.good();
        o.close();
        if (!good) { fs::remove(tmpPath); return out; }
    }
    if (!ReplaceAtomically(tmpPath, target, false))
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
    if (!unlock.success || unlock.fileKey.size() != 32 ||
        unlock.salt.size() != 32 || unlock.encKeyByPw.size() != 64 || unlock.encKeyByMaster.size() != 64)
        return false;
    if (IsEncrypted(target)) return true;   // already locked again

    try {
        std::vector<unsigned char> plain;
        if (!ReadBounded(target, plain) || plain.size() > 127u * 1024u * 1024u) return false;
        EvFileHeader hdr = {};
        std::memcpy(hdr.salt, unlock.salt.data(), 32);
        std::memcpy(hdr.encKeyByPw, unlock.encKeyByPw.data(), 64);
        std::memcpy(hdr.encKeyByMaster, unlock.encKeyByMaster.data(), 64);
        auto enc = EncryptAuthenticated(plain, unlock.fileKey, HeaderAAD(hdr));
        SecureZeroMemory(plain.data(), plain.size());
        if (enc.empty()) return false;

        // Rebuild the ORIGINAL header so the file keeps its password. The
        // trailer is written too, so a damaged primary header is repaired
        // the next time the file is unlocked and re-locked.
        fs::path tmpPath = TempPathFor(target);
        {
            std::ofstream o(tmpPath, std::ios::binary | std::ios::trunc);
            if (!o) return false;
            bool good = WriteEvfFile(o, hdr, enc);
            o.close();
            if (!good) { fs::remove(tmpPath); return false; }
        }
        if (!ReplaceAtomically(tmpPath, target, true))
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

static bool RewrapSingleFile(const fs::path& p, const std::wstring& oldPassword,
    bool usingMaster, const std::vector<unsigned char>& master,
    const std::vector<unsigned char>& newSalt, const std::vector<unsigned char>& newPwKey)
{
    if (newSalt.size() != 32 || newPwKey.size() != 32) return false;
        try {
            EvFileHeader hdr;
            bool hasTrailer = false, authenticated = false;
            EvHeaderState st = ReadEvHeader(p, hdr, hasTrailer, &authenticated);
            if (st == EvHeaderState::None || st == EvHeaderState::Corrupt) { return false; }
            std::vector<unsigned char> content;
            if (!ReadPayload(p, hasTrailer, content)) { return false; }

            std::vector<unsigned char> encKeyByPw(hdr.encKeyByPw, hdr.encKeyByPw + 64);
            std::vector<unsigned char> encKeyByMaster(hdr.encKeyByMaster, hdr.encKeyByMaster + 64);

            std::vector<unsigned char> fileKey;
            if (usingMaster)
                fileKey = DecryptBuffer(encKeyByMaster, master);
            else {
                auto key = DeriveKey(oldPassword, std::vector<unsigned char>(hdr.salt, hdr.salt + 32));
                fileKey = DecryptBuffer(encKeyByPw, key);
                SecureZeroMemory(key.data(), key.size());
            }
            if (fileKey.size() != 32) { return false; }

            std::vector<unsigned char> plain;
            if (!DecryptChecked(content, fileKey, plain,
                    authenticated ? HeaderAAD(hdr) : std::vector<unsigned char>{}, authenticated))
            { return false; }
            auto newEncKeyByPw = EncryptAuthenticated(fileKey, newPwKey);
            if (newEncKeyByPw.size() != 64) { return false; }

            EvFileHeader newHdr = {};
            std::memcpy(newHdr.salt, newSalt.data(), 32);
            std::memcpy(newHdr.encKeyByPw, newEncKeyByPw.data(), 64);
            std::memcpy(newHdr.encKeyByMaster, hdr.encKeyByMaster, 64);

            content = EncryptAuthenticated(plain, fileKey, HeaderAAD(newHdr));
            SecureZeroMemory(plain.data(), plain.size());
            SecureZeroMemory(fileKey.data(), fileKey.size());
            if (content.empty()) { return false; }

            // Rewrite the whole file atomically so BOTH header copies
            // (primary + trailer) carry the new password.
            fs::path tmpPath = TempPathFor(p);
            {
                std::ofstream o(tmpPath, std::ios::binary | std::ios::trunc);
                if (!o) { return false; }
                bool good = WriteEvfFile(o, newHdr, content);
                o.close();
                if (!good) { fs::remove(tmpPath); return false; }
            }
            if (!ReplaceAtomically(tmpPath, p, true))
            {
                fs::remove(tmpPath);
                return false;
            }
            EvRegister(p.wstring());   // driver: keep the path gated
            return true;
        } catch (...) {
            return false;
        }

}

bool ChangeFilePassword(const std::filesystem::path& target)
{
    EvGate gate(target);   // driver: allow reads during this operation

    std::vector<fs::path> selected, evFiles;
    if (!CollectTargetFiles(target, selected)) return false;
    for (const auto& p : selected) if (IsEncrypted(p)) evFiles.push_back(p);
    if (evFiles.empty()) {
        ShowError(L"EchoVault", L"No encrypted files found. Nothing was changed.");
        return false;
    }

    std::vector<unsigned char> sampleSalt;
    if (!ExtractSalt(evFiles[0], sampleSalt)) {
        ShowError(L"EchoVault", L"Could not read the encrypted file format.");
        return false;
    }

    std::vector<unsigned char> oldPwKey;
    std::wstring oldPassword;
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

        oldPassword = a1.password;
        oldPwKey = DeriveKey(oldPassword, sampleSalt);
        if (DecryptSingleFile(evFiles.front(), oldPwKey, {}, false, true) == 1) break;
        ShowError(L"EchoVault", L"Incorrect password or damaged file. Nothing was changed.");
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
    if (newSalt.size() != 32 || newPwKey.size() != 32) return false;

    int ok = 0, fail = 0;
    auto master = usingMaster ? GetMasterKeyOnDemand() : std::vector<unsigned char>{};
    if (usingMaster && master.size() != 32) return false;
    for (const auto& p : evFiles) {
        if (RewrapSingleFile(p, oldPassword, usingMaster, master, newSalt, newPwKey)) ++ok;
        else ++fail;
    }
    SecureZeroMemory(oldPassword.data(), oldPassword.size() * sizeof(wchar_t));
    SecureZeroMemory(oldPwKey.data(), oldPwKey.size());
    SecureZeroMemory(newPwKey.data(), newPwKey.size());
    std::wstring msg = L"Password Change complete.\n\n"
        L"Succeeded: " + std::to_wstring(ok) + L"\n"
        L"Failed: "    + std::to_wstring(fail);
    if (fail > 0) ShowError(L"EchoVault", msg);
    else ShowInfo(L"EchoVault", msg);

    return fail == 0;
}

// ---- Headless self-test (EchoVault.exe --selftest) --------------

int RunSelfTest(const fs::path& outputDirectory)
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

    // Every invocation owns a fresh test directory. Never clear a shared
    // directory or touch the user's vault database during a test.
    fs::path base = outputDirectory.empty() ? fs::temp_directory_path() / L"EchoVault-tests" : outputDirectory;
    std::error_code ec;
    fs::create_directories(base, ec);
    if (ec) return 2;
    fs::path dir = base / (L"run-" + std::to_wstring(GetCurrentProcessId()) + L"-" + std::to_wstring(GetTickCount64()));
    fs::create_directories(dir, ec);
    if (ec) return 2;
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
        if (!in || s < 0) { check(false, L"test file could not be read"); return v; }
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
        DWORD attrs = GetFileAttributesW(p.c_str());
        SetFileAttributesW(p.c_str(), attrs & ~FILE_ATTRIBUTE_READONLY);
        std::fstream f(p, std::ios::in | std::ios::out | std::ios::binary);
        std::vector<unsigned char> junk(n, 0x5A);   // 'Z' — clearly not original
        f.seekp(off);
        f.write(reinterpret_cast<char*>(junk.data()), n);
        f.close();
        SetFileAttributesW(p.c_str(), attrs);
    };

    line(L"== EchoVault self-test ==");

    // ---- Baseline: encrypt / decrypt round-trip ----
    {
        std::ofstream o(file, std::ios::binary);
        o.write(plain, plainLen);
    }
    check(!IsEncrypted(file), L"plain file not flagged as encrypted");
    check(EncryptSingleFile(file, pwKey, salt, masterKey), L"encrypt succeeds");
    check(IsEncrypted(file), L"encrypted file detected (EVF4)");
    check(IsReadOnlyFile(file), L"encrypted file is read-only against accidental overwrite");
    check(DecryptSingleFile(file, pwKey, {}, false) == 1, L"decrypt round-trip succeeds");
    check(contentMatches(readAll(file)), L"round-trip content matches");
    check(!IsEncrypted(file), L"file plain after decrypt");
    check(!IsReadOnlyFile(file), L"decrypted file is writable again");

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
        check(IsReadOnlyFile(file), L"relocked file is read-only again");
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
        check(IsEncrypted(file), L"payload recognizes file after both outer markers damaged");
        check(DecryptSingleFile(file, pwKey, {}, false) == 1,
              L"both outer markers recovered using authenticated header and payload");
        check(contentMatches(readAll(file)), L"content matches after both markers damaged");
    }

    #include "tests/file-safety-cases.inc"

    // ---- No stray temp files left behind ----
    {
        int temps = 0;
        for (auto& e : fs::directory_iterator(dir, ec))
            if (e.path().filename().wstring().find(L".evtmp.") != std::wstring::npos)
                temps++;
        check(temps == 0, L"no stray temp files left");
    }

    for (auto& entry : fs::directory_iterator(dir, ec))
        if (entry.is_regular_file()) SetFileAttributesW(entry.path().c_str(), FILE_ATTRIBUTE_NORMAL);
    fs::remove_all(dir, ec);

    line(fails == 0 ? L"ALL TESTS PASSED" : L"SOME TESTS FAILED");

    // Write the log next to vault.db so it is easy to find.
    {
        std::ofstream f(base / L"selftest.log", std::ios::trunc);
        if (!f) return 2;
        for (auto& ch : log)
            f << static_cast<char>(ch);
    }
    return fails == 0 ? 0 : 1;
}
