// Included inside RunSelfTest to exercise the same private operations as the UI.
{
    // AES-256-GCM zero-key/zero-nonce vector independently checked with .NET AesGcm.
    auto envelope = HexToBytes(L"45564734000000000000000000000000D0D1C8A799996BF0265B98B5D48AB919CEA7403D4D606B6E074EC5D3BAF39D18");
    std::vector<unsigned char> decoded;
    check(DecryptChecked(envelope, std::vector<unsigned char>(32, 0), decoded, {}, true) &&
          decoded == std::vector<unsigned char>(16, 0), L"AES-256-GCM external known-answer vector matches");
    auto aad = std::vector<unsigned char>{1,2,3};
    auto bound = EncryptAuthenticated(std::vector<unsigned char>{4,5,6}, fileKey, aad);
    aad[0] ^= 1;
    check(!DecryptChecked(bound, fileKey, decoded, aad, true), L"modified associated header data refused");
    bound[0] ^= 1;
    check(!DecryptChecked(bound, fileKey, decoded, {}, true), L"damaged GCM marker cannot downgrade to CBC");
}
{
    std::vector<unsigned char> empty, decoded;
    auto envelope = EncryptAuthenticated(empty, fileKey);
    check(envelope.size() == 32 && DecryptChecked(envelope, fileKey, decoded, {}, true) && decoded.empty(),
          L"authenticated empty payload is valid");
    auto cbcEmpty = EncryptBuffer(empty, fileKey);
    check(DecryptChecked(cbcEmpty, fileKey, decoded) && decoded.empty(), L"legacy CBC empty payload is valid");
    auto bad = envelope;
    if (!bad.empty()) bad.back() ^= 1;
    check(!DecryptChecked(bad, fileKey, decoded, {}, true), L"bad authentication tag refused");
    check(!DecryptChecked(envelope, GenerateRandomBytes(32), decoded, {}, true), L"wrong key refused");
    std::ofstream(file, std::ios::binary | std::ios::trunc).close();
    check(EncryptSingleFile(file, pwKey, salt, masterKey), L"empty file encrypts");
    check(DecryptSingleFile(file, pwKey, {}, false) == 1 && fs::file_size(file) == 0,
          L"empty file decrypts back to zero bytes");
    std::ofstream o(file, std::ios::binary | std::ios::trunc); o.write(plain, plainLen);
}
{
    check(EncryptSingleFile(file, pwKey, salt, masterKey), L"encrypt for refusal tests");
    auto before = readAll(file);
    auto wrong = DeriveKey(L"not the password", salt);
    check(DecryptSingleFile(file, wrong, {}, false) == 0 && readAll(file) == before,
          L"wrong password leaves encrypted bytes unchanged");
    check(DecryptSingleFile(file, pwKey, {}, false, true) == 1 && readAll(file) == before,
          L"password preflight never decrypts in place");
    HANDLE held = CreateFileW(file.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr,
                             OPEN_EXISTING, 0, nullptr);
    check(held != INVALID_HANDLE_VALUE, L"test obtains file lock");
    check(DecryptSingleFile(file, pwKey, {}, false) == 0 && readAll(file) == before && IsReadOnlyFile(file),
          L"replacement denied by open handle preserves encrypted original and read-only flag");
    if (held != INVALID_HANDLE_VALUE) CloseHandle(held);
    damage(file, kPrimaryHeaderSize + 32, 1);
    auto damaged = readAll(file);
    check(DecryptSingleFile(file, pwKey, {}, false) == 0 && readAll(file) == damaged,
          L"tampered ciphertext rejected without replacement");
    auto newSalt = GenerateRandomBytes(32);
    auto newKey = DeriveKey(L"new password", newSalt);
    check(!RewrapSingleFile(file, pw, false, {}, newSalt, newKey) && readAll(file) == damaged,
          L"password change refuses tampered content without replacement");
    SetFileAttributesW(file.c_str(), FILE_ATTRIBUTE_NORMAL);
    std::ofstream o(file, std::ios::binary | std::ios::trunc);
    o.write(reinterpret_cast<const char*>(before.data()), before.size()); o.close();
    check(RewrapSingleFile(file, pw, false, {}, newSalt, newKey), L"password change succeeds");
    auto changed = readAll(file);
    check(DecryptSingleFile(file, pwKey, {}, false) == 0 && readAll(file) == changed,
          L"old password no longer decrypts after password change");
    check(DecryptSingleFile(file, newKey, {}, false) == 1 && contentMatches(readAll(file)),
          L"new password decrypts matching content");
}
{
    std::vector<fs::path> batch;
    bool ok = true;
    for (int i = 0; i < 8; ++i) {
        auto p = dir / (L"unicode-\u0928\u092e\u0938\u094d\u0924\u0947 space " + std::to_wstring(i) + L".txt");
        { std::ofstream o(p, std::ios::binary); o.write(plain, plainLen); }
        auto independentSalt = GenerateRandomBytes(32);
        auto key = DeriveKey(pw, independentSalt);
        ok = EncryptSingleFile(p, key, independentSalt, masterKey) && ok;
        batch.push_back(p);
    }
    check(ok, L"eight independent encryption batches with Unicode filenames succeed");
    ok = true;
    for (const auto& p : batch) {
        std::vector<unsigned char> independentSalt;
        if (!ExtractSalt(p, independentSalt)) { ok = false; continue; }
        auto key = DeriveKey(pw, independentSalt);
        ok = DecryptSingleFile(p, key, {}, false) == 1 && contentMatches(readAll(p)) && ok;
    }
    check(ok, L"mixed-salt batch decrypts using only each file and its password, without vault.db");
    auto moved = dir / L"moved-renamed.txt";
    check(EncryptSingleFile(file, pwKey, salt, masterKey), L"encrypt for portability test");
    fs::rename(file, moved);
    check(DecryptSingleFile(moved, pwKey, {}, false) == 1 && contentMatches(readAll(moved)),
          L"renamed and moved file decrypts without a path database");
    fs::rename(moved, file);
    check(EncryptSingleFile(file, pwKey, salt, masterKey), L"encrypt for master recovery");
    check(DecryptSingleFile(file, {}, masterKey, true) == 1 && contentMatches(readAll(file)),
          L"matching master key decrypts");
    check(EncryptSingleFile(file, pwKey, salt, masterKey), L"encrypt for unrelated master test");
    auto before = readAll(file);
    check(DecryptSingleFile(file, {}, GenerateRandomBytes(32), true) == 0 && readAll(file) == before,
          L"unrelated computer's master key refused without changing file");
    check(DecryptSingleFile(file, pwKey, {}, false) == 1, L"file password still works after rejected master key");
}
check(!EvFilterAvailable() && !EvPortSend(0, L""),
      L"normal build has driver communications disabled");
{
    auto alias = dir / L"hardlink.txt";
    bool made = CreateHardLinkW(alias.c_str(), file.c_str(), nullptr) != FALSE;
    check(made, L"create hard-link test fixture");
    if (made) {
        auto before = readAll(file);
        check(!EncryptSingleFile(file, pwKey, salt, masterKey) && readAll(alias) == before,
              L"hard-linked plaintext refused without leaving an unencrypted alias");
        fs::remove(alias);
    }
    { std::ofstream stream(fs::path(file.wstring() + L":extra"), std::ios::binary); stream << "extra content"; }
    auto before = readAll(file);
    check(!EncryptSingleFile(file, pwKey, salt, masterKey) && readAll(file) == before,
          L"named data streams refused instead of silently losing stream contents");
}
