#include "PasswordChanger.h"
#include <shlwapi.h>
#include <wincrypt.h>
#include <vector>

#pragma comment(lib, "shlwapi.lib")
#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "advapi32.lib")

#define IDC_PASSWORD_EDIT       2001
#define IDC_CONFIRM_EDIT        2002

// ntpwedit 암호화 로직 C++ 구현
void PasswordChanger::StrToKey(const BYTE* str, BYTE* key)
{
    key[0] = str[0] >> 1;
    key[1] = ((str[0] & 0x01) << 6) | (str[1] >> 2);
    key[2] = ((str[1] & 0x03) << 5) | (str[2] >> 3);
    key[3] = ((str[2] & 0x07) << 4) | (str[3] >> 4);
    key[4] = ((str[3] & 0x0F) << 3) | (str[4] >> 5);
    key[5] = ((str[4] & 0x1F) << 2) | (str[5] >> 6);
    key[6] = ((str[5] & 0x3F) << 1) | (str[6] >> 7);
    key[7] = str[6] & 0x7F;
    for (int i = 0; i < 8; i++) {
        key[i] = (key[i] << 1);
    }
}

void PasswordChanger::SidToKey(DWORD rid, bool isSecondKey, BYTE* desKey)
{
    BYTE s[7];
    if (!isSecondKey) {
        s[0] = (BYTE)(rid & 0xFF);
        s[1] = (BYTE)((rid >> 8) & 0xFF);
        s[2] = (BYTE)((rid >> 16) & 0xFF);
        s[3] = (BYTE)((rid >> 24) & 0xFF);
        s[4] = s[0]; s[5] = s[1]; s[6] = s[2];
    }
    else {
        s[0] = (BYTE)((rid >> 24) & 0xFF);
        s[1] = (BYTE)(rid & 0xFF);
        s[2] = (BYTE)((rid >> 8) & 0xFF);
        s[3] = (BYTE)((rid >> 16) & 0xFF);
        s[4] = s[0]; s[5] = s[1]; s[6] = s[2];
    }
    StrToKey(s, desKey);
}

bool PasswordChanger::DesEncrypt(const BYTE* key, const BYTE* data, BYTE* encryptedData)
{
    HCRYPTPROV hProv = 0;
    HCRYPTKEY hKey = 0;
    bool success = false;

    struct DES_KEY_BLOB {
        BLOBHEADER header;
        DWORD dwKeySize;
        BYTE rgbKeyData[8];
    } keyBlob;

    if (!CryptAcquireContext(&hProv, nullptr, nullptr, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT)) return false;

    keyBlob.header.bType = PLAINTEXTKEYBLOB;
    keyBlob.header.bVersion = CUR_BLOB_VERSION;
    keyBlob.header.reserved = 0;
    keyBlob.header.aiKeyAlg = CALG_DES;
    keyBlob.dwKeySize = 8;
    memcpy(keyBlob.rgbKeyData, key, 8);

    if (CryptImportKey(hProv, (const BYTE*)&keyBlob, sizeof(keyBlob), 0, 0, &hKey)) {
        memcpy(encryptedData, data, 8);
        DWORD dataLen = 8;
        if (CryptEncrypt(hKey, 0, TRUE, 0, encryptedData, &dataLen, 8)) {
            success = true;
        }
        CryptDestroyKey(hKey);
    }
    CryptReleaseContext(hProv, 0);
    return success;
}

// --- 기존 클래스 멤버 함수들 ---

PasswordChanger::PasswordChanger() : m_hParent(nullptr), m_result(false) {}
PasswordChanger::~PasswordChanger() {}

bool PasswordChanger::ShowPasswordChangeDialog(HWND hParent, const std::wstring& windowsPath, const std::wstring& username)
{
    m_hParent = hParent; m_windowsPath = windowsPath; m_username = username; m_result = false;
    HWND hDlg = CreateWindow(L"#32770", L"비밀번호 변경", WS_POPUP | WS_CAPTION | WS_SYSMENU | WS_VISIBLE | DS_MODALFRAME, CW_USEDEFAULT, CW_USEDEFAULT, 320, 180, hParent, nullptr, GetModuleHandle(nullptr), this);
    if (!hDlg) { return false; }
    HFONT hFont = CreateFont(14, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE, DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY, DEFAULT_PITCH | FF_DONTCARE, L"맑은 고딕");
    HFONT hSmallFont = CreateFont(12, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE, DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY, DEFAULT_PITCH | FF_DONTCARE, L"맑은 고딕");
    HWND hPasswordLabel = CreateWindow(L"STATIC", L"새 비밀번호:", WS_VISIBLE | WS_CHILD, 20, 20, 80, 20, hDlg, nullptr, GetModuleHandle(nullptr), nullptr); SendMessage(hPasswordLabel, WM_SETFONT, (WPARAM)hFont, TRUE);
    HWND hPasswordEdit = CreateWindow(L"EDIT", L"", WS_VISIBLE | WS_CHILD | WS_BORDER | ES_PASSWORD | WS_TABSTOP, 110, 18, 180, 22, hDlg, (HMENU)IDC_PASSWORD_EDIT, GetModuleHandle(nullptr), nullptr); SendMessage(hPasswordEdit, WM_SETFONT, (WPARAM)hFont, TRUE);
    HWND hConfirmLabel = CreateWindow(L"STATIC", L"비밀번호 확인:", WS_VISIBLE | WS_CHILD, 20, 50, 80, 20, hDlg, nullptr, GetModuleHandle(nullptr), nullptr); SendMessage(hConfirmLabel, WM_SETFONT, (WPARAM)hFont, TRUE);
    HWND hConfirmEdit = CreateWindow(L"EDIT", L"", WS_VISIBLE | WS_CHILD | WS_BORDER | ES_PASSWORD | WS_TABSTOP, 110, 48, 180, 22, hDlg, (HMENU)IDC_CONFIRM_EDIT, GetModuleHandle(nullptr), nullptr); SendMessage(hConfirmEdit, WM_SETFONT, (WPARAM)hFont, TRUE);
    HWND hInfoLabel = CreateWindow(L"STATIC", L"※ 빈 칸으로 두면 비밀번호가 제거됩니다.", WS_VISIBLE | WS_CHILD | SS_LEFT, 20, 80, 270, 20, hDlg, nullptr, GetModuleHandle(nullptr), nullptr); SendMessage(hInfoLabel, WM_SETFONT, (WPARAM)hSmallFont, TRUE);
    HWND hOKButton = CreateWindow(L"BUTTON", L"변경", WS_VISIBLE | WS_CHILD | BS_DEFPUSHBUTTON | WS_TABSTOP, 150, 110, 60, 25, hDlg, (HMENU)IDOK, GetModuleHandle(nullptr), nullptr); SendMessage(hOKButton, WM_SETFONT, (WPARAM)hFont, TRUE);
    HWND hCancelButton = CreateWindow(L"BUTTON", L"취소", WS_VISIBLE | WS_CHILD | BS_PUSHBUTTON | WS_TABSTOP, 220, 110, 60, 25, hDlg, (HMENU)IDCANCEL, GetModuleHandle(nullptr), nullptr); SendMessage(hCancelButton, WM_SETFONT, (WPARAM)hFont, TRUE);
    SetFocus(hPasswordEdit);
    RECT rcParent, rcDlg; GetWindowRect(hParent, &rcParent); GetWindowRect(hDlg, &rcDlg); SetWindowPos(hDlg, nullptr, rcParent.left + (rcParent.right - rcParent.left - (rcDlg.right - rcDlg.left)) / 2, rcParent.top + (rcParent.bottom - rcParent.top - (rcDlg.bottom - rcDlg.top)) / 2, 0, 0, SWP_NOSIZE | SWP_NOZORDER);
    SetWindowLongPtr(hDlg, GWLP_USERDATA, (LONG_PTR)this); SetWindowLongPtr(hDlg, GWLP_WNDPROC, (LONG_PTR)PasswordDialogProc);
    EnableWindow(hParent, FALSE); MSG msg; while (GetMessage(&msg, nullptr, 0, 0)) { if (!IsDialogMessage(hDlg, &msg)) { TranslateMessage(&msg); DispatchMessage(&msg); } if (!IsWindow(hDlg)) { break; } } EnableWindow(hParent, TRUE); SetFocus(hParent);
    DeleteObject(hFont); DeleteObject(hSmallFont); return m_result;
}

INT_PTR CALLBACK PasswordChanger::PasswordDialogProc(HWND hDlg, UINT message, WPARAM wParam, LPARAM lParam)
{
    PasswordChanger* pThis = (PasswordChanger*)GetWindowLongPtr(hDlg, GWLP_USERDATA);
    if (pThis) { return pThis->HandleDialogMessage(hDlg, message, wParam, lParam); }
    return DefWindowProc(hDlg, message, wParam, lParam);
}

INT_PTR PasswordChanger::HandleDialogMessage(HWND hDlg, UINT message, WPARAM wParam, LPARAM lParam)
{
    switch (message) {
    case WM_COMMAND:
        switch (LOWORD(wParam)) {
        case IDOK: {
            wchar_t password[256] = { 0 }, passwordConfirm[256] = { 0 };
            GetDlgItemText(hDlg, IDC_PASSWORD_EDIT, password, 255);
            GetDlgItemText(hDlg, IDC_CONFIRM_EDIT, passwordConfirm, 255);
            if (wcscmp(password, passwordConfirm) != 0) {
                MessageBox(hDlg, L"비밀번호가 일치하지 않습니다.", L"오류", MB_OK | MB_ICONERROR);
                SetFocus(GetDlgItem(hDlg, IDC_PASSWORD_EDIT)); return TRUE;
            }
            m_newPassword = password;
            if (ChangePasswordViaSAM(m_windowsPath, m_username, m_newPassword)) {
                m_result = true; DestroyWindow(hDlg);
            }
            else { MessageBox(hDlg, L"비밀번호 변경에 실패했습니다.", L"오류", MB_OK | MB_ICONERROR); }
        } return TRUE;
        case IDCANCEL: m_result = false; DestroyWindow(hDlg); return TRUE;
        } break;
    case WM_CLOSE: m_result = false; DestroyWindow(hDlg); return TRUE;
    case WM_KEYDOWN: if (wParam == VK_ESCAPE) { m_result = false; DestroyWindow(hDlg); return TRUE; } break;
    }
    return DefWindowProc(hDlg, message, wParam, lParam);
}

bool PasswordChanger::ChangePasswordViaSAM(const std::wstring& windowsPath, const std::wstring& username, const std::wstring& newPassword)
{
    std::wstring samPath = windowsPath + L"\\System32\\config\\SAM";
    if (RegLoadKey(HKEY_LOCAL_MACHINE, L"TempSAM", samPath.c_str()) != ERROR_SUCCESS) { return false; }
    HKEY hSAM; bool success = false;
    if (RegOpenKeyEx(HKEY_LOCAL_MACHINE, L"TempSAM\\SAM\\Domains\\Account", 0, KEY_ALL_ACCESS, &hSAM) == ERROR_SUCCESS) {
        DWORD rid = FindUserRID(hSAM, username);
        if (rid != 0) {
            if (newPassword.empty()) {
                if (ClearUserPassword(hSAM, rid) && UnlockAndEnableAccount(hSAM, rid, false)) { success = true; }
            }
            else {
                if (SetUserPassword(hSAM, rid, newPassword) && UnlockAndEnableAccount(hSAM, rid, true)) { success = true; }
            }
        }
        RegCloseKey(hSAM);
    }
    RegUnLoadKey(HKEY_LOCAL_MACHINE, L"TempSAM"); return success;
}

DWORD PasswordChanger::FindUserRID(HKEY hSAM, const std::wstring& username)
{
    HKEY hUsersKey; if (RegOpenKeyEx(hSAM, L"Users\\Names", 0, KEY_READ, &hUsersKey) != ERROR_SUCCESS) { return 0; }
    HKEY hUserKey; DWORD rid = 0;
    if (RegOpenKeyEx(hUsersKey, username.c_str(), 0, KEY_READ, &hUserKey) == ERROR_SUCCESS) {
        DWORD dataSize = sizeof(DWORD), type;
        if (RegQueryValueEx(hUserKey, nullptr, nullptr, &type, (LPBYTE)&rid, &dataSize) == ERROR_SUCCESS) { rid = type; }
        RegCloseKey(hUserKey);
    }
    RegCloseKey(hUsersKey); return rid;
}

bool PasswordChanger::UnlockAndEnableAccount(HKEY hSAM, DWORD rid, bool passwordIsSet)
{
    wchar_t ridHex[16]; wsprintf(ridHex, L"Users\\%08X", rid);
    HKEY hUserKey; if (RegOpenKeyEx(hSAM, ridHex, 0, KEY_ALL_ACCESS, &hUserKey) != ERROR_SUCCESS) { return false; }
    DWORD dataSize = 0;
    if (RegQueryValueEx(hUserKey, L"F", nullptr, nullptr, nullptr, &dataSize) != ERROR_SUCCESS || dataSize == 0) { RegCloseKey(hUserKey); return false; }
    std::vector<BYTE> userData(dataSize);
    if (RegQueryValueEx(hUserKey, L"F", nullptr, nullptr, userData.data(), &dataSize) != ERROR_SUCCESS) { RegCloseKey(hUserKey); return false; }
    if (dataSize >= 0x3C) {
        DWORD* flags = (DWORD*)&userData[0x38];
        *flags &= ~0x00000001; // UF_ACCOUNTDISABLE
        *flags &= ~0x00000010; // UF_LOCKOUT
        if (passwordIsSet) { *flags &= ~0x00000020; } // UF_PASSWD_NOTREQD 해제
        else { *flags |= 0x00000020; }               // UF_PASSWD_NOTREQD 설정
        if (RegSetValueEx(hUserKey, L"F", 0, REG_BINARY, userData.data(), dataSize) == ERROR_SUCCESS) {
            RegCloseKey(hUserKey); return true;
        }
    }
    RegCloseKey(hUserKey); return false;
}

bool PasswordChanger::ClearUserPassword(HKEY hSAM, DWORD rid)
{
    wchar_t ridHex[16]; wsprintf(ridHex, L"Users\\%08X", rid);
    HKEY hUserKey; if (RegOpenKeyEx(hSAM, ridHex, 0, KEY_ALL_ACCESS, &hUserKey) != ERROR_SUCCESS) { return false; }
    DWORD dataSize = 0;
    if (RegQueryValueEx(hUserKey, L"V", nullptr, nullptr, nullptr, &dataSize) != ERROR_SUCCESS || dataSize < 0xCC) { RegCloseKey(hUserKey); return false; }
    std::vector<BYTE> vData(dataSize);
    if (RegQueryValueEx(hUserKey, L"V", nullptr, nullptr, vData.data(), &dataSize) != ERROR_SUCCESS) { RegCloseKey(hUserKey); return false; }
    *((DWORD*)&vData[0x9C]) = 0; // LM Hash Length
    *((DWORD*)&vData[0xAC]) = 0; // NT Hash Length
    if (RegSetValueEx(hUserKey, L"V", 0, REG_BINARY, vData.data(), dataSize) == ERROR_SUCCESS) {
        RegCloseKey(hUserKey); return true;
    }
    RegCloseKey(hUserKey); return false;
}

bool PasswordChanger::SetUserPassword(HKEY hSAM, DWORD rid, const std::wstring& password)
{
    // 1. 새 비밀번호의 NT MD4 해시 계산
    HCRYPTPROV hProv = 0; HCRYPTHASH hHash = 0; BYTE ntHash[16];
    if (!CryptAcquireContext(&hProv, nullptr, nullptr, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT)) return false;
    if (!CryptCreateHash(hProv, CALG_MD4, 0, 0, &hHash)) { CryptReleaseContext(hProv, 0); return false; }
    if (!CryptHashData(hHash, (const BYTE*)password.c_str(), (DWORD)password.length() * sizeof(wchar_t), 0)) { CryptDestroyHash(hHash); CryptReleaseContext(hProv, 0); return false; }
    DWORD hashLen = 16; CryptGetHashParam(hHash, HP_HASHVAL, ntHash, &hashLen, 0);
    CryptDestroyHash(hHash); CryptReleaseContext(hProv, 0);

    // 2. RID로부터 DES 키 2개 파생
    BYTE desKey1[8], desKey2[8];
    SidToKey(rid, false, desKey1);
    SidToKey(rid, true, desKey2);

    // 3. NT 해시를 DES 키로 암호화
    BYTE encryptedNtHash[16];
    if (!DesEncrypt(desKey1, ntHash, encryptedNtHash) ||
        !DesEncrypt(desKey2, ntHash + 8, encryptedNtHash + 8)) {
        return false;
    }

    // 4. SAM에서 V 데이터 읽기
    wchar_t ridHex[16]; wsprintf(ridHex, L"Users\\%08X", rid);
    HKEY hUserKey; if (RegOpenKeyEx(hSAM, ridHex, 0, KEY_ALL_ACCESS, &hUserKey) != ERROR_SUCCESS) return false;
    DWORD dataSize = 0;
    if (RegQueryValueEx(hUserKey, L"V", nullptr, nullptr, nullptr, &dataSize) != ERROR_SUCCESS || dataSize < 0xCC) { RegCloseKey(hUserKey); return false; }
    std::vector<BYTE> vData(dataSize);
    if (RegQueryValueEx(hUserKey, L"V", nullptr, nullptr, vData.data(), &dataSize) != ERROR_SUCCESS) { RegCloseKey(hUserKey); return false; }

    // 5. V 데이터의 정확한 위치에 해시와 길이를 씁니다. (결정적 오류 수정)
    DWORD ntHashOffset = *((DWORD*)&vData[0xA8]) + 0xCC;
    if (dataSize >= ntHashOffset + 16) {
        memcpy(&vData[ntHashOffset], encryptedNtHash, 16);
    }
    else {
        RegCloseKey(hUserKey); return false;
    }

    *((DWORD*)&vData[0x9C]) = 0;   // LM Hash Length
    *((DWORD*)&vData[0xAC]) = 16;  // NT Hash Length

    // 6. 수정된 V 데이터 저장
    if (RegSetValueEx(hUserKey, L"V", 0, REG_BINARY, vData.data(), dataSize) == ERROR_SUCCESS) {
        RegCloseKey(hUserKey); return true;
    }
    RegCloseKey(hUserKey); return false;
}