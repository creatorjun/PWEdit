#pragma once

// std::min, std::max와 Windows.h의 min/max 매크로 충돌 방지
#define NOMINMAX

#include <Windows.h>
#include <string>
#include <vector>

// ntpwedit의 암호화 로직을 C++로 포팅한 클래스
class NtpwCrypto
{
public:
    // DES 암호화에 사용되는 키 구조체
    struct symmetric_key {
        ULONG ek[32], dk[32];
    };

    // NTLM 해시 (MD4) 계산
    static void NtlmHash(const std::wstring& password, BYTE* ntHash);

    // RID로부터 DES 키 생성
    static void SidToKey(DWORD rid, bool isSecondKey, BYTE* desKey);

    // NT 해시를 DES로 암호화
    static bool EncryptNtHash(DWORD rid, const BYTE* ntHash, BYTE* encryptedNtHash);

private:
    // DES 암호화 내부 구현
    static void str_to_key(const BYTE* str, BYTE* key);
    static void des_setup(const BYTE* key, symmetric_key* skey);
    static void des_ecb_encrypt(const BYTE* pt, BYTE* ct, symmetric_key* skey);
};


class PasswordChanger
{
public:
    PasswordChanger();
    ~PasswordChanger();

    bool ShowPasswordChangeDialog(HWND hParent, const std::wstring& windowsPath, const std::wstring& username);

private:
    // UI 메시지 처리 함수
    static INT_PTR CALLBACK PasswordDialogProc(HWND hDlg, UINT message, WPARAM wParam, LPARAM lParam);
    INT_PTR HandleDialogMessage(HWND hDlg, UINT message, WPARAM wParam, LPARAM lParam);

    // SAM 데이터 수정을 위한 핵심 함수들
    bool ChangePasswordViaSAM(const std::wstring& windowsPath, const std::wstring& username, const std::wstring& newPassword);
    DWORD FindUserRID(HKEY hSAM, const std::wstring& username);
    bool UnlockAndEnableAccount(HKEY hSAM, DWORD rid, bool passwordIsSet);
    bool ClearUserPassword(HKEY hSAM, DWORD rid);
    bool SetUserPassword(HKEY hSAM, DWORD rid, const std::wstring& password);

    // 멤버 변수들
    HWND m_hParent;
    std::wstring m_windowsPath;
    std::wstring m_username;
    std::wstring m_newPassword;
    bool m_result;
};