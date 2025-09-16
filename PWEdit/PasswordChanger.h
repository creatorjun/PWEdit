#pragma once
#include <Windows.h>
#include <string>
#include <vector>

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

    // ntpwedit 암호화 로직을 위한 도우미 함수들
    void SidToKey(DWORD rid, bool isSecondKey, BYTE* desKey);
    void StrToKey(const BYTE* str, BYTE* key);
    bool DesEncrypt(const BYTE* key, const BYTE* data, BYTE* encryptedData);

    // 멤버 변수들
    HWND m_hParent;
    std::wstring m_windowsPath;
    std::wstring m_username;
    std::wstring m_newPassword;
    bool m_result;
};