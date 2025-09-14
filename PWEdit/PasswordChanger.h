#pragma once

#include <windows.h>
#include <string>
#include <vector>

class PasswordChanger
{
public:
    PasswordChanger();
    ~PasswordChanger();

    // 비밀번호 변경 다이얼로그 표시
    bool ShowPasswordChangeDialog(HWND hParent, const std::wstring& windowsPath, const std::wstring& username);

private:
    // 다이얼로그 프로시저
    static INT_PTR CALLBACK PasswordDialogProc(HWND hDlg, UINT message, WPARAM wParam, LPARAM lParam);
    INT_PTR HandleDialogMessage(HWND hDlg, UINT message, WPARAM wParam, LPARAM lParam);

    // SAM 직접 조작
    bool ChangePasswordViaSAM(const std::wstring& windowsPath, const std::wstring& username, const std::wstring& newPassword);

    // SAM 헬퍼 함수들
    DWORD FindUserRID(HKEY hSAM, const std::wstring& username);
    bool EnableUserAccount(HKEY hSAM, DWORD rid);
    bool ClearUserPassword(HKEY hSAM, DWORD rid);
    bool SetUserPassword(HKEY hSAM, DWORD rid, const std::wstring& password);

private:
    HWND m_hParent;
    std::wstring m_windowsPath;
    std::wstring m_username;
    std::wstring m_newPassword;
    bool m_result;
};
