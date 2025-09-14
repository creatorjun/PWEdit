#pragma once

#include <windows.h>
#include <string>
#include <vector>

class PasswordChanger
{
public:
    PasswordChanger();
    ~PasswordChanger();

    // ��й�ȣ ���� ���̾�α� ǥ��
    bool ShowPasswordChangeDialog(HWND hParent, const std::wstring& windowsPath, const std::wstring& username);

private:
    // ���̾�α� ���ν���
    static INT_PTR CALLBACK PasswordDialogProc(HWND hDlg, UINT message, WPARAM wParam, LPARAM lParam);
    INT_PTR HandleDialogMessage(HWND hDlg, UINT message, WPARAM wParam, LPARAM lParam);

    // SAM ���� ����
    bool ChangePasswordViaSAM(const std::wstring& windowsPath, const std::wstring& username, const std::wstring& newPassword);

    // SAM ���� �Լ���
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
