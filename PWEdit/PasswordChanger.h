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
    // UI �޽��� ó�� �Լ�
    static INT_PTR CALLBACK PasswordDialogProc(HWND hDlg, UINT message, WPARAM wParam, LPARAM lParam);
    INT_PTR HandleDialogMessage(HWND hDlg, UINT message, WPARAM wParam, LPARAM lParam);

    // SAM ������ ������ ���� �ٽ� �Լ���
    bool ChangePasswordViaSAM(const std::wstring& windowsPath, const std::wstring& username, const std::wstring& newPassword);
    DWORD FindUserRID(HKEY hSAM, const std::wstring& username);
    bool UnlockAndEnableAccount(HKEY hSAM, DWORD rid, bool passwordIsSet);
    bool ClearUserPassword(HKEY hSAM, DWORD rid);
    bool SetUserPassword(HKEY hSAM, DWORD rid, const std::wstring& password);

    // ntpwedit ��ȣȭ ������ ���� ����� �Լ���
    void SidToKey(DWORD rid, bool isSecondKey, BYTE* desKey);
    void StrToKey(const BYTE* str, BYTE* key);
    bool DesEncrypt(const BYTE* key, const BYTE* data, BYTE* encryptedData);

    // ��� ������
    HWND m_hParent;
    std::wstring m_windowsPath;
    std::wstring m_username;
    std::wstring m_newPassword;
    bool m_result;
};