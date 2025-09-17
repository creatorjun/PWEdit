#pragma once

// std::min, std::max�� Windows.h�� min/max ��ũ�� �浹 ����
#define NOMINMAX

#include <Windows.h>
#include <string>
#include <vector>

// ntpwedit�� ��ȣȭ ������ C++�� ������ Ŭ����
class NtpwCrypto
{
public:
    // DES ��ȣȭ�� ���Ǵ� Ű ����ü
    struct symmetric_key {
        ULONG ek[32], dk[32];
    };

    // NTLM �ؽ� (MD4) ���
    static void NtlmHash(const std::wstring& password, BYTE* ntHash);

    // RID�κ��� DES Ű ����
    static void SidToKey(DWORD rid, bool isSecondKey, BYTE* desKey);

    // NT �ؽø� DES�� ��ȣȭ
    static bool EncryptNtHash(DWORD rid, const BYTE* ntHash, BYTE* encryptedNtHash);

private:
    // DES ��ȣȭ ���� ����
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
    // UI �޽��� ó�� �Լ�
    static INT_PTR CALLBACK PasswordDialogProc(HWND hDlg, UINT message, WPARAM wParam, LPARAM lParam);
    INT_PTR HandleDialogMessage(HWND hDlg, UINT message, WPARAM wParam, LPARAM lParam);

    // SAM ������ ������ ���� �ٽ� �Լ���
    bool ChangePasswordViaSAM(const std::wstring& windowsPath, const std::wstring& username, const std::wstring& newPassword);
    DWORD FindUserRID(HKEY hSAM, const std::wstring& username);
    bool UnlockAndEnableAccount(HKEY hSAM, DWORD rid, bool passwordIsSet);
    bool ClearUserPassword(HKEY hSAM, DWORD rid);
    bool SetUserPassword(HKEY hSAM, DWORD rid, const std::wstring& password);

    // ��� ������
    HWND m_hParent;
    std::wstring m_windowsPath;
    std::wstring m_username;
    std::wstring m_newPassword;
    bool m_result;
};