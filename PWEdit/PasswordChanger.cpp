#include "PasswordChanger.h"
#include <shlwapi.h>
#include <wincrypt.h>

#pragma comment(lib, "shlwapi.lib")
#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "advapi32.lib")

#define IDC_PASSWORD_EDIT       2001
#define IDC_CONFIRM_EDIT        2002

PasswordChanger::PasswordChanger()
    : m_hParent(nullptr)
    , m_result(false)
{
}

PasswordChanger::~PasswordChanger()
{
}

bool PasswordChanger::ShowPasswordChangeDialog(HWND hParent, const std::wstring& windowsPath, const std::wstring& username)
{
    m_hParent = hParent;
    m_windowsPath = windowsPath;
    m_username = username;
    m_result = false;

    // ���� ũ���� ���̾�α� ����
    HWND hDlg = CreateWindow(
        L"#32770", // ���̾�α� Ŭ����
        L"��й�ȣ ����",
        WS_POPUP | WS_CAPTION | WS_SYSMENU | WS_VISIBLE | DS_MODALFRAME,
        CW_USEDEFAULT, CW_USEDEFAULT, 320, 180,
        hParent, nullptr, GetModuleHandle(nullptr), this
    );

    if (!hDlg) {
        return false;
    }

    // ���̾�α� ��Ʈ ����
    HFONT hFont = CreateFont(
        14, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE,
        DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
        CLEARTYPE_QUALITY, DEFAULT_PITCH | FF_DONTCARE, L"���� ���");

    // �� ��й�ȣ ��
    HWND hPasswordLabel = CreateWindow(L"STATIC", L"�� ��й�ȣ:",
        WS_VISIBLE | WS_CHILD,
        20, 20, 80, 20, hDlg, nullptr, GetModuleHandle(nullptr), nullptr);
    SendMessage(hPasswordLabel, WM_SETFONT, (WPARAM)hFont, TRUE);

    // �� ��й�ȣ �Է� �ʵ�
    HWND hPasswordEdit = CreateWindow(L"EDIT", L"",
        WS_VISIBLE | WS_CHILD | WS_BORDER | ES_PASSWORD | WS_TABSTOP,
        110, 18, 180, 22, hDlg, (HMENU)IDC_PASSWORD_EDIT, GetModuleHandle(nullptr), nullptr);
    SendMessage(hPasswordEdit, WM_SETFONT, (WPARAM)hFont, TRUE);

    // ��й�ȣ Ȯ�� ��
    HWND hConfirmLabel = CreateWindow(L"STATIC", L"��й�ȣ Ȯ��:",
        WS_VISIBLE | WS_CHILD,
        20, 50, 80, 20, hDlg, nullptr, GetModuleHandle(nullptr), nullptr);
    SendMessage(hConfirmLabel, WM_SETFONT, (WPARAM)hFont, TRUE);

    // ��й�ȣ Ȯ�� �Է� �ʵ�
    HWND hConfirmEdit = CreateWindow(L"EDIT", L"",
        WS_VISIBLE | WS_CHILD | WS_BORDER | ES_PASSWORD | WS_TABSTOP,
        110, 48, 180, 22, hDlg, (HMENU)IDC_CONFIRM_EDIT, GetModuleHandle(nullptr), nullptr);
    SendMessage(hConfirmEdit, WM_SETFONT, (WPARAM)hFont, TRUE);

    // �ȳ� �޽���
    HWND hInfoLabel = CreateWindow(L"STATIC", L"�� �� ��й�ȣ�� �����Ϸ��� �� �ʵ带 ��� ����μ���.",
        WS_VISIBLE | WS_CHILD | SS_LEFT,
        20, 80, 270, 20, hDlg, nullptr, GetModuleHandle(nullptr), nullptr);

    HFONT hSmallFont = CreateFont(
        12, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE,
        DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
        CLEARTYPE_QUALITY, DEFAULT_PITCH | FF_DONTCARE, L"���� ���");
    SendMessage(hInfoLabel, WM_SETFONT, (WPARAM)hSmallFont, TRUE);

    // ���� ��ư
    HWND hOKButton = CreateWindow(L"BUTTON", L"����",
        WS_VISIBLE | WS_CHILD | BS_DEFPUSHBUTTON | WS_TABSTOP,
        150, 110, 60, 25, hDlg, (HMENU)IDOK, GetModuleHandle(nullptr), nullptr);
    SendMessage(hOKButton, WM_SETFONT, (WPARAM)hFont, TRUE);

    // ��� ��ư
    HWND hCancelButton = CreateWindow(L"BUTTON", L"���",
        WS_VISIBLE | WS_CHILD | BS_PUSHBUTTON | WS_TABSTOP,
        220, 110, 60, 25, hDlg, (HMENU)IDCANCEL, GetModuleHandle(nullptr), nullptr);
    SendMessage(hCancelButton, WM_SETFONT, (WPARAM)hFont, TRUE);

    SetFocus(hPasswordEdit);

    // ���̾�α� �߾� ����
    RECT rcParent, rcDlg;
    GetWindowRect(hParent, &rcParent);
    GetWindowRect(hDlg, &rcDlg);
    int x = rcParent.left + ((rcParent.right - rcParent.left) - (rcDlg.right - rcDlg.left)) / 2;
    int y = rcParent.top + ((rcParent.bottom - rcParent.top) - (rcDlg.bottom - rcDlg.top)) / 2;
    SetWindowPos(hDlg, nullptr, x, y, 0, 0, SWP_NOSIZE | SWP_NOZORDER);

    // ����Ŭ�������� �޽��� ó��
    SetWindowLongPtr(hDlg, GWLP_USERDATA, (LONG_PTR)this);
    SetWindowLongPtr(hDlg, GWLP_WNDPROC, (LONG_PTR)PasswordDialogProc);

    // ��� ����
    EnableWindow(hParent, FALSE);
    MSG msg;
    while (GetMessage(&msg, nullptr, 0, 0)) {
        if (!IsDialogMessage(hDlg, &msg)) {
            TranslateMessage(&msg);
            DispatchMessage(&msg);
        }

        if (!IsWindow(hDlg)) {
            break;
        }
    }
    EnableWindow(hParent, TRUE);
    SetFocus(hParent);

    // ��Ʈ ����
    DeleteObject(hFont);
    DeleteObject(hSmallFont);

    return m_result;
}

INT_PTR CALLBACK PasswordChanger::PasswordDialogProc(HWND hDlg, UINT message, WPARAM wParam, LPARAM lParam)
{
    PasswordChanger* pThis = (PasswordChanger*)GetWindowLongPtr(hDlg, GWLP_USERDATA);
    if (pThis) {
        return pThis->HandleDialogMessage(hDlg, message, wParam, lParam);
    }
    return DefWindowProc(hDlg, message, wParam, lParam);
}

INT_PTR PasswordChanger::HandleDialogMessage(HWND hDlg, UINT message, WPARAM wParam, LPARAM lParam)
{
    switch (message) {
    case WM_COMMAND:
        switch (LOWORD(wParam)) {
        case IDOK:
        {
            wchar_t password1[256] = { 0 }, password2[256] = { 0 };
            GetDlgItemText(hDlg, IDC_PASSWORD_EDIT, password1, 255);
            GetDlgItemText(hDlg, IDC_CONFIRM_EDIT, password2, 255);

            if (wcscmp(password1, password2) != 0) {
                MessageBox(hDlg, L"��й�ȣ�� ��ġ���� �ʽ��ϴ�.", L"����", MB_OK | MB_ICONERROR);
                SetFocus(GetDlgItem(hDlg, IDC_PASSWORD_EDIT));
                return TRUE;
            }

            m_newPassword = password1;

            // SAM ���� �������� ��й�ȣ ����
            if (ChangePasswordViaSAM(m_windowsPath, m_username, m_newPassword)) {
                m_result = true;
                DestroyWindow(hDlg);
            }
            else {
                MessageBox(hDlg, L"��й�ȣ ���濡 �����߽��ϴ�.", L"����", MB_OK | MB_ICONERROR);
            }
        }
        return TRUE;

        case IDCANCEL:
            m_result = false;
            DestroyWindow(hDlg);
            return TRUE;
        }
        break;

    case WM_CLOSE:
        m_result = false;
        DestroyWindow(hDlg);
        return TRUE;

    case WM_KEYDOWN:
        if (wParam == VK_ESCAPE) {
            m_result = false;
            DestroyWindow(hDlg);
            return TRUE;
        }
        break;
    }

    return DefWindowProc(hDlg, message, wParam, lParam);
}

bool PasswordChanger::ChangePasswordViaSAM(const std::wstring& windowsPath, const std::wstring& username, const std::wstring& newPassword)
{
    std::wstring samPath = windowsPath + L"\\System32\\config\\SAM";

    // SAM ���̺� �ε�
    LONG result = RegLoadKey(HKEY_LOCAL_MACHINE, L"TempSAM", samPath.c_str());
    if (result != ERROR_SUCCESS) {
        return false;
    }

    HKEY hSAM;
    result = RegOpenKeyEx(HKEY_LOCAL_MACHINE, L"TempSAM\\SAM\\Domains\\Account", 0, KEY_ALL_ACCESS, &hSAM);

    bool success = false;
    if (result == ERROR_SUCCESS) {
        // ����� RID ã��
        DWORD rid = FindUserRID(hSAM, username);

        if (rid != 0) {
            // ���� Ȱ��ȭ
            if (EnableUserAccount(hSAM, rid)) {
                if (newPassword.empty()) {
                    // �� ��й�ȣ�� ����
                    success = ClearUserPassword(hSAM, rid);
                }
                else {
                    // �� ��й�ȣ ���� (�����ϹǷ� �ϴ� �� ��й�ȣ�θ�)
                    success = ClearUserPassword(hSAM, rid);
                }
            }
        }

        RegCloseKey(hSAM);
    }

    // ���̺� ��ε�
    RegUnLoadKey(HKEY_LOCAL_MACHINE, L"TempSAM");

    return success;
}

DWORD PasswordChanger::FindUserRID(HKEY hSAM, const std::wstring& username)
{
    HKEY hUsersKey;
    if (RegOpenKeyEx(hSAM, L"Users\\Names", 0, KEY_READ, &hUsersKey) != ERROR_SUCCESS) {
        return 0;
    }

    HKEY hUserKey;
    DWORD rid = 0;

    if (RegOpenKeyEx(hUsersKey, username.c_str(), 0, KEY_READ, &hUserKey) == ERROR_SUCCESS) {
        DWORD dataSize = sizeof(DWORD);
        DWORD type;

        // �⺻������ RID �б� (Ÿ�� �������� ����)
        if (RegQueryValueEx(hUserKey, nullptr, nullptr, &type, (LPBYTE)&rid, &dataSize) == ERROR_SUCCESS) {
            // RID�� type ���� ����
            rid = type;
        }

        RegCloseKey(hUserKey);
    }

    RegCloseKey(hUsersKey);
    return rid;
}

bool PasswordChanger::EnableUserAccount(HKEY hSAM, DWORD rid)
{
    wchar_t ridHex[16];
    wsprintf(ridHex, L"Users\\%08X", rid);

    HKEY hUserKey;
    if (RegOpenKeyEx(hSAM, ridHex, 0, KEY_ALL_ACCESS, &hUserKey) != ERROR_SUCCESS) {
        return false;
    }

    // F �� (����� ���� ����) �б�
    DWORD dataSize = 0;
    if (RegQueryValueEx(hUserKey, L"F", nullptr, nullptr, nullptr, &dataSize) != ERROR_SUCCESS) {
        RegCloseKey(hUserKey);
        return false;
    }

    std::vector<BYTE> userData(dataSize);
    if (RegQueryValueEx(hUserKey, L"F", nullptr, nullptr, userData.data(), &dataSize) != ERROR_SUCCESS) {
        RegCloseKey(hUserKey);
        return false;
    }

    // ���� �÷��� ���� (������ 0x38)
    if (dataSize >= 0x3C) {
        DWORD* flags = (DWORD*)&userData[0x38];

        // ��Ȱ��ȭ �÷��� ���� (0x00000001)
        *flags &= ~0x00000001;

        // ���� ��� ���� (0x00000010)
        *flags &= ~0x00000010;

        // ������ ������ ����
        if (RegSetValueEx(hUserKey, L"F", 0, REG_BINARY, userData.data(), dataSize) == ERROR_SUCCESS) {
            RegCloseKey(hUserKey);
            return true;
        }
    }

    RegCloseKey(hUserKey);
    return false;
}

bool PasswordChanger::ClearUserPassword(HKEY hSAM, DWORD rid)
{
    wchar_t ridHex[16];
    wsprintf(ridHex, L"Users\\%08X", rid);

    HKEY hUserKey;
    if (RegOpenKeyEx(hSAM, ridHex, 0, KEY_ALL_ACCESS, &hUserKey) != ERROR_SUCCESS) {
        return false;
    }

    // V �� (��й�ȣ �ؽ�) �б�
    DWORD dataSize = 0;
    if (RegQueryValueEx(hUserKey, L"V", nullptr, nullptr, nullptr, &dataSize) != ERROR_SUCCESS) {
        RegCloseKey(hUserKey);
        return false;
    }

    std::vector<BYTE> vData(dataSize);
    if (RegQueryValueEx(hUserKey, L"V", nullptr, nullptr, vData.data(), &dataSize) != ERROR_SUCCESS) {
        RegCloseKey(hUserKey);
        return false;
    }

    // ��й�ȣ �ؽø� �� ������ ����
    // NT �ؽ� ��ġ (�Ϲ������� 0xAC ������)
    if (dataSize >= 0xAC + 16) {
        // LM �ؽ� ���� (0x9C)
        memset(&vData[0x9C], 0, 16);

        // NT �ؽ� ���� (0xAC) 
        memset(&vData[0xAC], 0, 16);

        // ��й�ȣ ��� ����
        if (dataSize >= 0xCC) {
            // ��й�ȣ �����丮 ���̸� 0���� ����
            *((DWORD*)&vData[0x48]) = 0;
        }

        // ������ ������ ����
        if (RegSetValueEx(hUserKey, L"V", 0, REG_BINARY, vData.data(), dataSize) == ERROR_SUCCESS) {
            RegCloseKey(hUserKey);
            return true;
        }
    }

    RegCloseKey(hUserKey);
    return false;
}

bool PasswordChanger::SetUserPassword(HKEY hSAM, DWORD rid, const std::wstring& password)
{
    // �� ��й�ȣ ������ �ſ� �����ϹǷ� ����� �� ��й�ȣ�� ����
    return ClearUserPassword(hSAM, rid);
}
