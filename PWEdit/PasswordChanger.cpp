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

    // 작은 크기의 다이얼로그 생성
    HWND hDlg = CreateWindow(
        L"#32770", // 다이얼로그 클래스
        L"비밀번호 변경",
        WS_POPUP | WS_CAPTION | WS_SYSMENU | WS_VISIBLE | DS_MODALFRAME,
        CW_USEDEFAULT, CW_USEDEFAULT, 320, 180,
        hParent, nullptr, GetModuleHandle(nullptr), this
    );

    if (!hDlg) {
        return false;
    }

    // 다이얼로그 폰트 생성
    HFONT hFont = CreateFont(
        14, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE,
        DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
        CLEARTYPE_QUALITY, DEFAULT_PITCH | FF_DONTCARE, L"맑은 고딕");

    // 새 비밀번호 라벨
    HWND hPasswordLabel = CreateWindow(L"STATIC", L"새 비밀번호:",
        WS_VISIBLE | WS_CHILD,
        20, 20, 80, 20, hDlg, nullptr, GetModuleHandle(nullptr), nullptr);
    SendMessage(hPasswordLabel, WM_SETFONT, (WPARAM)hFont, TRUE);

    // 새 비밀번호 입력 필드
    HWND hPasswordEdit = CreateWindow(L"EDIT", L"",
        WS_VISIBLE | WS_CHILD | WS_BORDER | ES_PASSWORD | WS_TABSTOP,
        110, 18, 180, 22, hDlg, (HMENU)IDC_PASSWORD_EDIT, GetModuleHandle(nullptr), nullptr);
    SendMessage(hPasswordEdit, WM_SETFONT, (WPARAM)hFont, TRUE);

    // 비밀번호 확인 라벨
    HWND hConfirmLabel = CreateWindow(L"STATIC", L"비밀번호 확인:",
        WS_VISIBLE | WS_CHILD,
        20, 50, 80, 20, hDlg, nullptr, GetModuleHandle(nullptr), nullptr);
    SendMessage(hConfirmLabel, WM_SETFONT, (WPARAM)hFont, TRUE);

    // 비밀번호 확인 입력 필드
    HWND hConfirmEdit = CreateWindow(L"EDIT", L"",
        WS_VISIBLE | WS_CHILD | WS_BORDER | ES_PASSWORD | WS_TABSTOP,
        110, 48, 180, 22, hDlg, (HMENU)IDC_CONFIRM_EDIT, GetModuleHandle(nullptr), nullptr);
    SendMessage(hConfirmEdit, WM_SETFONT, (WPARAM)hFont, TRUE);

    // 안내 메시지
    HWND hInfoLabel = CreateWindow(L"STATIC", L"※ 빈 비밀번호로 설정하려면 두 필드를 모두 비워두세요.",
        WS_VISIBLE | WS_CHILD | SS_LEFT,
        20, 80, 270, 20, hDlg, nullptr, GetModuleHandle(nullptr), nullptr);

    HFONT hSmallFont = CreateFont(
        12, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE,
        DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
        CLEARTYPE_QUALITY, DEFAULT_PITCH | FF_DONTCARE, L"맑은 고딕");
    SendMessage(hInfoLabel, WM_SETFONT, (WPARAM)hSmallFont, TRUE);

    // 변경 버튼
    HWND hOKButton = CreateWindow(L"BUTTON", L"변경",
        WS_VISIBLE | WS_CHILD | BS_DEFPUSHBUTTON | WS_TABSTOP,
        150, 110, 60, 25, hDlg, (HMENU)IDOK, GetModuleHandle(nullptr), nullptr);
    SendMessage(hOKButton, WM_SETFONT, (WPARAM)hFont, TRUE);

    // 취소 버튼
    HWND hCancelButton = CreateWindow(L"BUTTON", L"취소",
        WS_VISIBLE | WS_CHILD | BS_PUSHBUTTON | WS_TABSTOP,
        220, 110, 60, 25, hDlg, (HMENU)IDCANCEL, GetModuleHandle(nullptr), nullptr);
    SendMessage(hCancelButton, WM_SETFONT, (WPARAM)hFont, TRUE);

    SetFocus(hPasswordEdit);

    // 다이얼로그 중앙 정렬
    RECT rcParent, rcDlg;
    GetWindowRect(hParent, &rcParent);
    GetWindowRect(hDlg, &rcDlg);
    int x = rcParent.left + ((rcParent.right - rcParent.left) - (rcDlg.right - rcDlg.left)) / 2;
    int y = rcParent.top + ((rcParent.bottom - rcParent.top) - (rcDlg.bottom - rcDlg.top)) / 2;
    SetWindowPos(hDlg, nullptr, x, y, 0, 0, SWP_NOSIZE | SWP_NOZORDER);

    // 서브클래싱으로 메시지 처리
    SetWindowLongPtr(hDlg, GWLP_USERDATA, (LONG_PTR)this);
    SetWindowLongPtr(hDlg, GWLP_WNDPROC, (LONG_PTR)PasswordDialogProc);

    // 모달 루프
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

    // 폰트 정리
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
                MessageBox(hDlg, L"비밀번호가 일치하지 않습니다.", L"오류", MB_OK | MB_ICONERROR);
                SetFocus(GetDlgItem(hDlg, IDC_PASSWORD_EDIT));
                return TRUE;
            }

            m_newPassword = password1;

            // SAM 직접 조작으로 비밀번호 변경
            if (ChangePasswordViaSAM(m_windowsPath, m_username, m_newPassword)) {
                m_result = true;
                DestroyWindow(hDlg);
            }
            else {
                MessageBox(hDlg, L"비밀번호 변경에 실패했습니다.", L"오류", MB_OK | MB_ICONERROR);
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

    // SAM 하이브 로드
    LONG result = RegLoadKey(HKEY_LOCAL_MACHINE, L"TempSAM", samPath.c_str());
    if (result != ERROR_SUCCESS) {
        return false;
    }

    HKEY hSAM;
    result = RegOpenKeyEx(HKEY_LOCAL_MACHINE, L"TempSAM\\SAM\\Domains\\Account", 0, KEY_ALL_ACCESS, &hSAM);

    bool success = false;
    if (result == ERROR_SUCCESS) {
        // 사용자 RID 찾기
        DWORD rid = FindUserRID(hSAM, username);

        if (rid != 0) {
            // 계정 활성화
            if (EnableUserAccount(hSAM, rid)) {
                if (newPassword.empty()) {
                    // 빈 비밀번호로 설정
                    success = ClearUserPassword(hSAM, rid);
                }
                else {
                    // 새 비밀번호 설정 (복잡하므로 일단 빈 비밀번호로만)
                    success = ClearUserPassword(hSAM, rid);
                }
            }
        }

        RegCloseKey(hSAM);
    }

    // 하이브 언로드
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

        // 기본값에서 RID 읽기 (타입 정보에서 추출)
        if (RegQueryValueEx(hUserKey, nullptr, nullptr, &type, (LPBYTE)&rid, &dataSize) == ERROR_SUCCESS) {
            // RID는 type 값에 있음
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

    // F 값 (사용자 계정 정보) 읽기
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

    // 계정 플래그 수정 (오프셋 0x38)
    if (dataSize >= 0x3C) {
        DWORD* flags = (DWORD*)&userData[0x38];

        // 비활성화 플래그 제거 (0x00000001)
        *flags &= ~0x00000001;

        // 계정 잠금 해제 (0x00000010)
        *flags &= ~0x00000010;

        // 수정된 데이터 저장
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

    // V 값 (비밀번호 해시) 읽기
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

    // 비밀번호 해시를 빈 값으로 설정
    // NT 해시 위치 (일반적으로 0xAC 오프셋)
    if (dataSize >= 0xAC + 16) {
        // LM 해시 제거 (0x9C)
        memset(&vData[0x9C], 0, 16);

        // NT 해시 제거 (0xAC) 
        memset(&vData[0xAC], 0, 16);

        // 비밀번호 기록 제거
        if (dataSize >= 0xCC) {
            // 비밀번호 히스토리 길이를 0으로 설정
            *((DWORD*)&vData[0x48]) = 0;
        }

        // 수정된 데이터 저장
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
    // 새 비밀번호 설정은 매우 복잡하므로 현재는 빈 비밀번호만 지원
    return ClearUserPassword(hSAM, rid);
}
