#include "MainWindow.h"
#include <shlobj.h>
#include "resource.h"

// 정적 브러시 초기화
HBRUSH MainWindow::s_hBackgroundBrush = nullptr;

MainWindow::MainWindow(HINSTANCE hInstance)
    : m_hInstance(hInstance)
    , m_hWnd(nullptr)
    , m_pUIComponents(std::make_unique<UIComponents>())
    , m_pUserManager(std::make_unique<WindowsUserManager>())
    , m_pPasswordChanger(std::make_unique<PasswordChanger>())
{
    // 배경 브러시 생성
    if (!s_hBackgroundBrush) {
        s_hBackgroundBrush = CreateSolidBrush(RGB(240, 240, 240));
    }
}

MainWindow::~MainWindow()
{
    // 정적 브러시는 프로그램 종료 시에만 삭제
}

int MainWindow::Run(int nCmdShow)
{
    // 윈도우 클래스 등록
    WNDCLASSEX wcex = { 0 };
    wcex.cbSize = sizeof(WNDCLASSEX);
    wcex.style = CS_HREDRAW | CS_VREDRAW;
    wcex.lpfnWndProc = WndProc;
    wcex.hInstance = m_hInstance;
    wcex.hIcon = LoadIcon(nullptr, IDI_APPLICATION); // 리소스 ID 문제 수정
    wcex.hCursor = LoadCursor(nullptr, IDC_ARROW);
    wcex.hbrBackground = s_hBackgroundBrush;
    wcex.lpszClassName = L"PWEditMainWindow";
    wcex.hIconSm = LoadIcon(nullptr, IDI_APPLICATION);

    if (!RegisterClassEx(&wcex)) {
        return FALSE;
    }

    // 메인 윈도우 생성
    m_hWnd = CreateWindow(
        L"PWEditMainWindow",
        L"PWEdit - Windows PE 비밀번호 관리 도구 v1.0",
        WS_OVERLAPPEDWINDOW & ~WS_MAXIMIZEBOX,
        CW_USEDEFAULT, CW_USEDEFAULT,
        900, 400,
        nullptr, nullptr, m_hInstance, this
    );

    if (!m_hWnd) {
        return FALSE;
    }

    ShowWindow(m_hWnd, nCmdShow);
    UpdateWindow(m_hWnd);

    // 시작 시 자동 드라이브 스캔
    PostMessage(m_hWnd, WM_COMMAND, MAKEWPARAM(IDC_AUTO_SCAN, 0), 0);

    // 메시지 루프
    MSG msg;
    while (GetMessage(&msg, nullptr, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }

    return static_cast<int>(msg.wParam);
}

LRESULT CALLBACK MainWindow::WndProc(HWND hWnd, UINT message, WPARAM wParam, LPARAM lParam)
{
    MainWindow* pThis = nullptr;

    if (message == WM_NCCREATE) {
        CREATESTRUCT* pcs = (CREATESTRUCT*)lParam;
        pThis = (MainWindow*)pcs->lpCreateParams;
        SetWindowLongPtr(hWnd, GWLP_USERDATA, (LONG_PTR)pThis);
        pThis->m_hWnd = hWnd;
    }
    else {
        pThis = (MainWindow*)GetWindowLongPtr(hWnd, GWLP_USERDATA);
    }

    if (pThis) {
        return pThis->HandleMessage(message, wParam, lParam);
    }

    return DefWindowProc(hWnd, message, wParam, lParam);
}

LRESULT MainWindow::HandleMessage(UINT message, WPARAM wParam, LPARAM lParam)
{
    switch (message) {
    case WM_CREATE:
        OnCreate();
        break;

    case WM_COMMAND:
        OnCommand(wParam, lParam);
        break;

    case WM_NOTIFY:
        OnNotify(lParam);
        break;

    case WM_SIZE:
        OnSize();
        break;

    case WM_CTLCOLORSTATIC:
        return OnCtlColorStatic((HDC)wParam); // LRESULT 반환

    case WM_DESTROY:
        PostQuitMessage(0);
        break;

    default:
        return DefWindowProc(m_hWnd, message, wParam, lParam);
    }
    return 0;
}

void MainWindow::OnCreate()
{
    m_pUIComponents->Initialize(m_hWnd, m_hInstance);
    SetStatus(L"PWEdit 비밀번호 관리 도구 준비 완료");
}

void MainWindow::OnSize()
{
    m_pUIComponents->OnWindowResize();
}

void MainWindow::OnCommand(WPARAM wParam, LPARAM lParam)
{
    switch (LOWORD(wParam)) {
    case IDC_BROWSE_BUTTON:
        BrowseFolder();
        break;
    case IDC_DRIVE_COMBO:
        if (HIWORD(wParam) == CBN_SELCHANGE) {
            RefreshUserList();
        }
        break;
    case IDC_PASSWORD_CHANGE_BUTTON:
        OnPasswordChange();
        break;
    case IDC_AUTO_SCAN:
        ScanDrives();
        break;
    }
}

void MainWindow::OnNotify(LPARAM lParam)
{
    LPNMHDR pnmh = (LPNMHDR)lParam;
    if (pnmh->idFrom == IDC_USER_LIST && pnmh->code == LVN_ITEMCHANGED) {
        LPNMLISTVIEW pnmv = (LPNMLISTVIEW)lParam;
        if (pnmv->uNewState & LVIS_SELECTED) {
            wchar_t username[256] = { 0 }; // 널 종료 보장
            ListView_GetItemText(m_pUIComponents->GetUserListHandle(), pnmv->iItem, 0, username, 255); // 버퍼 크기 -1
            SetStatus(std::wstring(L"선택된 사용자: ") + username);

            // 비밀번호 변경 버튼 활성화
            m_pUIComponents->EnablePasswordChangeButton(true);
        }
    }
}

LRESULT MainWindow::OnCtlColorStatic(HDC hdc)
{
    SetBkColor(hdc, RGB(240, 240, 240));
    return (LRESULT)s_hBackgroundBrush; // 정적 브러시 반환
}

void MainWindow::ScanDrives()
{
    SetStatus(L"드라이브를 스캔하는 중...");
    ShowProgress(true);

    std::vector<std::wstring> windowsDrives = m_pUserManager->scanWindowsDrives();
    m_pUIComponents->PopulateDriveCombo(windowsDrives);

    if (windowsDrives.empty()) {
        SetStatus(L"Windows 시스템을 찾을 수 없습니다.");
    }
    else {
        SetStatus(std::wstring(L"PWEdit: ") + std::to_wstring(windowsDrives.size()) + L"개의 Windows 시스템을 찾았습니다.");
        RefreshUserList();
    }

    ShowProgress(false);
}

void MainWindow::BrowseFolder()
{
    BROWSEINFO bi = { 0 };
    bi.hwndOwner = m_hWnd;
    bi.lpszTitle = L"Windows 폴더를 선택하세요";
    bi.ulFlags = BIF_RETURNONLYFSDIRS | BIF_NEWDIALOGSTYLE;

    LPITEMIDLIST pidl = SHBrowseForFolder(&bi);
    if (pidl) {
        wchar_t path[MAX_PATH] = { 0 }; // 널 종료 보장
        if (SHGetPathFromIDList(pidl, path)) {
            if (m_pUserManager->isValidWindowsSystem(path)) {
                m_currentWindowsPath = path;
                m_pUIComponents->UpdateSystemInfo(path);
                m_pUIComponents->AddManualSelection(path);
                RefreshUserList();
                SetStatus(L"Windows 시스템이 선택되었습니다.");
            }
            else {
                MessageBox(m_hWnd,
                    L"선택된 폴더는 유효한 Windows 시스템이 아닙니다.\nWindows 폴더를 선택했는지 확인하세요.",
                    L"PWEdit - 경고", MB_OK | MB_ICONWARNING);
            }
        }
        CoTaskMemFree(pidl);
    }
}

void MainWindow::RefreshUserList()
{
    std::wstring windowsPath = m_pUIComponents->GetSelectedWindowsPath();
    if (windowsPath.empty()) {
        windowsPath = m_currentWindowsPath; // 수동 선택된 경로 사용
    }

    if (windowsPath.empty()) return;

    m_currentWindowsPath = windowsPath;
    m_pUIComponents->UpdateSystemInfo(windowsPath);

    SetStatus(L"사용자 계정을 검색하는 중...");
    ShowProgress(true);

    std::vector<WindowsUserInfo> users = m_pUserManager->getLocalUsers(windowsPath);
    m_pUIComponents->UpdateUserList(users);
    m_pUIComponents->EnablePasswordChangeButton(false); // 사용자 선택 전에는 비활성화

    ShowProgress(false);
    SetStatus(std::wstring(L"PWEdit: ") + std::to_wstring(users.size()) + L"개의 사용자 계정을 찾았습니다.");
}

void MainWindow::OnPasswordChange()
{
    std::wstring selectedUser = m_pUIComponents->GetSelectedUser();
    if (selectedUser.empty()) {
        MessageBox(m_hWnd, L"사용자를 선택해주세요.", L"PWEdit - 알림", MB_OK | MB_ICONINFORMATION);
        return;
    }

    // 비밀번호 변경 다이얼로그 표시
    bool result = m_pPasswordChanger->ShowPasswordChangeDialog(m_hWnd, m_currentWindowsPath, selectedUser);

    if (result) {
        SetStatus(L"비밀번호가 성공적으로 변경되었습니다.");
        MessageBox(m_hWnd,
            L"비밀번호가 성공적으로 변경되었습니다!\n시스템을 재시작하고 새 비밀번호로 로그인하세요.",
            L"PWEdit - 성공", MB_OK | MB_ICONINFORMATION);
    }
}

void MainWindow::SetStatus(const std::wstring& text)
{
    m_pUIComponents->SetStatusText(text);
}

void MainWindow::ShowProgress(bool show)
{
    m_pUIComponents->ShowProgress(show);
}
