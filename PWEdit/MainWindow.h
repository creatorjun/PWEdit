#pragma once

#include <windows.h>
#include <string>
#include <memory>
#include "UIComponents.h"
#include "WindowsUserManager.h"
#include "PasswordChanger.h"

class MainWindow
{
public:
    MainWindow(HINSTANCE hInstance);
    ~MainWindow();

    int Run(int nCmdShow);

private:
    // 윈도우 프로시저
    static LRESULT CALLBACK WndProc(HWND hWnd, UINT message, WPARAM wParam, LPARAM lParam);
    LRESULT HandleMessage(UINT message, WPARAM wParam, LPARAM lParam);

    // 이벤트 핸들러
    void OnCreate();
    void OnSize();
    void OnCommand(WPARAM wParam, LPARAM lParam);
    void OnNotify(LPARAM lParam);
    LRESULT OnCtlColorStatic(HDC hdc); // void에서 LRESULT로 수정

    // 비즈니스 로직
    void ScanDrives();
    void BrowseFolder();
    void RefreshUserList();
    void OnPasswordChange();

    // 헬퍼 함수
    void SetStatus(const std::wstring& text);
    void ShowProgress(bool show);

private:
    HINSTANCE m_hInstance;
    HWND m_hWnd;
    std::wstring m_currentWindowsPath;

    // 정적 브러시 (메모리 누수 방지)
    static HBRUSH s_hBackgroundBrush;

    // 컴포넌트들
    std::unique_ptr<UIComponents> m_pUIComponents;
    std::unique_ptr<WindowsUserManager> m_pUserManager;
    std::unique_ptr<PasswordChanger> m_pPasswordChanger;
};
