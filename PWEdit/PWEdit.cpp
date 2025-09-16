#include "framework.h"
#include "PWEdit.h"
#include "MainWindow.h"
#include <objbase.h> // CoInitializeEx를 위해 추가

int APIENTRY wWinMain(_In_ HINSTANCE hInstance,
    _In_opt_ HINSTANCE hPrevInstance,
    _In_ LPWSTR    lpCmdLine,
    _In_ int       nCmdShow)
{
    UNREFERENCED_PARAMETER(hPrevInstance);
    UNREFERENCED_PARAMETER(lpCmdLine);

    // COM 라이브러리 초기화
    HRESULT hr = CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED | COINIT_DISABLE_OLE1DDE);
    if (FAILED(hr)) {
        MessageBox(nullptr, L"COM 라이브러리를 초기화할 수 없습니다.", L"치명적 오류", MB_OK | MB_ICONERROR);
        return 1;
    }

    MainWindow win(hInstance);
    int result = win.Run(nCmdShow);

    // COM 라이브러리 해제
    CoUninitialize();

    return result;
}