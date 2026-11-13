// Guest painting application for CPUEmu.
//
// Compiled with the host toolchain and executed under the emulator:
//   build-release\cpuemu.exe build\test-apps\paint.exe                interactive window
//   build-release\cpuemu.exe build\test-apps\paint.exe -- --selftest  headless verification
//   build-release\cpuemu.exe build\test-apps\paint.exe -- --screenshot stable visual probe
//   build-release\cpuemu.exe build\test-apps\paint.exe -- --sync-selftest Win32 sync verification
//
// The interactive mode exercises the guest window-procedure bridge: the window is a real
// host window whose messages are interpreted by the emulated CPU, and all drawing goes
// through natively forwarded GDI calls.

#include <windows.h>
// Common Controls depends on the base Windows declarations above.
#include <commctrl.h>
// Common Dialogs also depends on the base Windows declarations.
#include <commdlg.h>

#include <cstdint>
#include <cwchar>
#include <iterator>

#include "paint_resource.h"

namespace {

constexpr int window_width = 800;
constexpr int window_height = 600;
constexpr int palette_size = 6;
constexpr int stamp_shape_count = 3;
constexpr int max_segments = 5000;
constexpr int max_stamps = 256;

const COLORREF palette[palette_size] = {
    RGB(200, 30, 30), RGB(30, 120, 220), RGB(30, 160, 60),
    RGB(240, 180, 0), RGB(150, 60, 200), RGB(20, 20, 20),
};

struct Segment {
    int x0;
    int y0;
    int x1;
    int y1;
    int color;
};

struct Stamp {
    int x;
    int y;
    int shape;
    int color;
};

Segment segments[max_segments];
int segment_count = 0;
Stamp stamps[max_stamps];
int stamp_count = 0;
int current_color = 0;
int current_shape = 0;
bool drawing = false;
int last_x = 0;
int last_y = 0;
HPEN pens[palette_size] = {};
HBRUSH brushes[palette_size] = {};
HBRUSH background_brush = nullptr;
bool message_selftest = false;
bool legacy_window_callback_seen = false;
bool dialog_callback_seen = false;
bool nested_dialog_callback_seen = false;

void write_stdout(const char *text);

INT_PTR CALLBACK test_dialog_procedure(HWND dialog, UINT message, WPARAM, LPARAM parameter) {
    if (message != WM_INITDIALOG) {
        return FALSE;
    }
    if (parameter == 0x87654321) {
        nested_dialog_callback_seen = true;
        EndDialog(dialog, 0x1111);
        return TRUE;
    }
    dialog_callback_seen = parameter == 0x12345678;
    SetDlgItemInt(dialog, IDC_CALLBACK_VALUE, 73, FALSE);
    BOOL translated = FALSE;
    const auto value = GetDlgItemInt(dialog, IDC_CALLBACK_VALUE, &translated, FALSE);
    const auto nested_result =
        DialogBoxParamW(GetModuleHandleW(nullptr), MAKEINTRESOURCEW(IDD_CALLBACK_TEST), dialog,
                        test_dialog_procedure, 0x87654321);
    EndDialog(dialog, translated && value == 73 && nested_result == 0x1111 ? 0x2468 : 0x1357);
    return TRUE;
}

constexpr UINT_PTR subclass_id = 0x123456789abcdef0ULL;
constexpr DWORD_PTR subclass_reference = 0x0fedcba987654321ULL;

LRESULT CALLBACK paint_subclass_procedure(HWND window, UINT message, WPARAM word_parameter,
                                          LPARAM long_parameter, UINT_PTR id,
                                          DWORD_PTR reference_data) {
    if (message == WM_APP + 1) {
        DWORD_PTR queried_reference = 0;
        const bool valid =
            id == subclass_id && reference_data == subclass_reference &&
            GetWindowSubclass(window, paint_subclass_procedure, subclass_id, &queried_reference) !=
                FALSE &&
            queried_reference == subclass_reference &&
            RemoveWindowSubclass(window, paint_subclass_procedure, subclass_id) != FALSE;
        write_stdout(valid ? "PAINT SUBCLASS SELFTEST PASSED\r\n"
                           : "PAINT SUBCLASS SELFTEST FAILED\r\n");
        PostQuitMessage(valid ? 0 : 1);
        return 0;
    }
    return DefSubclassProc(window, message, word_parameter, long_parameter);
}

LRESULT CALLBACK legacy_window_procedure(HWND window, UINT message, WPARAM word_parameter,
                                         LPARAM long_parameter) {
    if (message == WM_APP + 2) {
        legacy_window_callback_seen = true;
        return 0x1234;
    }
    return DefWindowProcW(window, message, word_parameter, long_parameter);
}

void trace(const char *message) { OutputDebugStringA(message); }

HPEN pen_for(int color) {
    if (pens[color] == nullptr) {
        pens[color] = CreatePen(PS_SOLID, 3, palette[color]);
    }
    return pens[color];
}

HBRUSH brush_for(int color) {
    if (brushes[color] == nullptr) {
        brushes[color] = CreateSolidBrush(palette[color]);
    }
    return brushes[color];
}

void draw_segment(HDC dc, const Segment &segment) {
    const auto previous_pen = SelectObject(dc, pen_for(segment.color));
    MoveToEx(dc, segment.x0, segment.y0, nullptr);
    LineTo(dc, segment.x1, segment.y1);
    SelectObject(dc, previous_pen);
}

void draw_stamp(HDC dc, const Stamp &stamp) {
    const auto previous_pen = SelectObject(dc, pen_for(stamp.color));
    const auto previous_brush = SelectObject(dc, brush_for(stamp.color));
    constexpr int radius = 24;
    if (stamp.shape == 0) {
        Ellipse(dc, stamp.x - radius, stamp.y - radius, stamp.x + radius, stamp.y + radius);
    } else if (stamp.shape == 1) {
        Rectangle(dc, stamp.x - radius, stamp.y - radius, stamp.x + radius, stamp.y + radius);
    } else {
        const POINT triangle[3] = {{stamp.x, stamp.y - radius},
                                   {stamp.x - radius, stamp.y + radius},
                                   {stamp.x + radius, stamp.y + radius}};
        Polygon(dc, triangle, 3);
    }
    SelectObject(dc, previous_pen);
    SelectObject(dc, previous_brush);
}

void draw_palette(HDC dc, int width, int height) {
    const HBRUSH black = CreateSolidBrush(RGB(0, 0, 0));
    for (int index = 0; index < palette_size; ++index) {
        const int right = width - 16 - (palette_size - 1 - index) * 48;
        const RECT cell{right - 32, height - 40, right, height - 16};
        FillRect(dc, &cell, brush_for(index));
        if (index == current_color) {
            const RECT frame{cell.left - 3, cell.top - 3, cell.right + 3, cell.bottom + 3};
            FrameRect(dc, &frame, black);
        }
    }
    DeleteObject(black);
}

void repaint(HWND window, HDC dc) {
    RECT client{};
    GetClientRect(window, &client);
    FillRect(dc, &client, background_brush);
    SetBkMode(dc, TRANSPARENT);
    SetTextColor(dc, RGB(70, 70, 70));
    static const wchar_t banner[] =
        L"CPUEmu Paint - drag to draw, right-click to stamp, C changes color, Esc clears";
    TextOutW(dc, 12, 10, banner, static_cast<int>(wcslen(banner)));
    for (int index = 0; index < stamp_count; ++index) {
        draw_stamp(dc, stamps[index]);
    }
    for (int index = 0; index < segment_count; ++index) {
        draw_segment(dc, segments[index]);
    }
    draw_palette(dc, client.right, client.bottom);
}

void add_segment(int x0, int y0, int x1, int y1) {
    segments[segment_count] = {x0, y0, x1, y1, current_color};
    segment_count = (segment_count + 1) % max_segments;
}

void add_stamp(int x, int y) {
    stamps[stamp_count] = {x, y, current_shape, current_color};
    stamp_count = (stamp_count + 1) % max_stamps;
}

void draw_latest_segment(HWND window) {
    const HDC dc = GetDC(window);
    draw_segment(dc, segments[(segment_count + max_segments - 1) % max_segments]);
    ReleaseDC(window, dc);
}

LRESULT CALLBACK paint_window_procedure(HWND window, UINT message, WPARAM word_parameter,
                                        LPARAM long_parameter) {
    switch (message) {
    case WM_CREATE:
        trace("paint: window created");
        if (message_selftest) {
            if (SetWindowSubclass(window, paint_subclass_procedure, subclass_id,
                                  subclass_reference) == FALSE) {
                write_stdout("PAINT SUBCLASS SELFTEST FAILED\r\n");
                PostQuitMessage(1);
            } else {
                PostMessageW(window, WM_APP + 1, 0, 0);
            }
        }
        return 0;
    case WM_APP + 1:
        write_stdout("PAINT SUBCLASS SELFTEST FAILED\r\n");
        PostQuitMessage(1);
        return 0;
    case WM_ERASEBKGND:
        return 1;
    case WM_PAINT: {
        PAINTSTRUCT paint{};
        const HDC dc = BeginPaint(window, &paint);
        repaint(window, dc);
        EndPaint(window, &paint);
        return 0;
    }
    case WM_LBUTTONDOWN:
        drawing = true;
        last_x = static_cast<short>(LOWORD(long_parameter));
        last_y = static_cast<short>(HIWORD(long_parameter));
        SetCapture(window);
        add_segment(last_x, last_y, last_x, last_y);
        draw_latest_segment(window);
        return 0;
    case WM_MOUSEMOVE: {
        if (!drawing || (word_parameter & MK_LBUTTON) == 0) {
            break;
        }
        const int x = static_cast<short>(LOWORD(long_parameter));
        const int y = static_cast<short>(HIWORD(long_parameter));
        add_segment(last_x, last_y, x, y);
        draw_latest_segment(window);
        last_x = x;
        last_y = y;
        return 0;
    }
    case WM_LBUTTONUP:
        if (drawing) {
            drawing = false;
            ReleaseCapture();
        }
        return 0;
    case WM_RBUTTONDOWN: {
        const int x = static_cast<short>(LOWORD(long_parameter));
        const int y = static_cast<short>(HIWORD(long_parameter));
        add_stamp(x, y);
        current_shape = (current_shape + 1) % stamp_shape_count;
        InvalidateRect(window, nullptr, FALSE);
        return 0;
    }
    case WM_KEYDOWN:
        if (word_parameter == 'C') {
            current_color = (current_color + 1) % palette_size;
            InvalidateRect(window, nullptr, FALSE);
        } else if (word_parameter == VK_ESCAPE) {
            segment_count = 0;
            stamp_count = 0;
            InvalidateRect(window, nullptr, TRUE);
            trace("paint: canvas cleared");
        }
        return 0;
    case WM_DESTROY:
        PostQuitMessage(0);
        return 0;
    default:
        return DefWindowProcW(window, message, word_parameter, long_parameter);
    }
    return 0;
}

int run_windowed(HINSTANCE instance, int show_command) {
    background_brush = CreateSolidBrush(RGB(252, 252, 250));
    WNDCLASSEXW window_class{};
    window_class.cbSize = sizeof(window_class);
    window_class.lpfnWndProc = paint_window_procedure;
    window_class.hInstance = instance;
    window_class.hCursor = LoadCursorW(nullptr, IDC_ARROW);
    window_class.hbrBackground = nullptr;
    window_class.lpszClassName = L"CPUEmuPaint";
    if (RegisterClassExW(&window_class) == 0) {
        trace("paint: RegisterClassExW failed");
        return 1;
    }
    const HWND window = CreateWindowExW(
        0, window_class.lpszClassName, L"CPUEmu Paint", WS_OVERLAPPEDWINDOW, CW_USEDEFAULT,
        CW_USEDEFAULT, window_width, window_height, nullptr, nullptr, instance, nullptr);
    if (window == nullptr) {
        trace("paint: CreateWindowExW failed");
        return 1;
    }
    ShowWindow(window, show_command);
    UpdateWindow(window);
    MSG message{};
    while (GetMessageW(&message, nullptr, 0, 0) > 0) {
        TranslateMessage(&message);
        DispatchMessageW(&message);
    }
    return static_cast<int>(message.wParam);
}

int run_screenshot(HINSTANCE instance) {
    background_brush = CreateSolidBrush(RGB(252, 252, 250));
    WNDCLASSEXW window_class{};
    window_class.cbSize = sizeof(window_class);
    window_class.lpfnWndProc = paint_window_procedure;
    window_class.hInstance = instance;
    window_class.hCursor = LoadCursorW(nullptr, IDC_ARROW);
    window_class.lpszClassName = L"CPUEmuPaintScreenshot";
    if (RegisterClassExW(&window_class) == 0) {
        trace("paint screenshot: RegisterClassExW failed");
        return 1;
    }
    const HWND window =
        CreateWindowExW(0, window_class.lpszClassName, L"CPUEmu Paint - interpreted guest",
                        WS_OVERLAPPEDWINDOW | WS_VISIBLE, CW_USEDEFAULT, CW_USEDEFAULT,
                        window_width, window_height, nullptr, nullptr, instance, nullptr);
    if (window == nullptr) {
        trace("paint screenshot: CreateWindowExW failed");
        return 1;
    }

    current_color = 0;
    add_stamp(150, 155);
    current_color = 1;
    add_stamp(260, 225);
    current_color = 2;
    add_stamp(375, 155);
    current_color = 4;
    add_segment(80, 350, 210, 285);
    add_segment(210, 285, 340, 365);
    add_segment(340, 365, 500, 275);
    current_color = 3;
    add_segment(500, 275, 680, 350);
    current_color = 0;

    const HDC dc = GetDC(window);
    repaint(window, dc);
    ReleaseDC(window, dc);
    GdiFlush();
    trace("paint screenshot: visual probe ready");
    const DWORD started = GetTickCount();
    MSG message{};
    while (GetTickCount() - started < 60000) {
        while (PeekMessageW(&message, nullptr, 0, 0, PM_REMOVE) != FALSE) {
            if (message.message == WM_QUIT) {
                return static_cast<int>(message.wParam);
            }
            TranslateMessage(&message);
            DispatchMessageW(&message);
        }
        Sleep(10);
    }
    return 0;
}

void write_stdout(const char *text) {
    const HANDLE output = GetStdHandle(STD_OUTPUT_HANDLE);
    DWORD written = 0;
    WriteFile(output, text, static_cast<DWORD>(lstrlenA(text)), &written, nullptr);
}

int run_selftest() {
    write_stdout("paint selftest: drawing\r\n");
    bool ok = true;
    const HDC screen = GetDC(nullptr);
    BITMAPINFO info{};
    info.bmiHeader.biSize = sizeof(BITMAPINFOHEADER);
    info.bmiHeader.biWidth = 256;
    info.bmiHeader.biHeight = -256;
    info.bmiHeader.biPlanes = 1;
    info.bmiHeader.biBitCount = 32;
    info.bmiHeader.biCompression = BI_RGB;
    void *bits = nullptr;
    const HBITMAP bitmap = CreateDIBSection(screen, &info, DIB_RGB_COLORS, &bits, nullptr, 0);
    const HDC memory_dc = CreateCompatibleDC(screen);
    if (bitmap == nullptr || bits == nullptr || memory_dc == nullptr) {
        write_stdout("paint selftest: DIB setup failed\r\n");
        return 2;
    }
    const HGDIOBJ previous_bitmap = SelectObject(memory_dc, bitmap);
    const HBRUSH white = CreateSolidBrush(RGB(255, 255, 255));
    const RECT full{0, 0, 256, 256};
    FillRect(memory_dc, &full, white);
    DeleteObject(white);
    const HBRUSH red = CreateSolidBrush(RGB(200, 30, 30));
    SelectObject(memory_dc, red);
    Ellipse(memory_dc, 10, 10, 110, 110);
    const HBRUSH blue = CreateSolidBrush(RGB(30, 120, 220));
    SelectObject(memory_dc, blue);
    Rectangle(memory_dc, 140, 140, 240, 240);
    const HPEN green = CreatePen(PS_SOLID, 3, RGB(30, 160, 60));
    SelectObject(memory_dc, green);
    MoveToEx(memory_dc, 5, 200, nullptr);
    LineTo(memory_dc, 250, 200);
    SetTextColor(memory_dc, RGB(20, 20, 20));
    SetBkMode(memory_dc, TRANSPARENT);
    TextOutW(memory_dc, 8, 128, L"CPUEmu GDI", 10);
    GdiFlush();
    const auto check_pixel = [&](int x, int y, COLORREF want, const char *what) {
        const COLORREF got = GetPixel(memory_dc, x, y);
        if (got != want) {
            write_stdout("paint selftest: pixel mismatch at ");
            write_stdout(what);
            write_stdout("\r\n");
            ok = false;
        }
    };
    check_pixel(60, 60, RGB(200, 30, 30), "ellipse fill");
    check_pixel(250, 250, RGB(255, 255, 255), "background");
    check_pixel(190, 190, RGB(30, 120, 220), "rectangle fill");
    check_pixel(128, 200, RGB(30, 160, 60), "line");
    bool text_ink = false;
    for (int y = 126; y < 150 && !text_ink; ++y) {
        for (int x = 6; x < 130 && !text_ink; ++x) {
            const COLORREF pixel = GetPixel(memory_dc, x, y);
            if (GetRValue(pixel) < 100 && GetGValue(pixel) < 100 && GetBValue(pixel) < 100) {
                text_ink = true;
            }
        }
    }
    if (!text_ink) {
        write_stdout("paint selftest: no text ink found\r\n");
        ok = false;
    }
    SelectObject(memory_dc, previous_bitmap);
    DeleteObject(green);
    DeleteObject(red);
    DeleteObject(blue);
    DeleteObject(bitmap);
    DeleteDC(memory_dc);
    ReleaseDC(nullptr, screen);
    if (ok) {
        write_stdout("PAINT SELFTEST PASSED\r\n");
    } else {
        write_stdout("PAINT SELFTEST FAILED\r\n");
    }
    return ok ? 0 : 1;
}

int run_sync_selftest() {
    bool ok = true;
    const auto check = [&](bool condition, const char *failure) {
        if (!condition) {
            write_stdout(failure);
            write_stdout("\r\n");
            ok = false;
        }
    };

    OPENFILENAMEW invalid_dialog{};
    check(GetOpenFileNameW(&invalid_dialog) == FALSE && CommDlgExtendedError() == CDERR_STRUCTSIZE,
          "sync selftest: reject invalid file-dialog structure");

    wchar_t executable[MAX_PATH]{};
    const DWORD executable_length = GetModuleFileNameW(nullptr, executable, MAX_PATH);
    check(executable_length != 0 && executable_length < MAX_PATH, "sync selftest: executable path");
    const HANDLE executable_file =
        executable_length == 0 || executable_length >= MAX_PATH
            ? INVALID_HANDLE_VALUE
            : CreateFileW(executable, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr,
                          OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    check(executable_file != INVALID_HANDLE_VALUE, "sync selftest: open executable file");
    if (executable_file != INVALID_HANDLE_VALUE) {
        BY_HANDLE_FILE_INFORMATION information{};
        check(GetFileInformationByHandle(executable_file, &information) != FALSE &&
                  (information.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) == 0 &&
                  (information.nFileSizeHigh != 0 || information.nFileSizeLow != 0),
              "sync selftest: file information output");
        const HANDLE mapping =
            CreateFileMappingW(executable_file, nullptr, PAGE_READONLY, 0, 0, nullptr);
        check(mapping != nullptr, "sync selftest: create read-only file mapping");
        if (mapping != nullptr) {
            const auto *view =
                static_cast<const unsigned char *>(MapViewOfFile(mapping, FILE_MAP_READ, 0, 0, 64));
            check(MapViewOfFile(mapping, FILE_MAP_WRITE, 0, 0, 64) == nullptr &&
                      GetLastError() == ERROR_ACCESS_DENIED,
                  "sync selftest: reject writable file view");
            check(CloseHandle(mapping) != FALSE, "sync selftest: close mapping before its view");
            check(CloseHandle(mapping) == FALSE && GetLastError() == ERROR_INVALID_HANDLE,
                  "sync selftest: reject closed mapping handle");
            check(view != nullptr && view[0] == 'M' && view[1] == 'Z',
                  "sync selftest: mapped view outlives its handle");
            if (view != nullptr) {
                check(UnmapViewOfFile(view) != FALSE, "sync selftest: unmap guest file view");
                check(UnmapViewOfFile(view) == FALSE && GetLastError() == ERROR_INVALID_ADDRESS,
                      "sync selftest: reject double unmap");
            }
        }
        check(CreateFileMappingW(executable_file, nullptr, PAGE_READONLY, 0, 0,
                                 L"CPUEmu forbidden host mapping") == nullptr &&
                  GetLastError() == ERROR_NOT_SUPPORTED,
              "sync selftest: reject unisolated named mapping");
        check(CloseHandle(executable_file) != FALSE, "sync selftest: close executable file");
    }
    BY_HANDLE_FILE_INFORMATION invalid_information{};
    check(GetFileInformationByHandle(reinterpret_cast<HANDLE>(0xdead), &invalid_information) ==
                  FALSE &&
              GetLastError() == ERROR_INVALID_HANDLE,
          "sync selftest: reject invalid file-information handle");
    check(CreateFileMappingW(reinterpret_cast<HANDLE>(0xdead), nullptr, PAGE_READONLY, 0, 0,
                             nullptr) == nullptr &&
              GetLastError() == ERROR_INVALID_HANDLE,
          "sync selftest: reject invalid file-mapping handle");
    check(MapViewOfFile(reinterpret_cast<HANDLE>(0xdead), FILE_MAP_READ, 0, 0, 64) == nullptr &&
              GetLastError() == ERROR_INVALID_HANDLE,
          "sync selftest: reject invalid mapping token");
    check(CreateFileMappingW(INVALID_HANDLE_VALUE, nullptr, PAGE_READONLY, 0, 257U * 1024U * 1024U,
                             nullptr) == nullptr &&
              GetLastError() == ERROR_NOT_ENOUGH_MEMORY,
          "sync selftest: cap page-file mapping size");

    WNDCLASSW legacy_class{};
    legacy_class.lpfnWndProc = legacy_window_procedure;
    legacy_class.hInstance = GetModuleHandleW(nullptr);
    legacy_class.lpszClassName = L"CPUEmuLegacyWindowClass";
    const ATOM legacy_atom = RegisterClassW(&legacy_class);
    check(legacy_atom != 0, "sync selftest: register legacy window class");
    const HWND legacy_window =
        legacy_atom == 0
            ? nullptr
            : CreateWindowExW(0, legacy_class.lpszClassName, L"CPUEmu legacy window", WS_POPUP, 0,
                              0, 100, 100, nullptr, nullptr, nullptr, nullptr);
    check(legacy_window != nullptr, "sync selftest: create legacy registered window");
    if (legacy_window != nullptr) {
        check(SendMessageW(legacy_window, WM_APP + 2, 0, 0) == 0x1234 &&
                  legacy_window_callback_seen,
              "sync selftest: dispatch legacy registered window callback");
        DestroyWindow(legacy_window);
    }
    check(RegisterClassW(nullptr) == 0 && GetLastError() == ERROR_INVALID_PARAMETER,
          "sync selftest: reject null legacy window class");

    const auto dialog_result =
        DialogBoxParamW(GetModuleHandleW(nullptr), MAKEINTRESOURCEW(IDD_CALLBACK_TEST), nullptr,
                        test_dialog_procedure, 0x12345678);
    check(dialog_result == 0x2468 && dialog_callback_seen && nested_dialog_callback_seen,
          "sync selftest: nested modal dialog callbacks and result");
    SetLastError(ERROR_SUCCESS);
    check(DialogBoxParamW(GetModuleHandleW(nullptr), MAKEINTRESOURCEW(IDD_CALLBACK_TEST), nullptr,
                          nullptr, 0) == -1 &&
              GetLastError() == ERROR_INVALID_PARAMETER,
          "sync selftest: reject null dialog callback");
    SetLastError(ERROR_SUCCESS);
    check(DialogBoxParamW(GetModuleHandleW(nullptr), MAKEINTRESOURCEW(0x7fff), nullptr,
                          test_dialog_procedure, 0) == -1 &&
              GetLastError() != ERROR_SUCCESS,
          "sync selftest: reject missing dialog resource");

    const HWND edit = CreateWindowExW(0, L"EDIT", L"", WS_POPUP | ES_MULTILINE, 0, 0, 200, 100,
                                      nullptr, nullptr, nullptr, nullptr);
    check(edit != nullptr, "sync selftest: create multiline edit control");
    if (edit != nullptr) {
        check(SendMessageW(edit, EM_SETHANDLE, 0xdead, 0) == 0 &&
                  GetLastError() == ERROR_INVALID_HANDLE,
              "sync selftest: reject invalid edit memory handle");
        constexpr wchar_t initial_text[] = L"guest-owned edit text";
        const HLOCAL edit_memory =
            LocalAlloc(LMEM_MOVEABLE | LMEM_ZEROINIT, sizeof(initial_text) + 64);
        check(edit_memory != nullptr, "sync selftest: allocate edit backing memory");
        if (edit_memory != nullptr) {
            auto *const locked = static_cast<wchar_t *>(LocalLock(edit_memory));
            check(locked != nullptr, "sync selftest: lock edit backing memory");
            if (locked != nullptr) {
                for (std::size_t index = 0; index < std::size(initial_text); ++index) {
                    locked[index] = initial_text[index];
                }
                LocalUnlock(edit_memory);
                check(SendMessageW(edit, EM_SETHANDLE, reinterpret_cast<WPARAM>(edit_memory), 0) !=
                          0,
                      "sync selftest: set guest-owned edit handle");
                wchar_t edit_text[64]{};
                check(GetWindowTextW(edit, edit_text, static_cast<int>(std::size(edit_text))) !=
                              0 &&
                          lstrcmpW(edit_text, initial_text) == 0,
                      "sync selftest: edit handle copies text to native control");
                constexpr wchar_t updated_text[] =
                    L"native edit update that exceeds the original guest-owned buffer and "
                    L"requires a larger copy-back allocation";
                check(SetWindowTextW(edit, updated_text) != FALSE,
                      "sync selftest: update native edit text");
                const auto returned =
                    reinterpret_cast<HLOCAL>(SendMessageW(edit, EM_GETHANDLE, 0, 0));
                const auto *const returned_text = static_cast<const wchar_t *>(LocalLock(returned));
                check(returned != nullptr && returned != edit_memory && returned_text != nullptr &&
                          lstrcmpW(returned_text, updated_text) == 0,
                      "sync selftest: get edit handle grows guest memory and copies text");
                if (returned_text != nullptr) {
                    LocalUnlock(returned);
                }
            }
        }
        DestroyWindow(edit);
    }

    const HANDLE missing =
        OpenSemaphoreW(SEMAPHORE_ALL_ACCESS, FALSE, L"CPUEmu synchronization missing object");
    check(missing == nullptr && GetLastError() == ERROR_FILE_NOT_FOUND,
          "sync selftest: missing named semaphore result");

    const HANDLE semaphore = CreateSemaphoreExW(nullptr, 0, 1, L"CPUEmu synchronization semaphore",
                                                0, SEMAPHORE_ALL_ACCESS);
    check(semaphore != nullptr, "sync selftest: semaphore creation");
    const HANDLE opened =
        OpenSemaphoreW(SEMAPHORE_ALL_ACCESS, FALSE, L"CPUEmu synchronization semaphore");
    check(opened != nullptr, "sync selftest: semaphore open");
    if (semaphore != nullptr && opened != nullptr) {
        check(WaitForSingleObject(opened, 0) == WAIT_TIMEOUT,
              "sync selftest: unsignaled semaphore wait");
        LONG previous = -1;
        check(ReleaseSemaphore(semaphore, 1, &previous) != FALSE && previous == 0,
              "sync selftest: semaphore release count");
        check(WaitForSingleObject(opened, 0) == WAIT_OBJECT_0,
              "sync selftest: signaled semaphore wait");
    }

    const HANDLE mutex = CreateMutexExW(nullptr, L"CPUEmu synchronization mutex",
                                        CREATE_MUTEX_INITIAL_OWNER, MUTEX_ALL_ACCESS);
    check(mutex != nullptr, "sync selftest: mutex creation");
    if (mutex != nullptr) {
        check(ReleaseMutex(mutex) != FALSE, "sync selftest: mutex release");
    }

    const HANDLE event =
        CreateEventExW(nullptr, L"CPUEmu synchronization event", 0, EVENT_ALL_ACCESS);
    check(event != nullptr, "sync selftest: event creation");
    if (event != nullptr) {
        check(WaitForSingleObject(event, 0) == WAIT_TIMEOUT,
              "sync selftest: unsignaled event wait");
        check(SetEvent(event) != FALSE, "sync selftest: set event");
        check(WaitForSingleObject(event, 0) == WAIT_OBJECT_0, "sync selftest: signaled event wait");
        check(ResetEvent(event) != FALSE, "sync selftest: reset event");
    }

    SRWLOCK lock{};
    InitializeSRWLock(&lock);
    AcquireSRWLockExclusive(&lock);
    ReleaseSRWLockExclusive(&lock);
    check(TryAcquireSRWLockShared(&lock) != FALSE, "sync selftest: SRW try acquire");
    ReleaseSRWLockShared(&lock);

    const ULONG_PTR message_arguments[] = {reinterpret_cast<ULONG_PTR>(L"guest"), 7};
    wchar_t *formatted = nullptr;
    const DWORD formatted_length = FormatMessageW(
        FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_STRING | FORMAT_MESSAGE_ARGUMENT_ARRAY,
        L"%1 synchronization value %2!u!", 0, 0, reinterpret_cast<wchar_t *>(&formatted), 0,
        reinterpret_cast<va_list *>(const_cast<ULONG_PTR *>(message_arguments)));
    check(formatted_length != 0 && formatted != nullptr &&
              lstrcmpW(formatted, L"guest synchronization value 7") == 0,
          "sync selftest: FormatMessageW guest allocation");
    if (formatted != nullptr) {
        LocalFree(formatted);
    }

    check(WaitForSingleObject(reinterpret_cast<HANDLE>(0xdead), 0) == WAIT_FAILED &&
              GetLastError() == ERROR_INVALID_HANDLE,
          "sync selftest: invalid handle wait");
    if (opened != nullptr) {
        check(CloseHandle(opened) != FALSE, "sync selftest: close opened semaphore");
        check(CloseHandle(opened) == FALSE && GetLastError() == ERROR_INVALID_HANDLE,
              "sync selftest: reject double close");
    }
    if (semaphore != nullptr) {
        CloseHandle(semaphore);
    }
    if (mutex != nullptr) {
        CloseHandle(mutex);
    }
    if (event != nullptr) {
        CloseHandle(event);
    }

    write_stdout(ok ? "SYNC SELFTEST PASSED\r\n" : "SYNC SELFTEST FAILED\r\n");
    return ok ? 0 : 1;
}

} // namespace

extern "C" int WINAPI wWinMain(HINSTANCE instance, HINSTANCE, PWSTR, int show_command) {
    if (wcsstr(GetCommandLineW(), L"--sync-selftest") != nullptr) {
        return run_sync_selftest();
    }
    if (wcsstr(GetCommandLineW(), L"--selftest") != nullptr) {
        return run_selftest();
    }
    if (wcsstr(GetCommandLineW(), L"--screenshot") != nullptr) {
        return run_screenshot(instance);
    }
    if (wcsstr(GetCommandLineW(), L"--message-selftest") != nullptr) {
        message_selftest = true;
        return run_windowed(instance, show_command);
    }
    return run_windowed(instance, show_command);
}
