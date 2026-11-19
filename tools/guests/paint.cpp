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
#include <d3d9.h>
#include <dsound.h>
#include <mmsystem.h>
#include <shlobj.h>

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
bool subclass_callback_seen = false;
bool timer_callback_seen = false;
bool callback_selftest_reported = false;
UINT_PTR callback_timer_id = 0;
UINT_PTR retained_timer_id = 0;
HWND retained_modeless_dialog = nullptr;
bool legacy_window_callback_seen = false;
bool legacy_key_message_seen = false;
bool dialog_callback_seen = false;
bool nested_dialog_callback_seen = false;
bool modeless_dialog_init_seen = false;
bool modeless_dialog_message_seen = false;
HDC font_enum_device_context = nullptr;
bool font_enum_callback_seen = false;
bool extended_font_enum_callback_seen = false;
bool family_font_enum_callback_seen = false;
int line_dda_point_count = 0;
int nested_line_dda_point_count = 0;
bool nested_line_dda_started = false;
HWND expected_enum_child = nullptr;
HWND expected_enum_grandchild = nullptr;
HWND expected_enum_parent = nullptr;
bool outer_enum_callback_seen = false;
bool nested_enum_callback_seen = false;
bool process_enum_callback_seen = false;

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

INT_PTR CALLBACK test_modeless_dialog_procedure(HWND, UINT message, WPARAM, LPARAM parameter) {
    if (message == WM_INITDIALOG) {
        modeless_dialog_init_seen = parameter == 0x31415926;
        return TRUE;
    }
    if (message == WM_APP + 4) {
        modeless_dialog_message_seen = true;
        return TRUE;
    }
    return FALSE;
}

int CALLBACK test_font_enum_procedure(const LOGFONTW *font, const TEXTMETRICW *metric,
                                      DWORD font_type, LPARAM parameter) {
    constexpr LPARAM outer_parameter = 0x22334455;
    constexpr LPARAM extended_parameter = 0x33445566;
    constexpr LPARAM family_parameter = 0x44556677;
    if (font == nullptr || metric == nullptr || font->lfFaceName[0] == L'\0' ||
        metric->tmHeight == 0) {
        return 0;
    }
    if (parameter == extended_parameter) {
        const auto *extended_font = reinterpret_cast<const ENUMLOGFONTEXW *>(font);
        extended_font_enum_callback_seen =
            extended_font->elfLogFont.lfFaceName[0] != L'\0' &&
            (font_type & (RASTER_FONTTYPE | DEVICE_FONTTYPE | TRUETYPE_FONTTYPE)) != 0;
        return 0;
    }
    if (parameter == family_parameter) {
        family_font_enum_callback_seen = true;
        return 0;
    }
    if (parameter != outer_parameter) {
        return 0;
    }
    font_enum_callback_seen = true;
    LOGFONTW request{};
    request.lfCharSet = DEFAULT_CHARSET;
    static_cast<void>(EnumFontFamiliesExW(font_enum_device_context, &request,
                                          test_font_enum_procedure, extended_parameter, 0));
    return 0;
}

void CALLBACK test_line_dda_procedure(int x, int y, LPARAM parameter) {
    constexpr LPARAM outer_parameter = static_cast<LPARAM>(0x123456789abcdef0ULL);
    constexpr LPARAM nested_parameter = static_cast<LPARAM>(0x0fedcba987654321ULL);
    if (parameter == nested_parameter) {
        if (y == 10 && x == 10 + nested_line_dda_point_count) {
            ++nested_line_dda_point_count;
        }
        return;
    }
    if (parameter != outer_parameter || y != 3 || x != -2 + line_dda_point_count) {
        return;
    }
    ++line_dda_point_count;
    if (!nested_line_dda_started) {
        nested_line_dda_started = true;
        static_cast<void>(LineDDA(10, 10, 13, 10, test_line_dda_procedure, nested_parameter));
    }
}

BOOL CALLBACK test_window_enum_procedure(HWND window, LPARAM parameter) {
    constexpr LPARAM outer_parameter = 0x10203040;
    constexpr LPARAM nested_parameter = 0x50607080;
    constexpr LPARAM process_parameter = 0x11223344;
    if (parameter == process_parameter) {
        process_enum_callback_seen = process_enum_callback_seen || window == expected_enum_parent;
        return TRUE;
    }
    if (parameter == nested_parameter) {
        nested_enum_callback_seen = nested_enum_callback_seen || window == expected_enum_grandchild;
        return TRUE;
    }
    if (parameter != outer_parameter) {
        return FALSE;
    }
    if (window == expected_enum_child) {
        outer_enum_callback_seen = true;
        return EnumChildWindows(window, test_window_enum_procedure, nested_parameter);
    }
    return TRUE;
}

constexpr UINT_PTR subclass_id = 0x123456789abcdef0ULL;
constexpr DWORD_PTR subclass_reference = 0x0fedcba987654321ULL;

void finish_callback_selftest() {
    if (!callback_selftest_reported && subclass_callback_seen && timer_callback_seen) {
        callback_selftest_reported = true;
        write_stdout("PAINT CALLBACK SELFTEST PASSED\r\n");
        PostQuitMessage(0);
    }
}

void CALLBACK paint_timer_procedure(HWND window, UINT message, UINT_PTR timer_id, DWORD) {
    const bool valid = message == WM_TIMER && timer_id == callback_timer_id &&
                       KillTimer(window, timer_id) != FALSE && KillTimer(window, timer_id) == FALSE;
    if (!valid) {
        write_stdout("PAINT TIMER SELFTEST FAILED\r\n");
        PostQuitMessage(1);
        return;
    }
    timer_callback_seen = true;
    finish_callback_selftest();
}

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
        if (!valid) {
            write_stdout("PAINT SUBCLASS SELFTEST FAILED\r\n");
            PostQuitMessage(1);
            return 0;
        }
        subclass_callback_seen = true;
        finish_callback_selftest();
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
    if (message == WM_KEYDOWN && word_parameter == 'Z') {
        legacy_key_message_seen = true;
        return 0;
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
            SetLastError(ERROR_SUCCESS);
            const bool invalid_timer_rejected =
                SetTimer(window, 0x41, 10, reinterpret_cast<TIMERPROC>(0xdead)) == 0 &&
                GetLastError() == ERROR_INVALID_PARAMETER;
            const auto message_timer = SetTimer(window, 0x42, 10, nullptr);
            const bool message_timer_valid =
                message_timer != 0 && KillTimer(window, message_timer) != FALSE;
            callback_timer_id = SetTimer(window, 0x43, 10, paint_timer_procedure);
            retained_timer_id = SetTimer(nullptr, 0, 60000, paint_timer_procedure);
            retained_modeless_dialog =
                CreateDialogParamW(GetModuleHandleW(nullptr), MAKEINTRESOURCEW(IDD_CALLBACK_TEST),
                                   window, test_modeless_dialog_procedure, 0x31415926);
            if (!invalid_timer_rejected || !message_timer_valid || callback_timer_id == 0 ||
                retained_timer_id == 0 || retained_modeless_dialog == nullptr ||
                SetWindowSubclass(window, paint_subclass_procedure, subclass_id,
                                  subclass_reference) == FALSE) {
                write_stdout("PAINT SUBCLASS SELFTEST FAILED\r\n");
                if (callback_timer_id != 0) {
                    KillTimer(window, callback_timer_id);
                }
                if (retained_timer_id != 0) {
                    KillTimer(nullptr, retained_timer_id);
                }
                if (retained_modeless_dialog != nullptr) {
                    DestroyWindow(retained_modeless_dialog);
                }
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

    check(IsDebuggerPresent() == FALSE,
          "sync selftest: guest process has no attached guest debugger");
    check(GetUserDefaultLCID() != 0, "sync selftest: query user default locale identifier");
    wchar_t language_name[16]{};
    check(GetLocaleInfoW(GetUserDefaultLCID(), LOCALE_SISO639LANGNAME, language_name,
                         static_cast<int>(std::size(language_name))) > 1 &&
              language_name[0] != L'\0',
          "sync selftest: marshal user locale information");
    SetLastError(ERROR_SUCCESS);
    check(GetLocaleInfoW(GetUserDefaultLCID(), LOCALE_SISO639LANGNAME, nullptr, 2) == 0 &&
              GetLastError() == ERROR_INVALID_PARAMETER,
          "sync selftest: reject invalid locale output");
    check(IsValidLocale(GetUserDefaultLCID(), LCID_INSTALLED) != FALSE &&
              IsValidLocale(static_cast<LCID>(0xffffffffU), LCID_INSTALLED) == FALSE,
          "sync selftest: validate locale identifiers");
    DWORD rejected_thread_id = 0;
    SetLastError(ERROR_SUCCESS);
    check(CreateThread(nullptr, 0, reinterpret_cast<LPTHREAD_START_ROUTINE>(1), nullptr, 0,
                       &rejected_thread_id) == nullptr &&
              GetLastError() == ERROR_INVALID_PARAMETER,
          "sync selftest: reject invalid guest thread entry");
    check(SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_ABOVE_NORMAL) != FALSE &&
              GetThreadPriority(GetCurrentThread()) == THREAD_PRIORITY_ABOVE_NORMAL,
          "sync selftest: retain guest current-thread priority");
    SetLastError(ERROR_SUCCESS);
    check(SetThreadPriority(reinterpret_cast<HANDLE>(0x1234), THREAD_PRIORITY_NORMAL) == FALSE &&
              GetLastError() == ERROR_INVALID_HANDLE,
          "sync selftest: reject unknown guest thread handle");
    auto *read_only = VirtualAlloc(nullptr, 0x1000, MEM_RESERVE | MEM_COMMIT, PAGE_READONLY);
    check(read_only != nullptr && IsBadReadPtr(read_only, 0x1000) == FALSE &&
              IsBadWritePtr(read_only, 0x1000) != FALSE,
          "sync selftest: distinguish readable and writable guest ranges");
    check(read_only != nullptr && IsBadReadPtr(read_only, 0x1001) != FALSE &&
              IsBadReadPtr(nullptr, 1) != FALSE && IsBadWritePtr(nullptr, 0) == FALSE,
          "sync selftest: reject invalid and crossing guest ranges");
    if (read_only != nullptr) {
        VirtualFree(read_only, 0, MEM_RELEASE);
    }

    IDirect3D9Ex *direct3d = nullptr;
    const HRESULT direct3d_result = Direct3DCreate9Ex(D3D_SDK_VERSION, &direct3d);
    check(SUCCEEDED(direct3d_result) && direct3d != nullptr,
          "sync selftest: create Direct3D9Ex proxy");
    if (direct3d != nullptr) {
        const UINT adapter_count = direct3d->GetAdapterCount();
        check(adapter_count != 0, "sync selftest: enumerate Direct3D adapters");
        if (adapter_count != 0) {
            constexpr size_t identifier_fields_size =
                offsetof(D3DADAPTER_IDENTIFIER9, WHQLLevel) + sizeof(DWORD);
            alignas(D3DADAPTER_IDENTIFIER9) unsigned char
                identifier_storage[sizeof(D3DADAPTER_IDENTIFIER9) + 4]{};
            for (size_t index = identifier_fields_size; index < sizeof(identifier_storage);
                 ++index) {
                identifier_storage[index] = 0xa5;
            }
            auto *identifier = reinterpret_cast<D3DADAPTER_IDENTIFIER9 *>(identifier_storage);
            check(SUCCEEDED(direct3d->GetAdapterIdentifier(0, 0, identifier)) &&
                      identifier->Description[0] != '\0',
                  "sync selftest: query Direct3D adapter identifier");
            bool identifier_canary_intact = true;
            for (size_t index = identifier_fields_size; index < sizeof(identifier_storage);
                 ++index) {
                identifier_canary_intact &= identifier_storage[index] == 0xa5;
            }
            check(identifier_canary_intact,
                  "sync selftest: preserve Direct3D identifier trailing bytes");
            D3DDISPLAYMODE mode{};
            check(SUCCEEDED(direct3d->GetAdapterDisplayMode(0, &mode)) && mode.Width != 0 &&
                      mode.Height != 0,
                  "sync selftest: query Direct3D display mode");
            D3DCAPS9 capabilities{};
            check(SUCCEEDED(direct3d->GetDeviceCaps(0, D3DDEVTYPE_HAL, &capabilities)),
                  "sync selftest: query Direct3D device capabilities");
        }
        IDirect3D9Ex *queried = nullptr;
        check(SUCCEEDED(direct3d->QueryInterface(__uuidof(IDirect3D9Ex),
                                                 reinterpret_cast<void **>(&queried))) &&
                  queried == direct3d,
              "sync selftest: Direct3D QueryInterface lifetime");
        if (queried != nullptr) {
            queried->Release();
        }
        HWND device_window =
            CreateWindowExW(0, L"STATIC", L"CPUEmu D3D fixture", WS_POPUP, 0, 0, 64, 64, nullptr,
                            nullptr, GetModuleHandleW(nullptr), nullptr);
        check(device_window != nullptr, "sync selftest: create Direct3D device window");
        if (device_window != nullptr) {
            check(ShowWindow(device_window, SW_SHOW) == FALSE &&
                      UpdateWindow(device_window) != FALSE &&
                      ShowWindow(device_window, SW_HIDE) != FALSE,
                  "sync selftest: show, update, and hide native guest window");
        }
        IDirectSound *direct_sound = nullptr;
        const auto sound_result = DirectSoundCreate(nullptr, &direct_sound, nullptr);
        check(SUCCEEDED(sound_result) && direct_sound != nullptr,
              "sync selftest: create DirectSound proxy");
        if (direct_sound != nullptr) {
            DSCAPS sound_caps{};
            sound_caps.dwSize = sizeof(sound_caps);
            check(SUCCEEDED(direct_sound->GetCaps(&sound_caps)) &&
                      sound_caps.dwSize == sizeof(sound_caps),
                  "sync selftest: query DirectSound capabilities");
            check(FAILED(direct_sound->GetCaps(nullptr)),
                  "sync selftest: reject null DirectSound capabilities output");
            check(device_window != nullptr &&
                      SUCCEEDED(direct_sound->SetCooperativeLevel(device_window, DSSCL_NORMAL)),
                  "sync selftest: set DirectSound cooperative level");
            WAVEFORMATEX wave_format{};
            wave_format.wFormatTag = WAVE_FORMAT_PCM;
            wave_format.nChannels = 2;
            wave_format.nSamplesPerSec = 44100;
            wave_format.nAvgBytesPerSec = 176400;
            wave_format.nBlockAlign = 4;
            wave_format.wBitsPerSample = 16;
            DSBUFFERDESC buffer_description{};
            buffer_description.dwSize = sizeof(buffer_description);
            buffer_description.dwFlags = DSBCAPS_CTRLVOLUME | DSBCAPS_CTRLFREQUENCY;
            buffer_description.dwBufferBytes = 4096;
            buffer_description.lpwfxFormat = &wave_format;
            IDirectSoundBuffer *sound_buffer = nullptr;
            check(SUCCEEDED(direct_sound->CreateSoundBuffer(&buffer_description, &sound_buffer,
                                                            nullptr)) &&
                      sound_buffer != nullptr,
                  "sync selftest: create guest-owned DirectSound buffer");
            if (sound_buffer != nullptr) {
                DSBCAPS buffer_caps{};
                buffer_caps.dwSize = sizeof(buffer_caps);
                check(SUCCEEDED(sound_buffer->GetCaps(&buffer_caps)) &&
                          buffer_caps.dwBufferBytes == 4096,
                      "sync selftest: query DirectSound buffer capabilities");
                void *region1 = nullptr;
                void *region2 = nullptr;
                DWORD region1_size = 0;
                DWORD region2_size = 0;
                check(SUCCEEDED(sound_buffer->Lock(0, 4096, &region1, &region1_size, &region2,
                                                   &region2_size, 0)) &&
                          region1 != nullptr && region1_size + region2_size == 4096,
                      "sync selftest: lock DirectSound buffer staging");
                if (region1 != nullptr) {
                    std::memset(region1, 0, region1_size);
                    if (region2 != nullptr) {
                        std::memset(region2, 0, region2_size);
                    }
                    check(SUCCEEDED(
                              sound_buffer->Unlock(region1, region1_size, region2, region2_size)),
                          "sync selftest: upload DirectSound buffer staging");
                }
                check(SUCCEEDED(sound_buffer->SetVolume(DSBVOLUME_MIN)) &&
                          SUCCEEDED(sound_buffer->Play(0, 0, 0)) && SUCCEEDED(sound_buffer->Stop()),
                      "sync selftest: control DirectSound buffer playback");
                IDirectSoundBuffer *queried_buffer = nullptr;
                check(SUCCEEDED(sound_buffer->QueryInterface(
                          IID_IDirectSoundBuffer, reinterpret_cast<void **>(&queried_buffer))) &&
                          queried_buffer == sound_buffer,
                      "sync selftest: DirectSound buffer QueryInterface lifetime");
                if (queried_buffer != nullptr) {
                    queried_buffer->Release();
                }
                sound_buffer->Release();
            }
            check(FAILED(direct_sound->CreateSoundBuffer(&buffer_description, nullptr, nullptr)),
                  "sync selftest: reject null DirectSound buffer output");
            IDirectSound *queried_sound = nullptr;
            check(SUCCEEDED(direct_sound->QueryInterface(
                      IID_IDirectSound, reinterpret_cast<void **>(&queried_sound))) &&
                      queried_sound == direct_sound,
                  "sync selftest: DirectSound QueryInterface lifetime");
            if (queried_sound != nullptr) {
                queried_sound->Release();
            }
            direct_sound->Release();
        }
        check(FAILED(DirectSoundCreate(nullptr, nullptr, nullptr)),
              "sync selftest: reject null DirectSound output");
        D3DPRESENT_PARAMETERS presentation{};
        presentation.BackBufferWidth = 64;
        presentation.BackBufferHeight = 64;
        presentation.BackBufferFormat = D3DFMT_UNKNOWN;
        presentation.BackBufferCount = 1;
        presentation.SwapEffect = D3DSWAPEFFECT_DISCARD;
        presentation.hDeviceWindow = device_window;
        presentation.Windowed = TRUE;
        IDirect3DDevice9 *base_device = nullptr;
        check(device_window != nullptr &&
                  SUCCEEDED(direct3d->CreateDevice(0, D3DDEVTYPE_HAL, device_window,
                                                   D3DCREATE_SOFTWARE_VERTEXPROCESSING,
                                                   &presentation, &base_device)) &&
                  base_device != nullptr,
              "sync selftest: create Direct3D9 device proxy");
        if (base_device != nullptr) {
            D3DCAPS9 device_caps{};
            check(SUCCEEDED(base_device->GetDeviceCaps(&device_caps)),
                  "sync selftest: query Direct3D device caps");
            check(FAILED(base_device->GetDeviceCaps(nullptr)),
                  "sync selftest: reject null Direct3D device caps output");
            D3DDEVICE_CREATION_PARAMETERS creation{};
            check(SUCCEEDED(base_device->GetCreationParameters(&creation)) &&
                      creation.hFocusWindow == device_window,
                  "sync selftest: marshal Direct3D creation parameters");
            check(PostMessageW(nullptr, WM_APP + 77, 0x12, 0x34) != FALSE,
                  "sync selftest: queue message across Direct3D presentation");
            check(SUCCEEDED(base_device->BeginScene()) &&
                      SUCCEEDED(
                          base_device->Clear(0, nullptr, D3DCLEAR_TARGET, 0xff102030, 1.0f, 0)) &&
                      SUCCEEDED(base_device->EndScene()) &&
                      SUCCEEDED(base_device->Present(nullptr, nullptr, device_window, nullptr)),
                  "sync selftest: execute Direct3D scene methods");
            IDirect3DDevice9 *queried_device = nullptr;
            check(SUCCEEDED(base_device->QueryInterface(
                      __uuidof(IDirect3DDevice9), reinterpret_cast<void **>(&queried_device))) &&
                      queried_device == base_device,
                  "sync selftest: Direct3D device QueryInterface lifetime");
            if (queried_device != nullptr) {
                queried_device->Release();
            }
            IDirect3DTexture9 *texture = nullptr;
            check(SUCCEEDED(base_device->CreateTexture(4, 4, 1, D3DUSAGE_DYNAMIC, D3DFMT_A8R8G8B8,
                                                       D3DPOOL_DEFAULT, &texture, nullptr)) &&
                      texture != nullptr,
                  "sync selftest: create Direct3D texture proxy");
            if (texture != nullptr) {
                D3DSURFACE_DESC description{};
                check(texture->GetLevelCount() == 1 &&
                          SUCCEEDED(texture->GetLevelDesc(0, &description)) &&
                          description.Width == 4 && description.Height == 4,
                      "sync selftest: query Direct3D texture description");
                D3DLOCKED_RECT locked_texture{};
                check(SUCCEEDED(texture->LockRect(0, &locked_texture, nullptr, D3DLOCK_DISCARD)) &&
                          locked_texture.pBits != nullptr && locked_texture.Pitch >= 16,
                      "sync selftest: lock Direct3D texture staging");
                if (locked_texture.pBits != nullptr) {
                    auto *pixels = static_cast<std::uint8_t *>(locked_texture.pBits);
                    for (UINT row = 0; row < 4; ++row) {
                        std::memset(pixels + locked_texture.Pitch * row, 0x7f, 16);
                    }
                    check(SUCCEEDED(texture->UnlockRect(0)),
                          "sync selftest: upload Direct3D texture staging");
                }
                check(FAILED(texture->LockRect(0, nullptr, nullptr, 0)),
                      "sync selftest: reject null Direct3D texture lock output");
                IDirect3DSurface9 *surface = nullptr;
                check(SUCCEEDED(texture->GetSurfaceLevel(0, &surface)) && surface != nullptr,
                      "sync selftest: create guest-owned Direct3D surface proxy");
                if (surface != nullptr) {
                    D3DSURFACE_DESC surface_description{};
                    check(SUCCEEDED(surface->GetDesc(&surface_description)) &&
                              surface_description.Width == 4 && surface_description.Height == 4,
                          "sync selftest: query Direct3D surface description");
                    IDirect3DDevice9 *surface_device = nullptr;
                    check(SUCCEEDED(surface->GetDevice(&surface_device)) &&
                              surface_device == base_device,
                          "sync selftest: retain Direct3D surface device owner");
                    if (surface_device != nullptr) {
                        surface_device->Release();
                    }
                    IDirect3DTexture9 *surface_texture = nullptr;
                    check(SUCCEEDED(
                              surface->GetContainer(__uuidof(IDirect3DTexture9),
                                                    reinterpret_cast<void **>(&surface_texture))) &&
                              surface_texture == texture,
                          "sync selftest: retain Direct3D surface texture owner");
                    if (surface_texture != nullptr) {
                        surface_texture->Release();
                    }
                    IDirect3DSurface9 *queried_surface = nullptr;
                    check(SUCCEEDED(surface->QueryInterface(
                              __uuidof(IDirect3DSurface9),
                              reinterpret_cast<void **>(&queried_surface))) &&
                              queried_surface == surface,
                          "sync selftest: Direct3D surface QueryInterface lifetime");
                    if (queried_surface != nullptr) {
                        queried_surface->Release();
                    }
                    surface->Release();
                }
                check(FAILED(texture->GetSurfaceLevel(0, nullptr)),
                      "sync selftest: reject null Direct3D surface output");
                IDirect3DDevice9 *texture_device = nullptr;
                check(SUCCEEDED(texture->GetDevice(&texture_device)) &&
                          texture_device == base_device,
                      "sync selftest: retain Direct3D texture device owner");
                if (texture_device != nullptr) {
                    texture_device->Release();
                }
                IDirect3DTexture9 *queried_texture = nullptr;
                check(SUCCEEDED(
                          texture->QueryInterface(__uuidof(IDirect3DTexture9),
                                                  reinterpret_cast<void **>(&queried_texture))) &&
                          queried_texture == texture,
                      "sync selftest: Direct3D texture QueryInterface lifetime");
                if (queried_texture != nullptr) {
                    queried_texture->Release();
                }
                check(SUCCEEDED(base_device->SetTexture(0, texture)) &&
                          SUCCEEDED(base_device->SetTexture(0, nullptr)),
                      "sync selftest: bind and unbind Direct3D texture proxy");
                texture->Release();
            }
            check(FAILED(base_device->CreateTexture(4, 4, 1, 0, D3DFMT_A8R8G8B8, D3DPOOL_DEFAULT,
                                                    nullptr, nullptr)),
                  "sync selftest: reject null Direct3D texture output");
            IDirect3DTexture9 *upload_source = nullptr;
            IDirect3DTexture9 *upload_destination = nullptr;
            check(SUCCEEDED(base_device->CreateTexture(
                      4, 4, 1, 0, D3DFMT_A8R8G8B8, D3DPOOL_SYSTEMMEM, &upload_source, nullptr)) &&
                      SUCCEEDED(base_device->CreateTexture(4, 4, 1, 0, D3DFMT_A8R8G8B8,
                                                           D3DPOOL_DEFAULT, &upload_destination,
                                                           nullptr)) &&
                      upload_source != nullptr && upload_destination != nullptr,
                  "sync selftest: create Direct3D texture upload pair");
            if (upload_source != nullptr && upload_destination != nullptr) {
                D3DLOCKED_RECT upload_lock{};
                check(SUCCEEDED(upload_source->LockRect(0, &upload_lock, nullptr, 0)) &&
                          upload_lock.pBits != nullptr,
                      "sync selftest: stage Direct3D texture update source");
                if (upload_lock.pBits != nullptr) {
                    auto *pixels = static_cast<std::uint8_t *>(upload_lock.pBits);
                    for (UINT row = 0; row < 4; ++row) {
                        std::memset(pixels + upload_lock.Pitch * row, 0x3c, 16);
                    }
                    check(SUCCEEDED(upload_source->UnlockRect(0)) &&
                              SUCCEEDED(
                                  base_device->UpdateTexture(upload_source, upload_destination)),
                          "sync selftest: upload Direct3D texture between pools");
                }
            }
            if (upload_source != nullptr) {
                upload_source->Release();
            }
            if (upload_destination != nullptr) {
                upload_destination->Release();
            }
            IDirect3DVertexBuffer9 *vertex_buffer = nullptr;
            check(SUCCEEDED(base_device->CreateVertexBuffer(64, 0, D3DFVF_XYZ, D3DPOOL_DEFAULT,
                                                            &vertex_buffer, nullptr)) &&
                      vertex_buffer != nullptr,
                  "sync selftest: create Direct3D vertex buffer proxy");
            if (vertex_buffer != nullptr) {
                void *vertices = nullptr;
                check(SUCCEEDED(vertex_buffer->Lock(0, 0, &vertices, 0)) && vertices != nullptr,
                      "sync selftest: lock Direct3D vertex buffer staging");
                if (vertices != nullptr) {
                    std::memset(vertices, 0x5a, 64);
                }
                check(SUCCEEDED(vertex_buffer->Unlock()),
                      "sync selftest: upload Direct3D vertex buffer staging");
                D3DVERTEXBUFFER_DESC description{};
                check(SUCCEEDED(vertex_buffer->GetDesc(&description)) && description.Size == 64 &&
                          description.FVF == D3DFVF_XYZ,
                      "sync selftest: query Direct3D vertex buffer description");
                IDirect3DDevice9 *buffer_device = nullptr;
                check(SUCCEEDED(vertex_buffer->GetDevice(&buffer_device)) &&
                          buffer_device == base_device,
                      "sync selftest: retain Direct3D vertex buffer device owner");
                if (buffer_device != nullptr) {
                    buffer_device->Release();
                }
                IDirect3DVertexBuffer9 *queried_buffer = nullptr;
                check(SUCCEEDED(vertex_buffer->QueryInterface(
                          __uuidof(IDirect3DVertexBuffer9),
                          reinterpret_cast<void **>(&queried_buffer))) &&
                          queried_buffer == vertex_buffer,
                      "sync selftest: Direct3D vertex buffer QueryInterface lifetime");
                if (queried_buffer != nullptr) {
                    queried_buffer->Release();
                }
                check(SUCCEEDED(base_device->SetStreamSource(0, vertex_buffer, 0, 12)) &&
                          SUCCEEDED(base_device->SetFVF(D3DFVF_XYZ)) &&
                          SUCCEEDED(base_device->BeginScene()) &&
                          SUCCEEDED(base_device->DrawPrimitive(D3DPT_TRIANGLELIST, 0, 1)) &&
                          SUCCEEDED(base_device->EndScene()) &&
                          SUCCEEDED(base_device->SetStreamSource(0, nullptr, 0, 0)),
                      "sync selftest: draw from Direct3D vertex buffer proxy");
                check(FAILED(vertex_buffer->Lock(0, 0, nullptr, 0)),
                      "sync selftest: reject null Direct3D vertex buffer lock output");
                vertex_buffer->Release();
            }
            check(FAILED(base_device->CreateVertexBuffer(64, 0, D3DFVF_XYZ, D3DPOOL_DEFAULT,
                                                         nullptr, nullptr)),
                  "sync selftest: reject null Direct3D vertex buffer output");
            IDirect3DIndexBuffer9 *index_buffer = nullptr;
            check(SUCCEEDED(base_device->CreateIndexBuffer(12, 0, D3DFMT_INDEX16, D3DPOOL_DEFAULT,
                                                           &index_buffer, nullptr)) &&
                      index_buffer != nullptr,
                  "sync selftest: create Direct3D index buffer proxy");
            if (index_buffer != nullptr) {
                void *indices = nullptr;
                check(SUCCEEDED(index_buffer->Lock(0, 0, &indices, 0)) && indices != nullptr,
                      "sync selftest: lock Direct3D index buffer staging");
                if (indices != nullptr) {
                    std::memset(indices, 0, 12);
                }
                check(SUCCEEDED(index_buffer->Unlock()),
                      "sync selftest: upload Direct3D index buffer staging");
                D3DINDEXBUFFER_DESC description{};
                check(SUCCEEDED(index_buffer->GetDesc(&description)) && description.Size == 12 &&
                          description.Format == D3DFMT_INDEX16,
                      "sync selftest: query Direct3D index buffer description");
                IDirect3DIndexBuffer9 *queried_buffer = nullptr;
                check(SUCCEEDED(index_buffer->QueryInterface(
                          __uuidof(IDirect3DIndexBuffer9),
                          reinterpret_cast<void **>(&queried_buffer))) &&
                          queried_buffer == index_buffer,
                      "sync selftest: Direct3D index buffer QueryInterface lifetime");
                if (queried_buffer != nullptr) {
                    queried_buffer->Release();
                }
                check(SUCCEEDED(base_device->SetIndices(index_buffer)) &&
                          SUCCEEDED(base_device->SetIndices(nullptr)),
                      "sync selftest: bind and unbind Direct3D index buffer proxy");
                index_buffer->Release();
            }
            check(FAILED(base_device->CreateIndexBuffer(12, 0, D3DFMT_INDEX16, D3DPOOL_DEFAULT,
                                                        nullptr, nullptr)),
                  "sync selftest: reject null Direct3D index buffer output");
            void *unsupported_device_interface = reinterpret_cast<void *>(1);
            check(base_device->QueryInterface(__uuidof(IDirect3DTexture9),
                                              &unsupported_device_interface) == E_NOINTERFACE &&
                      unsupported_device_interface == nullptr,
                  "sync selftest: reject unsupported Direct3D device interface");
            base_device->Release();
        }
        if (device_window != nullptr) {
            DestroyWindow(device_window);
        }
        IDirect3DDevice9Ex *device = reinterpret_cast<IDirect3DDevice9Ex *>(1);
        check(FAILED(direct3d->CreateDeviceEx(0, D3DDEVTYPE_HAL, nullptr, 0, nullptr, nullptr,
                                              &device)) &&
                  device == nullptr,
              "sync selftest: fail closed before Direct3D device proxy");
        direct3d->Release();
    }
    check(FAILED(Direct3DCreate9Ex(D3D_SDK_VERSION, nullptr)),
          "sync selftest: reject null Direct3D output");

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

    char application_data[MAX_PATH]{};
    check(SHGetSpecialFolderPathA(nullptr, application_data, CSIDL_APPDATA, FALSE) != FALSE &&
              application_data[0] != '\0',
          "sync selftest: marshal ANSI special-folder path");
    check(SHGetSpecialFolderPathA(nullptr, nullptr, CSIDL_APPDATA, FALSE) == FALSE &&
              GetLastError() == ERROR_INVALID_PARAMETER,
          "sync selftest: reject null special-folder output");
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
        MSG presentation_queue_message{};
        check(PeekMessageW(&presentation_queue_message, nullptr, WM_APP + 77, WM_APP + 77,
                           PM_REMOVE) != FALSE &&
                  presentation_queue_message.message == WM_APP + 77 &&
                  presentation_queue_message.wParam == 0x12 &&
                  presentation_queue_message.lParam == 0x34,
              "sync selftest: preserve guest message across presentation heartbeat");
        ShowWindow(legacy_window, SW_SHOW);
        SetForegroundWindow(legacy_window);
        check(GetForegroundWindow() == legacy_window,
              "sync selftest: virtualize foreground query to process-owned window");
        check(SendMessageW(legacy_window, WM_APP + 2, 0, 0) == 0x1234 &&
                  legacy_window_callback_seen,
              "sync selftest: dispatch legacy registered window callback");
        check(PostMessageW(legacy_window, WM_KEYDOWN, 'Z', 1) != FALSE,
              "sync selftest: queue guest keyboard message");
        MSG keyboard_message{};
        check(PeekMessageW(&keyboard_message, legacy_window, WM_KEYDOWN, WM_KEYDOWN, PM_REMOVE) !=
                      FALSE &&
                  keyboard_message.hwnd == legacy_window && keyboard_message.wParam == 'Z',
              "sync selftest: marshal guest keyboard message");
        DispatchMessageW(&keyboard_message);
        check(legacy_key_message_seen, "sync selftest: dispatch guest keyboard message callback");
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

    const HWND modeless_dialog =
        CreateDialogParamW(GetModuleHandleW(nullptr), MAKEINTRESOURCEW(IDD_CALLBACK_TEST), nullptr,
                           test_modeless_dialog_procedure, 0x31415926);
    check(modeless_dialog != nullptr && modeless_dialog_init_seen,
          "sync selftest: create modeless dialog callback");
    if (modeless_dialog != nullptr) {
        SendMessageW(modeless_dialog, WM_APP + 4, 0, 0);
        check(modeless_dialog_message_seen,
              "sync selftest: dispatch persistent modeless dialog callback");
        check(DestroyWindow(modeless_dialog) != FALSE,
              "sync selftest: destroy modeless dialog callback window");
    }
    SetLastError(ERROR_SUCCESS);
    check(CreateDialogParamW(GetModuleHandleW(nullptr), MAKEINTRESOURCEW(IDD_CALLBACK_TEST),
                             nullptr, nullptr, 0) == nullptr &&
              GetLastError() == ERROR_INVALID_PARAMETER,
          "sync selftest: reject null modeless dialog callback");
    SetLastError(ERROR_SUCCESS);
    check(CreateDialogParamW(GetModuleHandleW(nullptr), MAKEINTRESOURCEW(0x7fff), nullptr,
                             test_modeless_dialog_procedure, 0) == nullptr &&
              GetLastError() != ERROR_SUCCESS,
          "sync selftest: reject missing modeless dialog resource");
    SetLastError(ERROR_SUCCESS);
    check(DestroyWindow(reinterpret_cast<HWND>(0xdead)) == FALSE &&
              GetLastError() == ERROR_INVALID_WINDOW_HANDLE,
          "sync selftest: reject invalid window destruction handle");

    font_enum_device_context = GetDC(nullptr);
    check(font_enum_device_context != nullptr, "sync selftest: acquire font enumeration context");
    if (font_enum_device_context != nullptr) {
        check(EnumFontsW(font_enum_device_context, nullptr, test_font_enum_procedure, 0x22334455) ==
                      0 &&
                  font_enum_callback_seen && extended_font_enum_callback_seen,
              "sync selftest: nested Unicode font enumeration callbacks");
        check(EnumFontFamiliesW(font_enum_device_context, nullptr, test_font_enum_procedure,
                                0x44556677) == 0 &&
                  family_font_enum_callback_seen,
              "sync selftest: Unicode font-family callback");
        SetLastError(ERROR_SUCCESS);
        check(EnumFontsW(font_enum_device_context, nullptr, reinterpret_cast<FONTENUMPROCW>(0xdead),
                         0) == 0 &&
                  GetLastError() == ERROR_INVALID_PARAMETER,
              "sync selftest: reject invalid font enumeration callback");
        SetLastError(ERROR_SUCCESS);
        check(EnumFontFamiliesExW(font_enum_device_context, nullptr, test_font_enum_procedure, 0,
                                  0) == 0 &&
                  GetLastError() == ERROR_INVALID_PARAMETER,
              "sync selftest: reject null extended font request");
        ReleaseDC(nullptr, font_enum_device_context);
        font_enum_device_context = nullptr;
    }

    check(LineDDA(-2, 3, 2, 3, test_line_dda_procedure,
                  static_cast<LPARAM>(0x123456789abcdef0ULL)) != FALSE &&
              line_dda_point_count == 4 && nested_line_dda_point_count == 3,
          "sync selftest: nested LineDDA guest callbacks");
    SetLastError(ERROR_SUCCESS);
    check(LineDDA(0, 0, 2, 2, reinterpret_cast<LINEDDAPROC>(0xdead), 0) == FALSE &&
              GetLastError() == ERROR_INVALID_PARAMETER,
          "sync selftest: reject invalid LineDDA callback");

    expected_enum_parent = CreateWindowExW(0, L"STATIC", L"enumeration parent", WS_POPUP, 0, 0, 100,
                                           100, nullptr, nullptr, nullptr, nullptr);
    expected_enum_child = CreateWindowExW(0, L"STATIC", L"enumeration child", WS_CHILD, 0, 0, 50,
                                          50, expected_enum_parent, nullptr, nullptr, nullptr);
    expected_enum_grandchild =
        CreateWindowExW(0, L"STATIC", L"enumeration grandchild", WS_CHILD, 0, 0, 25, 25,
                        expected_enum_child, nullptr, nullptr, nullptr);
    check(expected_enum_parent != nullptr && expected_enum_child != nullptr &&
              expected_enum_grandchild != nullptr,
          "sync selftest: create window enumeration tree");
    check(EnumChildWindows(expected_enum_parent, test_window_enum_procedure, 0x10203040) != FALSE &&
              outer_enum_callback_seen && nested_enum_callback_seen,
          "sync selftest: nested child-window enumeration callbacks");
    check(EnumWindows(test_window_enum_procedure, 0x11223344) != FALSE &&
              process_enum_callback_seen,
          "sync selftest: process-owned top-level window enumeration");
    SetLastError(ERROR_SUCCESS);
    check(EnumChildWindows(expected_enum_parent, reinterpret_cast<WNDENUMPROC>(0xdead), 0) ==
                  FALSE &&
              GetLastError() == ERROR_INVALID_PARAMETER,
          "sync selftest: reject invalid window enumeration callback");
    if (expected_enum_parent != nullptr) {
        DestroyWindow(expected_enum_parent);
    }

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

    const HANDLE timer = CreateWaitableTimerW(nullptr, FALSE, nullptr);
    check(timer != nullptr, "sync selftest: waitable timer creation");
    if (timer != nullptr) {
        check(WaitForSingleObject(timer, 0) == WAIT_TIMEOUT,
              "sync selftest: inactive waitable timer wait");
        LARGE_INTEGER due_time{};
        due_time.QuadPart = -10000;
        check(SetWaitableTimer(timer, &due_time, 0, nullptr, nullptr, FALSE) != FALSE,
              "sync selftest: arm waitable timer");
        check(WaitForSingleObject(timer, 1000) == WAIT_OBJECT_0,
              "sync selftest: signaled waitable timer wait");
        check(SetWaitableTimer(timer, &due_time, 0, reinterpret_cast<PTIMERAPCROUTINE>(1), nullptr,
                               FALSE) == FALSE &&
                  GetLastError() == ERROR_NOT_SUPPORTED,
              "sync selftest: reject guest waitable timer callback");
        check(SetWaitableTimer(timer, reinterpret_cast<LARGE_INTEGER *>(1), 0, nullptr, nullptr,
                               FALSE) == FALSE &&
                  GetLastError() == ERROR_INVALID_PARAMETER,
              "sync selftest: reject invalid waitable timer due time");
    }
    check(CreateWaitableTimerW(reinterpret_cast<SECURITY_ATTRIBUTES *>(1), FALSE, nullptr) ==
                  nullptr &&
              GetLastError() == ERROR_NOT_SUPPORTED,
          "sync selftest: reject waitable timer security attributes");

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
    if (timer != nullptr) {
        CloseHandle(timer);
    }

    const HANDLE process_heap = GetProcessHeap();
    auto *heap_block = static_cast<unsigned char *>(HeapAlloc(process_heap, 0, 32));
    check(heap_block != nullptr, "sync selftest: allocate guest heap block");
    if (heap_block != nullptr) {
        for (unsigned index = 0; index < 32; ++index) {
            heap_block[index] = static_cast<unsigned char>(index);
        }
        auto *grown = static_cast<unsigned char *>(HeapReAlloc(process_heap, 0, heap_block, 64));
        bool preserved = grown != nullptr && HeapSize(process_heap, 0, grown) == 64;
        for (unsigned index = 0; preserved && index < 32; ++index) {
            preserved = grown[index] == static_cast<unsigned char>(index);
        }
        check(preserved, "sync selftest: grow guest heap block and preserve contents");
        if (grown != nullptr) {
            check(HeapFree(process_heap, 0, grown) != FALSE,
                  "sync selftest: free guest heap block");
            auto *reused = HeapAlloc(process_heap, 0, 16);
            check(reused == grown || reused == heap_block,
                  "sync selftest: reuse released guest heap address range");
            check(HeapFree(process_heap, 0, reused) != FALSE,
                  "sync selftest: free reused guest heap block");
            check(HeapFree(process_heap, 0, reused) == FALSE &&
                      GetLastError() == ERROR_INVALID_PARAMETER,
                  "sync selftest: reject guest heap double free");
        }
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
