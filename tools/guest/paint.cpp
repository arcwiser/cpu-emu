// Guest painting application for CPUEmu.
//
// Compiled with the host toolchain and executed under the emulator:
//   build-release\cpuemu.exe build\test-apps\paint.exe                interactive window
//   build-release\cpuemu.exe build\test-apps\paint.exe -- --selftest  headless verification
//
// The interactive mode exercises the guest window-procedure bridge: the window is a real
// host window whose messages are interpreted by the emulated CPU, and all drawing goes
// through natively forwarded GDI calls.

#include <windows.h>

#include <cstdint>
#include <cwchar>

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

} // namespace

extern "C" int WINAPI wWinMain(HINSTANCE instance, HINSTANCE, PWSTR, int show_command) {
    if (wcsstr(GetCommandLineW(), L"--selftest") != nullptr) {
        return run_selftest();
    }
    return run_windowed(instance, show_command);
}
