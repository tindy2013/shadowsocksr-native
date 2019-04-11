#include <stdio.h>
#if defined(WIN32)
#include <windows.h>
#endif
#include "text_in_color.h"

void print_text_in_color(const char *text, enum text_color color) {
#if defined(WIN32)
    WORD wAttributes = 0;
    HANDLE  hConsole;
    CONSOLE_SCREEN_BUFFER_INFO csbiInfo = { 0 };

#define TEXT_COLOR_WIN(item, ansi_text, win_int) case (item): wAttributes = (win_int); break;
    switch (color) {
        TEXT_COLOR_MAP(TEXT_COLOR_WIN)
    default:;  // Silence text_color_max -Wswitch warning.
    }
#undef TEXT_COLOR_WIN

    hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
    GetConsoleScreenBufferInfo(hConsole, &csbiInfo);
    SetConsoleTextAttribute(hConsole, wAttributes);
    printf("%s", text);
    SetConsoleTextAttribute(hConsole, csbiInfo.wAttributes);

#else
    const char *clr_txt = ANSI_COLOR_RESET;

#define TEXT_COLOR_UNIX(item, ansi_text, win_int) case (item): clr_txt = (ansi_text); break;
    switch (color) {
        TEXT_COLOR_MAP(TEXT_COLOR_UNIX)
    default:;  // Silence text_color_max -Wswitch warning.
    }
#undef TEXT_COLOR_UNIX

    printf("%s%s" ANSI_COLOR_RESET, clr_txt, text);

#endif /* WIN32 */
}
