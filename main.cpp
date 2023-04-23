#include <iostream>
#include <Windows.h>
#include "inthook.hpp"


int WINAPI hMessageBoxA(HWND hWnd, LPCSTR lpText, LPCSTR lpCaption, UINT uType) {
    printf(":)");
    inthook::ignore(MessageBoxA);
    return MessageBoxA(hWnd, "hooked", lpCaption, MB_ICONWARNING | uType);
}

int main() {
    if (!inthook::init()) 
        return 1;

    if (!inthook::create(MessageBoxA, hMessageBoxA))
        return 2;

    MessageBoxA(0, "hello world", "hello world", MB_OK);

    inthook::remove(MessageBoxA);

    MessageBoxA(0, "hello world", "hello world", MB_OK);

    inthook::uninit();

    getchar();
    return 0;
}