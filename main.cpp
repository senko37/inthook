#include <iostream>
#include "inthook.hpp"

typedef int (WINAPI* tMessageBoxA)(HWND hWnd, LPCSTR lpText, LPCSTR lpCaption, UINT uType);
tMessageBoxA oMessageBoxA;

int WINAPI hMessageBoxA(HWND hWnd, LPCSTR lpText, LPCSTR lpCaption, UINT uType) {
    printf(":)");
    return oMessageBoxA(hWnd, "hooked", lpCaption, MB_ICONWARNING | uType);
}

int main() {
    if (!inthook::init()) 
        return 1;

    if (!inthook::create(MessageBoxA, &hMessageBoxA, reinterpret_cast<void*&>(oMessageBoxA)))
        return 2;

    MessageBoxA(0, "hello world", "hello world", MB_OK);

    inthook::remove(MessageBoxA);

    MessageBoxA(0, "hello world", "hello world", MB_OK);

    inthook::uninit();

    getchar();
    return 0;
}