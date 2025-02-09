#include <windows.h>  // Including the Windows API header to use functions like LoadLibrary and MessageBox
#include <iostream>    // For standard input/output (optional for this example)

typedef void (*ShowMessageFunc)();  // Define a function pointer type to match the function in DLL

int main() {
    // Attempt to load the DLL into memory
    HMODULE hDll = LoadLibrary(L"MySimpleDLL.dll");  // L"..." is a wide-character string literal
    if (hDll == NULL) {  // Check if loading the DLL failed
        // If the DLL couldn't be loaded, show an error message box
        MessageBox(NULL, L"Failed to load the DLL!", L"Error", MB_OK | MB_ICONERROR);
        return 1;  // Exit the program with error code 1
    }

    // Get the address of the ShowMessage function from the DLL
    ShowMessageFunc ShowMessage = (ShowMessageFunc)GetProcAddress(hDll, "ShowMessage");
    if (ShowMessage == NULL) {  // Check if the function was found in the DLL
        // If the function couldn't be found, show an error message box
        MessageBox(NULL, L"Failed to find the function in the DLL!", L"Error", MB_OK | MB_ICONERROR);
        FreeLibrary(hDll);  // Don't forget to free the loaded DLL
        return 1;  // Exit the program with error code 1
    }

    // If everything is fine, call the function to show the message
    ShowMessage();  // This calls the ShowMessage function we defined in the DLL

    // Free the loaded DLL from memory after we're done
    FreeLibrary(hDll);

    return 0;  // Successfully finished, exit with code 0
}
