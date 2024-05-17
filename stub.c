#include <stdlib.h>
#include <windows.h>
int main(int argc, char* argv[]){
    if (argc > 1){
        char tmp[1000] = "Stub is running ";
        strcat(tmp, argv[1]);
        MessageBox(NULL, tmp, "Stub", MB_OK);
    }        
    else
        MessageBox(NULL, "Sample", "Stub", MB_OK);
    return 0;
}

