#include <stdio.h>

int main() {
    write(1, "Hello\n", sizeof("Hello\n"));
    
    char a[10];
    gets(a);
}

