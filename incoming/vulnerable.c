#include <string.h>
void bad() {
    char b[10];
    strcpy(b, "too long string here");
    gets(b);
}
