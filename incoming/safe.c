#include <string.h>
void ok() {
    char b[100];
    strncpy(b, "safe", 99);
    b[99] = '\0';
}
