#include <stdio.h>
#include <string.h>

int main(int argc, char **argv) {
    if (argc < 2) {
        printf("Использование: %s <файл.c>\n", argv[0]);
        return 1;
    }
    FILE *f = fopen(argv[1], "r");
    if (!f) { perror(argv[1]); return 1; }
    char line[1024];
    int n = 0;
    while (fgets(line, sizeof(line), f)) {
        n++;
        if (strstr(line, "strcpy(")) {
            printf("Найден strcpy() в строке %d\n", n);
        }
    }
    fclose(f);
    return 0;
}
