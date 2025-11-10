#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <regex.h>
#include <libgen.h>

int main(int argc, char **argv) {
    if (argc < 2) return 1;
    regex_t re;
    regcomp(&re, "\\bstrcpy[ \t]*\\(", REG_EXTENDED);

    for (int i = 1; i < argc; i++) {
        FILE *f = fopen(argv[i], "r");
        if (!f) continue;
        char *line = NULL; size_t len = 0;
        int lineno = 0;
        while (getline(&line, &len, f) != -1) {
            lineno++;
            if (regexec(&re, line, 0, NULL, 0) == 0) {
                printf("\033[31mОПАСНО\033[0m: %s:%d → strcpy()\n", basename(argv[i]), lineno);
            }
        }
        free(line); fclose(f);
    }
    regfree(&re);
    return 0;
}
