#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <regex.h>
#include <libgen.h>

const char* dangerous[] = {"strcpy","strcat","sprintf","vsprintf","gets","realpath","getwd","confstr",NULL};
const char* warning[]   = {"strncpy","strncat","snprintf","vsnprintf",NULL};

int is_dangerous(const char* f) {
    for (int i = 0; dangerous[i]; i++) if (strcmp(f, dangerous[i]) == 0) return 2;
    for (int i = 0; warning[i];   i++) if (strcmp(f, warning[i])   == 0) return 1;
    return 0;
}

int main(int argc, char **argv) {
    regex_t re;
    regcomp(&re, "\\b([a-zA-Z_][a-zA-Z0-9_]*)[ \t]*\\(", REG_EXTENDED);

    for (int i = 1; i < argc; i++) {
        FILE *f = fopen(argv[i], "r");
        if (!f) continue;
        char *line = NULL; size_t len = 0;
        int lineno = 0;
        while (getline(&line, &len, f) != -1) {
            lineno++;
            regmatch_t pm[2];
            char *p = line;
            while (regexec(&re, p, 2, pm, 0) == 0) {
                char func[64] = {0};
                int l = pm[1].rm_eo - pm[1].rm_so;
                strncpy(func, p + pm[1].rm_so, l);
                func[l] = '\0';
                int lvl = is_dangerous(func);
                if (lvl == 2) printf("\033[1;31mОПАСНО\033[0m: %s:%d → %s()\n", basename(argv[i]), lineno, func);
                else if (lvl == 1) printf("\033[1;33mПРЕДУПРЕЖДЕНИЕ\033[0m: %s:%d → %s()\n", basename(argv[i]), lineno, func);
                p += pm[0].rm_eo;
            }
        }
        free(line); fclose(f);
    }
    regfree(&re);
    return 0;
}
