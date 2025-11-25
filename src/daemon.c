#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/inotify.h>
#include <unistd.h>
#include <syslog.h>
#include <time.h>
#include <limits.h>
#include <libgen.h>
#include <regex.h>
#include <sys/stat.h>

#define EVENT_SIZE  (sizeof(struct inotify_event))
#define BUF_LEN     (1024 * (EVENT_SIZE + 16))

const char *incoming_dir = "/var/lib/bufanalyzer/incoming";
const char *report_dir    = "/var/lib/bufanalyzer/reports";

const char* dangerous[] = {"strcpy","strcat","sprintf","vsprintf","gets","realpath","getwd","confstr",NULL};
const char* warning[]   = {"strncpy","strncat","snprintf","vsnprintf",NULL};

int is_dangerous(const char* f) {
    for (int i = 0; dangerous[i]; i++) if (strcmp(f, dangerous[i]) == 0) return 2;
    for (int i = 0; warning[i];   i++) if (strcmp(f, warning[i])   == 0) return 1;
    return 0;
}

int skip_line(const char* line) {
    int in_str = 0, in_comment = 0;
    for (const char *s = line; *s; s++) {
        if (*s == '"' && (s == line || *(s-1) != '\\'))
            in_str = !in_str;
        if (in_str) continue;
        if (s[0] == '/' && s[1] == '/') return 1;
        if (s[0] == '/' && s[1] == '*') in_comment = 1;
        if (in_comment && s[0] == '*' && s[1] == '/') { in_comment = 0; s++; }
    }
    return in_comment;
}

void analyze_and_report(const char* filepath) {
    FILE *f = fopen(filepath, "r");
    if (!f) return;

    regex_t re;
    regcomp(&re, "\\b([a-zA-Z_][a-zA-Z0-9_]*)[ \t]*\\(", REG_EXTENDED);

    int dangers = 0, warnings = 0;
    char details[16384] = {0};
    char *ptr = details;

    char *line = NULL; size_t len = 0;
    int lineno = 0;
    while (getline(&line, &len, f) != -1) {
        lineno++;
        if (skip_line(line)) { free(line); line = NULL; continue; }

        regmatch_t pm[2];
        char *p = line;
        while (regexec(&re, p, 2, pm, 0) == 0) {
            char func[64] = {0};
            int l = pm[1].rm_eo - pm[1].rm_so;
            strncpy(func, p + pm[1].rm_so, l);
            func[l] = '\0';

            int lvl = is_dangerous(func);
            if (lvl == 2) {
                dangers++;
                ptr += snprintf(ptr, 16384 - (ptr-details), "- **ОПАСНО** строка %d: `%s()`\n", lineno, func);
            } else if (lvl == 1) {
                warnings++;
                ptr += snprintf(ptr, 16384 - (ptr-details), "- **ПРЕДУПРЕЖДЕНИЕ** строка %d: `%s()`\n", lineno, func);
            }
            p += pm[0].rm_eo;
        }
        free(line); line = NULL;
    }
    fclose(f);
    regfree(&re);

    time_t t = time(NULL);
    char timestamp[64];
    strftime(timestamp, sizeof(timestamp), "%Y-%m-%d_%H%M%S", localtime(&t));

    char report_path[PATH_MAX];
    snprintf(report_path, sizeof(report_path), "%s/report_%s_%s.md", report_dir, timestamp, basename((char*)filepath));

    FILE *r = fopen(report_path, "w");
    fprintf(r, "# Отчёт статического анализа\n\n");
    fprintf(r, "**Файл:** `%s`\n**Дата:** %s\n\n", basename((char*)filepath), timestamp);
    fprintf(r, "**Опасных вызовов:** %d\n**Предупреждений:** %d\n\n", dangers, warnings);
    fprintf(r, "## Найденные проблемы\n\n%s\n", (dangers + warnings) ? details : "Проблем не обнаружено.\n");
    fclose(r);

    syslog(LOG_INFO, "Создан отчёт %s (опасно=%d, предупреждения=%d)", report_path, dangers, warnings);
}

int main() {
    openlog("bufanalyzer-daemon", LOG_PID | LOG_NDELAY, LOG_DAEMON);
    syslog(LOG_INFO, "Демон запущен — полный анализ + Markdown");

    mkdir(incoming_dir, 0755);
    mkdir(report_dir, 0755);

    int fd = inotify_init();
    int wd = inotify_add_watch(fd, incoming_dir, IN_CLOSE_WRITE | IN_MOVED_TO);

    char buffer[BUF_LEN];
    while (1) {
        ssize_t len = read(fd, buffer, BUF_LEN);
        if (len <= 0) continue;

        for (char *ptr = buffer; ptr < buffer + len; ) {
            struct inotify_event *event = (struct inotify_event *)ptr;
            if (event->len && (strstr(event->name, ".c") || strstr(event->name, ".h"))) {
                char path[PATH_MAX];
                snprintf(path, sizeof(path), "%s/%s", incoming_dir, event->name);
                analyze_and_report(path);

                char archived[PATH_MAX];
                snprintf(archived, sizeof(archived), "%s/processed_%s", incoming_dir, event->name);
                rename(path, archived);
            }
            ptr += EVENT_SIZE + event->len;
        }
    }
    closelog();
    return 0;
}
