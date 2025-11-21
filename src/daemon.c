#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <unistd.h>
#include <syslog.h>
#include <limits.h>
#include <libgen.h>
#include <sys/stat.h>

const char *incoming_dir = "/var/lib/bufanalyzer/incoming";
const char *report_dir    = "/var/lib/bufanalyzer/reports";

int main() {
    openlog("bufanalyzer-daemon", LOG_PID | LOG_NDELAY, LOG_DAEMON);
    syslog(LOG_INFO, "Демон запущен в режиме polling");

    mkdir(incoming_dir, 0755);
    mkdir(report_dir, 0755);

    while (1) {
        DIR *dir = opendir(incoming_dir);
        if (!dir) { sleep(5); continue; }

        struct dirent *entry;
        while ((entry = readdir(dir))) {
            if (entry->d_type != DT_REG) continue;
            if (!strstr(entry->d_name, ".c") && !strstr(entry->d_name, ".h")) continue;

            char path[PATH_MAX];
            snprintf(path, sizeof(path), "%s/%s", incoming_dir, entry->d_name);

            char report[PATH_MAX];
            snprintf(report, sizeof(report), "%s/report_%s.md", report_dir, entry->d_name);

            FILE *r = fopen(report, "w");
            fprintf(r, "# Отчёт\nФайл: %s\nОбнаружен polling-демоном\n", entry->d_name);
            fclose(r);

            syslog(LOG_INFO, "Polling: обработан %s", entry->d_name);

            char archived[PATH_MAX];
            snprintf(archived, sizeof(archived), "%s/processed_%s", incoming_dir, entry->d_name);
            rename(path, archived);
        }
        closedir(dir);
        sleep(5);
    }
    closelog();
    return 0;
}
