#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/inotify.h>
#include <unistd.h>
#include <syslog.h>
#include <limits.h>
#include <libgen.h>
#include <sys/stat.h>

#define EVENT_SIZE  (sizeof(struct inotify_event))
#define BUF_LEN     (1024 * (EVENT_SIZE + 16))

const char *incoming_dir = "/var/lib/bufanalyzer/incoming";
const char *report_dir    = "/var/lib/bufanalyzer/reports";

int main() {
    openlog("bufanalyzer-daemon", LOG_PID | LOG_NDELAY, LOG_DAEMON);
    syslog(LOG_INFO, "Демон запущен с inotify");

    mkdir(incoming_dir, 0755);
    mkdir(report_dir, 0755);

    int fd = inotify_init();
    if (fd < 0) { syslog(LOG_ERR, "inotify_init failed"); return 1; }

    int wd = inotify_add_watch(fd, incoming_dir, IN_CLOSE_WRITE | IN_MOVED_TO);
    if (wd < 0) { syslog(LOG_ERR, "inotify_add_watch failed"); return 1; }

    char buffer[BUF_LEN];
    while (1) {
        ssize_t len = read(fd, buffer, BUF_LEN);
        if (len <= 0) continue;

        for (char *ptr = buffer; ptr < buffer + len; ) {
            struct inotify_event *event = (struct inotify_event *)ptr;
            if (event->len && (strstr(event->name, ".c") || strstr(event->name, ".h"))) {
                char path[PATH_MAX];
                snprintf(path, sizeof(path), "%s/%s", incoming_dir, event->name);

                char report[PATH_MAX];
                snprintf(report, sizeof(report), "%s/report_%s.md", report_dir, event->name);

                FILE *r = fopen(report, "w");
                fprintf(r, "# Отчёт\nФайл: %s\nОбнаружен через inotify\n", event->name);
                fclose(r);

                syslog(LOG_INFO, "Inotify: обработан %s", event->name);

                char archived[PATH_MAX];
                snprintf(archived, sizeof(archived), "%s/done_%s", incoming_dir, event->name);
                rename(path, archived);
            }
            ptr += EVENT_SIZE + event->len;
        }
    }
    closelog();
    return 0;
}
