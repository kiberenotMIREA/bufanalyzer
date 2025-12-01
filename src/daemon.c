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
#include <pwd.h>
#include <sys/stat.h>
#include <errno.h>

/*
 * КОНСТАНТЫ ПУТЕЙ К РАБОЧИМ КАТАЛОГАМ
 */
const char *incoming_dir = "/var/lib/bufanalyzer/incoming";
const char *report_dir    = "/var/lib/bufanalyzer/reports";

/*
 * МАССИВЫ ОПАСНЫХ ФУНКЦИЙ
 */
const char* dangerous[] = {
    "strcpy", "strcat", "sprintf", "vsprintf",
    "gets", "realpath", "getwd", "confstr", 
    NULL
};

const char* warning[] = {
    "strncpy", "strncat", "snprintf", "vsnprintf",
    NULL
};

/*
 * ФУНКЦИЯ: is_dangerous()
 */
int is_dangerous(const char* f) {
    for (int i = 0; dangerous[i]; i++) {
        if (strcmp(f, dangerous[i]) == 0) return 2;
    }
    for (int i = 0; warning[i]; i++) {
        if (strcmp(f, warning[i]) == 0) return 1;
    }
    return 0;
}

/*
 * ФУНКЦИЯ: skip_line()
 */
int skip_line(const char* line) {
    int in_string = 0, in_comment = 0;
    for (const char *s = line; *s; s++) {
        if (*s == '"' && (s == line || *(s-1) != '\\'))
            in_string = !in_string;
        if (in_string) continue;
        if (s[0] == '/' && s[1] == '/') return 1;
        if (s[0] == '/' && s[1] == '*') in_comment = 1;
        if (in_comment && s[0] == '*' && s[1] == '/') {
            in_comment = 0;
            s++;
        }
    }
    return in_comment;
}

/*
 * ФУНКЦИЯ: analyze_and_report()
 */
void analyze_and_report(const char* filepath, const char* original_name) {
    FILE *f = fopen(filepath, "r");
    if (!f) {
        syslog(LOG_ERR, "Не удалось открыть файл для анализа: %s", filepath);
        return;
    }

    regex_t re;
    regcomp(&re, "\\b([a-zA-Z_][a-zA-Z0-9_]*)[ \t]*\\(", REG_EXTENDED);

    int dangers = 0, warnings = 0;
    char details[16384] = {0};
    char *ptr = details;

    char *line = NULL;
    size_t len = 0;
    int lineno = 0;
    
    while (getline(&line, &len, f) != -1) {
        lineno++;
        if (skip_line(line)) {
            free(line);
            line = NULL;
            continue;
        }

        regmatch_t pm[2];
        char *p = line;
        
        while (regexec(&re, p, 2, pm, 0) == 0) {
            char func[64] = {0};
            int l = pm[1].rm_eo - pm[1].rm_so;
            
            if (l >= 64) l = 63;
            
            strncpy(func, p + pm[1].rm_so, l);
            func[l] = '\0';

            int lvl = is_dangerous(func);
            
            if (lvl == 2) {
                dangers++;
                ptr += snprintf(ptr, sizeof(details) - (ptr - details),
                                "- **ОПАСНО** строка %d: `%s()`\n", lineno, func);
            } 
            else if (lvl == 1) {
                warnings++;
                ptr += snprintf(ptr, sizeof(details) - (ptr - details),
                                "- **ПРЕДУПРЕЖДЕНИЕ** строка %d: `%s()`\n", lineno, func);
            }
            
            p += pm[0].rm_eo;
        }
        
        free(line);
        line = NULL;
    }
    
    fclose(f);
    regfree(&re);

    // Генерируем временную метку
    time_t t = time(NULL);
    char timestamp[64];
    strftime(timestamp, sizeof(timestamp), "%Y-%m-%d_%H%M%S", localtime(&t));

    // Используем оригинальное имя файла без префикса "processed_"
    char clean_name[256];
    strncpy(clean_name, original_name, sizeof(clean_name));
    clean_name[sizeof(clean_name)-1] = '\0';
    
    // Удаляем префикс "processed_" если он есть
    const char *prefix = "processed_";
    size_t prefix_len = strlen(prefix);
    if (strncmp(clean_name, prefix, prefix_len) == 0) {
        memmove(clean_name, clean_name + prefix_len, strlen(clean_name) - prefix_len + 1);
    }

    // Создаем имя отчета
    char report_path[PATH_MAX];
    snprintf(report_path, sizeof(report_path), 
             "%s/report_%s_%s.md", report_dir, timestamp, clean_name);

    // Создаем отчет
    FILE *r = fopen(report_path, "w");
    if (r) {
        fprintf(r, "# Отчёт статического анализа\n\n");
        fprintf(r, "**Файл:** `%s`\n", clean_name);
        fprintf(r, "**Дата анализа:** %s\n\n", timestamp);
        fprintf(r, "**Опасных вызовов:** %d\n", dangers);
        fprintf(r, "**Предупреждений:** %d\n\n", warnings);
        fprintf(r, "## Обнаруженные проблемы\n\n");
        
        if (dangers + warnings > 0) {
            fprintf(r, "%s\n", details);
        } else {
            fprintf(r, "Проблем не обнаружено — код безопасен!\n");
        }
        
        fclose(r);
        
        syslog(LOG_INFO, "Создан отчёт: %s (опасно=%d, предупреждений=%d)", 
               report_path, dangers, warnings);
    }
}

/*
 * ФУНКЦИЯ: should_process_file()
 * Проверяет, нужно ли обрабатывать файл
 * Возвращает 1 если нужно обработать, 0 если нет
 */
int should_process_file(const char *filename) {
    // Проверяем расширение файла
    if (!strstr(filename, ".c") && !strstr(filename, ".h")) {
        return 0;
    }
    
    // Игнорируем файлы с префиксом "processed_"
    if (strncmp(filename, "processed_", 10) == 0) {
        return 0;
    }
    
    return 1;
}

/*
 * ГЛАВНАЯ ФУНКЦИЯ ДЕМОНА: main()
 */
int main() {
    struct passwd *pw = getpwuid(getuid());
    const char *username = pw ? pw->pw_name : "user-12-31";
    
    openlog(username, LOG_PID | LOG_NDELAY, LOG_DAEMON);
    syslog(LOG_INFO, "Запуск демона анализа кода от пользователя %s", username);

    // Создаём рабочие каталоги
    mkdir(incoming_dir, 0750);
    mkdir(report_dir, 0750);

    // Инициализация inotify
    int fd = inotify_init();
    if (fd < 0) {
        syslog(LOG_CRIT, "inotify_init() failed: %s", strerror(errno));
        return 1;
    }

    // Настраиваем отслеживание только для новых файлов
    int wd = inotify_add_watch(fd, incoming_dir, IN_CLOSE_WRITE);
    
    if (wd < 0) {
        syslog(LOG_CRIT, "Не удалось установить слежение за %s: %s", 
               incoming_dir, strerror(errno));
        close(fd);
        return 1;
    }

    syslog(LOG_INFO, "Демон запущен, отслеживание каталога %s", incoming_dir);

    // Буфер для событий
    char buffer[4096] __attribute__ ((aligned(__alignof__(struct inotify_event))));
    
    // Основной цикл демона
    while (1) {
        ssize_t len = read(fd, buffer, sizeof(buffer));
        
        if (len == -1) {
            if (errno == EINTR) {
                continue; // Сигнал прервал read
            }
            syslog(LOG_ERR, "Ошибка чтения inotify: %s", strerror(errno));
            continue;
        }

        // Обрабатываем события
        for (char *ptr = buffer; ptr < buffer + len; ) {
            struct inotify_event *event = (struct inotify_event *)ptr;
            
            // Проверяем, что событие содержит имя файла
            if (event->len > 0) {
                // Проверяем, нужно ли обрабатывать этот файл
                if (should_process_file(event->name)) {
                    char fullpath[PATH_MAX];
                    snprintf(fullpath, sizeof(fullpath), "%s/%s", incoming_dir, event->name);
                    
                    syslog(LOG_INFO, "Обнаружен новый файл: %s", event->name);
                    
                    // Анализируем файл и создаем отчет
                    analyze_and_report(fullpath, event->name);
                    
                    // Переименовываем файл, чтобы избежать повторной обработки
                    char archived[PATH_MAX];
                    snprintf(archived, sizeof(archived), "%s/processed_%s", incoming_dir, event->name);
                    
                    if (rename(fullpath, archived) == 0) {
                        syslog(LOG_INFO, "Файл переименован: %s -> %s", event->name, archived);
                    } else {
                        syslog(LOG_ERR, "Ошибка переименования %s: %s", 
                               event->name, strerror(errno));
                    }
                }
            }
            
            ptr += sizeof(struct inotify_event) + event->len;
        }
    }

    // Закрываем ресурсы (этот код никогда не выполняется из-за бесконечного цикла)
    close(fd);
    closelog();
    
    return 0;
}
