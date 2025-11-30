#define _GNU_SOURCE  // Для getline(), basename() и других GNU-расширений
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/inotify.h>  // Мониторинг файловой системы
#include <unistd.h>
#include <syslog.h>
#include <time.h>         // time(), localtime(), strftime()
#include <limits.h>       // PATH_MAX
#include <libgen.h>
#include <regex.h>
#include <pwd.h>
#include <sys/stat.h>

/*
 * КОНСТАНТЫ ПУТЕЙ К РАБОЧИМ КАТАЛОГАМ
 * 
 * Эти пути используются демоном для мониторинга и хранения отчётов.
 * В production-среде должны соответствовать настройкам в конфигурации.
 */
const char *incoming_dir = "/var/lib/bufanalyzer/incoming";  // Каталог для новых файлов
const char *report_dir    = "/var/lib/bufanalyzer/reports";   // Каталог для отчётов

/*
 * МАССИВЫ ОПАСНЫХ ФУНКЦИЙ (ТЕ ЖЕ, ЧТО И В MAIN.C)
 * Для консистентности используем те же списки, что и в основной утилите.
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
 * (идентична функции из main.c)
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
 * (идентична функция из main.c)
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
 * 
 * Назначение: Анализирует файл и создаёт Markdown-отчёт
 * Это основная рабочая функция демона, выполняющая:
 * 1. Анализ файла на наличие опасных функций
 * 2. Подсчёт статистики
 * 3. Генерацию отчёта в формате Markdown
 * 4. Логирование результатов
 * 
 * Аргументы:
 *   filepath - полный путь к анализируемому файлу
 */
void analyze_and_report(const char* filepath) {
    // Открываем файл для чтения
    FILE *f = fopen(filepath, "r");
    if (!f) {
        syslog(LOG_ERR, "Не удалось открыть файл для анализа: %s", filepath);
        return;  // Выходим при ошибке открытия файла
    }

    // Компилируем регулярное выражение для поиска вызовов функций
    regex_t re;
    regcomp(&re, "\\b([a-zA-Z_][a-zA-Z0-9_]*)[ \t]*\\(", REG_EXTENDED);

    // ========== ПЕРЕМЕННЫЕ ДЛЯ СТАТИСТИКИ И ОТЧЁТА ==========
    int dangers = 0;      // Счётчик опасных вызовов
    int warnings = 0;     // Счётчик предупреждений
    
    // Буфер для накопления деталей отчёта (16KB должно хватить для большинства файлов)
    char details[16384] = {0};
    char *ptr = details;  // Указатель на текущую позицию в буфере

    // ========== ПЕРЕМЕННЫЕ ДЛЯ ЧТЕНИЯ ФАЙЛА ==========
    char *line = NULL;    // Буфер для строки (выделяется getline)
    size_t len = 0;       // Размер выделенного буфера
    int lineno = 0;       // Номер текущей строки

    // ========== АНАЛИЗ ФАЙЛА ПОСТРОЧНО ==========
    while (getline(&line, &len, f) != -1) {
        lineno++;  // Увеличиваем счётчик строк
        
        // Пропускаем строки с комментариями и строками
        if (skip_line(line)) {
            free(line); 
            line = NULL; 
            continue;
        }

        // ========== ПОИСК ВЫЗОВОВ ФУНКЦИЙ В СТРОКЕ ==========
        regmatch_t pm[2];
        char *p = line;
        
        while (regexec(&re, p, 2, pm, 0) == 0) {
            // Извлекаем имя функции из совпадения
            char func[64] = {0};
            int l = pm[1].rm_eo - pm[1].rm_so;
            
            // БЕЗОПАСНОСТЬ: Проверка переполнения буфера
            if (l >= 64) l = 63;  // Оставляем место для '\0'
            
            strncpy(func, p + pm[1].rm_so, l);
            func[l] = '\0';  // Гарантированное завершение строки

            // Проверяем уровень опасности функции
            int lvl = is_dangerous(func);
            
            if (lvl == 2) {
                // ОПАСНАЯ ФУНКЦИЯ: увеличиваем счётчик и добавляем в отчёт
                dangers++;
                
                // Форматируем строку в Markdown и добавляем в буфер
                // snprintf возвращает количество записанных символов
                ptr += snprintf(ptr, sizeof(details) - (ptr - details),
                                "- **ОПАСНО** строка %d: `%s()`\n", lineno, func);
            } 
            else if (lvl == 1) {
                // ФУНКЦИЯ С ПРЕДУПРЕЖДЕНИЕМ
                warnings++;
                ptr += snprintf(ptr, sizeof(details) - (ptr - details),
                                "- **ПРЕДУПРЕЖДЕНИЕ** строка %d: `%s()`\n", lineno, func);
            }
            
            // Переходим к следующему совпадению в строке
            p += pm[0].rm_eo;
        }
        
        // Очищаем память, выделенную getline
        free(line); 
        line = NULL;
    }
    
    // ========== ЗАВЕРШЕНИЕ АНАЛИЗА ==========
    fclose(f);      // Закрываем файл
    regfree(&re);   // Освобождаем регулярное выражение

    // ========== ГЕНЕРАЦИЯ ИМЕНИ ОТЧЁТА ==========
    // Создаём уникальное имя отчёта с временной меткой,
    // чтобы избежать конфликтов при одновременной обработке файлов
    
    time_t t = time(NULL);  // Текущее время в секундах с эпохи
    char timestamp[64];     // Буфер для форматированного времени
    
    // Форматируем время: ГГГГ-ММ-ДД_ЧЧММСС
    strftime(timestamp, sizeof(timestamp), "%Y-%m-%d_%H%M%S", localtime(&t));
    
    // Формируем полный путь к отчёту
    char report_path[PATH_MAX];
    snprintf(report_path, sizeof(report_path), 
             "%s/report_%s_%s.md",          // Шаблон пути
             report_dir, timestamp,         // Каталог и временная метка
             basename((char*)filepath));    // Имя исходного файла

    // ========== СОЗДАНИЕ MARKDOWN-ОТЧЁТА ==========
    FILE *r = fopen(report_path, "w");
    if (r) {
        // ----- ЗАГОЛОВОК И МЕТА-ИНФОРМАЦИЯ -----
        fprintf(r, "# Отчёт статического анализа\n\n");
        fprintf(r, "**Файл:** `%s`\n", basename((char*)filepath));
        fprintf(r, "**Дата анализа:** %s\n\n", timestamp);
        
        // ----- СТАТИСТИКА -----
        fprintf(r, "**Опасных вызовов:** %d\n", dangers);
        fprintf(r, "**Предупреждений:** %d\n\n", warnings);
        
        // ----- ДЕТАЛИ ОБНАРУЖЕННЫХ ПРОБЛЕМ -----
        fprintf(r, "## Обнаруженные проблемы\n\n");
        
        if (dangers + warnings > 0) {
            // Есть проблемы: выводим детали
            fprintf(r, "%s\n", details);
        } else {
            // Проблем не обнаружено
            fprintf(r, "Проблем не обнаружено — код безопасен!\n");
        }
        
        fclose(r);  // Закрываем файл отчёта
        
        // Логируем успешное создание отчёта
        syslog(LOG_INFO, "Создан отчёт: %s (опасно=%d, предупреждений=%d)", 
               report_path, dangers, warnings);
    }
    // Примечание: если fopen() вернул NULL, отчёт не создаётся,
    // но это уже залогировано при открытии исходного файла
}

/*
 * ГЛАВНАЯ ФУНКЦИЯ ДЕМОНА: main()
 * 
 * Назначение: Точка входа демона, основной цикл мониторинга
 * Демон работает в фоновом режиме и:
 * 1. Настраивает мониторинг каталога incoming_dir
 * 2. Ожидает появления новых файлов .c и .h
 * 3. Запускает анализ для каждого нового файла
 * 4. Архивирует обработанные файлы
 */
int main() {
    // ========== НАСТРОЙКА ЛОГИРОВАНИЯ ==========
    // Динамическое определение имени пользователя для syslog
    struct passwd *pw = getpwuid(getuid());
    const char *username = pw ? pw->pw_name : "user-12-31";
    
    // Открываем syslog с facility LOG_DAEMON (для демонов)
    openlog(username, LOG_PID | LOG_NDELAY, LOG_DAEMON);
    syslog(LOG_INFO, "Запуск демона анализа кода от пользователя %s", username);

    // ========== СОЗДАНИЕ РАБОЧИХ КАТАЛОГОВ ==========
    // Создаём каталоги с правами 0750 (rwxr-x---):
    // - Владелец: полные права
    // - Группа: чтение и выполнение
    # - Остальные: нет доступа
    mkdir(incoming_dir, 0750);
    mkdir(report_dir, 0750);

    // ========== ИНИЦИАЛИЗАЦИЯ INOTIFY ==========
    // Inotify - механизм ядра Linux для мониторинга изменений в файловой системе
    
    int fd = inotify_init();  // Создаём экземпляр inotify
    if (fd < 0) {
        syslog(LOG_CRIT, "inotify_init() failed");
        return 1;  // Критическая ошибка: не можем мониторить файлы
    }

    // Настраиваем отслеживание событий в каталоге incoming
    // IN_CLOSE_WRITE - файл был открыт для записи и закрыт
    // IN_MOVED_TO - файл был перемещён в отслеживаемый каталог
    int wd = inotify_add_watch(fd, incoming_dir, IN_CLOSE_WRITE | IN_MOVED_TO);
    
    if (wd < 0) {
        syslog(LOG_CRIT, "Не удалось установить слежение за %s", incoming_dir);
        close(fd);  // Закрываем дескриптор inotify
        return 1;   // Критическая ошибка
    }

    // ========== НАСТРОЙКА БУФЕРА ДЛЯ СОБЫТИЙ ==========
    // Размер буфера рассчитан на 1024 события inotify
    // Каждое событие: структура inotify_event + до 16 символов имени файла
    char buffer[1024 * (sizeof(struct inotify_event) + 16)];
    
    // ========== ОСНОВНОЙ ЦИКЛ ДЕМОНА ==========
    while (1) {
        // Ожидаем события inotify (блокирующий вызов)
        ssize_t len = read(fd, buffer, sizeof(buffer));
        
        // Обрабатываем ошибки чтения
        if (len <= 0) {
            # len == 0: EOF (невозможно для inotify)
            # len < 0: ошибка (например, EINTR - прервано сигналом)
            continue;  // Продолжаем цикл
        }

        // ========== ОБРАБОТКА СОБЫТИЙ В БУФЕРЕ ==========
        char *ptr = buffer;  // Указатель на начало буфера
        
        // Проходим по всем событиям в буфере
        while (ptr < buffer + len) {
            // Приводим указатель к типу события inotify
            struct inotify_event *event = (struct inotify_event *)ptr;

            // Проверяем, что событие содержит имя файла (event->len > 0)
            // и файл имеет расширение .c или .h
            if (event->len > 0 &&
                (strstr(event->name, ".c") || strstr(event->name, ".h"))) {

                // ========== ФОРМИРОВАНИЕ ПУТИ К ФАЙЛУ ==========
                char fullpath[PATH_MAX];
                snprintf(fullpath, sizeof(fullpath), 
                         "%s/%s", incoming_dir, event->name);
                
                // ========== АНАЛИЗ ФАЙЛА И СОЗДАНИЕ ОТЧЁТА ==========
                analyze_and_report(fullpath);

                // ========== АРХИВАЦИЯ ОБРАБОТАННОГО ФАЙЛА ==========
                // Переименовываем файл, добавляя префикс "processed_"
                // Это предотвращает повторную обработку того же файла
                char archived[PATH_MAX];
                snprintf(archived, sizeof(archived), 
                         "%s/processed_%s", incoming_dir, event->name);
                
                rename(fullpath, archived);
            }
            
            // ========== ПЕРЕХОД К СЛЕДУЮЩЕМУ СОБЫТИЮ ==========
            // Сдвигаем указатель на размер структуры + длину имени файла
            ptr += sizeof(struct inotify_event) + event->len;
        }
    }

    // ========== ОЧИСТКА РЕСУРСОВ ==========
    // Этот код никогда не выполняется из-за бесконечного цикла,
    // но добавлен для корректности
    close(fd);    // Закрываем дескриптор inotify
    closelog();   // Закрываем соединение с syslog
    
    return 0;
}
