# Buffer Overflow Analyzer

Статический анализатор кода на языке C, выявляющий вызовы потенциально опасных функций (например, strcpy, gets, sprintf и др.).

Проект включает:
- Командную утилиту "bufanalyzer"
- Системный демон "bufanalyzer-daemon"
- Генерацию подробных Markdown-отчётов
- Интеграцию с syslog и systemd

## Зависимости:
- inotify-tools (для работы демона)
- gcc, make (для сборки)
- systemd (для работы службы)

После установки:
- Демон будет следить за каталогом /var/lib/bufanalyzer/incoming
- Отчёты сохраняются в /var/lib/bufanalyzer/reports
- Пользователь user-12-31 создаётся автоматически

Как использовать:
- bufanalyzer your-file.c
- sudo cp file.c /var/lib/bufanalyzer/incoming/
- journalctl -u bufanalyzer.service -f

Безопасность:
- Программа bufanalyzer имеет setuid-бит
- Демон работает от пользователя user-12-31

Разработчик: Юлия Горбачева <yuliya.gorbacheva.06@list.ru>
