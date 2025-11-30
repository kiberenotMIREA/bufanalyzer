# Buffer Overflow Analyzer

Статический анализатор кода на языке C.

## Зависимости:
- **inotify-tools** - для мониторинга файловой системы демоном
- **systemd** - для работы службы
- **coreutils, grep** - для базовых операций
- **shadow-utils** - для управления пользователями (автоматическое создание пользователя)

## После установки:
- Демон следит за /var/lib/bufanalyzer/incoming
- Отчёты в /var/lib/bufanalyzer/reports
- Пользователь user-12-31 создаётся автоматически через RPM

## Как собрать RPM:
make rpm

## Как установить зависимости:
make install-deps

## Разработчик:
Юлия Горбачева <yuliya.gorbacheva.06@list.ru>
