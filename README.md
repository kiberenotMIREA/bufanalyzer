Buffer Overflow Analyzer
========================

Статический анализатор кода на языке C для поиска опасных функций (strcpy, gets, sprintf и др.).

Зависимости
-----------
- inotify-tools
- systemd
- coreutils
- grep
- shadow-utils

Установка
---------
1. Создайте пользователя:
   sudo groupadd -r user-12-31
   sudo useradd -r -g user-12-31 -d /var/lib/bufanalyzer -s /sbin/nologin user-12-31

2. Соберите и установите:
   make all
   make rpm
   sudo rpm -ivh ~/rpmbuild/RPMS/x86_64/buffer-overflow-analyzer-1.0-1.*.rpm

Использование
-------------
- Анализ файла: bufanalyzer файл.c
- Автоматический анализ: поместите файл.c в /var/lib/bufanalyzer/incoming/
- Просмотр логов: journalctl -u bufanalyzer.service -f

Безопасность
------------
- bufanalyzer имеет setuid-бит для анализа защищенных файлов
- Демон работает от непривилегированного пользователя user-12-31
- Автоматическое понижение привилегий при запуске от root

Разработчик
-----------
Юлия Горбачева <yuliya.gorbacheva.06@list.ru>
