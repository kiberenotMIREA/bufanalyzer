%global run_user user-12-31

Name:           buffer-overflow-analyzer
Version:        1.0
Release:        1%{?dist}
Summary:        Статический анализатор опасных функций C

License:        GPLv3
Source0:        %{name}-%{version}.tar.gz

BuildRequires:  gcc make
Requires:       inotify-tools systemd coreutils grep
Requires(pre):  shadow-utils
Requires(post): systemd
Requires(preun): systemd
Requires(postun): systemd

# Отключаем генерацию debuginfo пакетов
%define debug_package %{nil}

%pre
# Условное создание пользователя и группы
# Используем 2>/dev/null для подавления ошибок если уже существуют
getent group %{run_user} >/dev/null 2>&1 || groupadd -r %{run_user} 2>/dev/null || true
getent passwd %{run_user} >/dev/null 2>&1 || useradd -r -g %{run_user} \
  -d /var/lib/bufanalyzer -s /sbin/nologin \
  -c "Buffer Analyzer User" %{run_user} 2>/dev/null || true

%post
# Создание рабочих каталогов и настройка прав
mkdir -p /var/lib/bufanalyzer/{incoming,reports}
chown -R %{run_user}:%{run_user} /var/lib/bufanalyzer
chmod 750 /var/lib/bufanalyzer/{incoming,reports}
systemctl daemon-reload
systemctl enable bufanalyzer.service >/dev/null 2>&1 || :

%preun
if [ \$1 -eq 0 ]; then
    systemctl --no-reload disable bufanalyzer.service >/dev/null 2>&1 || :
fi

%postun
if [ \$1 -ge 1 ]; then
    systemctl try-restart bufanalyzer.service >/dev/null 2>&1 || :
fi

%files
%attr(4755,root,%{run_user}) %{_bindir}/bufanalyzer
%{_bindir}/bufanalyzer-daemon
%config(noreplace) %{_sysconfdir}/bufanalyzer.conf
%{_unitdir}/bufanalyzer.service
%dir %attr(0750,%{run_user},%{run_user}) /var/lib/bufanalyzer
%dir %attr(0750,%{run_user},%{run_user}) /var/lib/bufanalyzer/incoming
%dir %attr(0750,%{run_user},%{run_user}) /var/lib/bufanalyzer/reports
%doc README.md

%description
Анализатор + демон для поиска функций, подверженных переполнению буфера.

Проект включает:
- Утилиту командной строки bufanalyzer для статического анализа C-кода
- Системный демон bufanalyzer-daemon для мониторинга каталогов
- Генерацию Markdown-отчётов об обнаруженных проблемах
- Интеграцию с syslog и systemd

%description -l ru
Анализатор + демон для поиска функций, подверженных переполнению буфера.

Проект включает:
- Утилиту командной строки bufanalyzer для статического анализа C-кода
- Системный демон bufanalyzer-daemon для мониторинга каталогов
- Генерацию Markdown-отчётов об обнаруженных проблемах
- Интеграцию с syslog и systemd

%prep
%setup -q

%build
make

%install
# Создать необходимые каталоги в buildroot
mkdir -p %{buildroot}%{_bindir}
mkdir -p %{buildroot}%{_sysconfdir}
mkdir -p %{buildroot}%{_unitdir}
mkdir -p %{buildroot}/var/lib/bufanalyzer/{incoming,reports}

install -D -m 4755 bufanalyzer %{buildroot}%{_bindir}/bufanalyzer
install -D -m 0755 bufanalyzer-daemon %{buildroot}%{_bindir}/bufanalyzer-daemon
install -m 644 config/bufanalyzer.conf %{buildroot}%{_sysconfdir}/bufanalyzer.conf
install -D -m 644 service/bufanalyzer.service %{buildroot}%{_unitdir}/bufanalyzer.service

%changelog
* Fri Nov 28 2025 Юлия Горбачева <yuliya.gorbacheva.06@list.ru> - 1.0-1
- Первая версия
- Добавлены зависимости: inotify-tools, systemd, coreutils, grep
