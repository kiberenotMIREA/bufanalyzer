%global run_user user-12-31

Name:           buffer-overflow-analyzer
Version:        1.0
Release:        1%{?dist}
Summary:        Статический анализатор опасных функций C

License:        GPLv3
Source0:        %{name}-%{version}.tar.gz

BuildRequires:  gcc make
Requires:       inotify-tools systemd coreutils grep shadow-utils

Provides: user(%{run_user})
Provides: group(%{run_user})

%define debug_package %{nil}

%pre
# Проверяем существование пользователя перед установкой
echo "Проверка пользователя %{run_user}..."
if ! getent passwd %{run_user} >/dev/null 2>&1; then
    echo "ОШИБКА: Пользователь %{run_user} не существует!" >&2
    echo "Создайте пользователя перед установкой:" >&2
    echo "  sudo groupadd -r %{run_user}" >&2
    echo "  sudo useradd -r -g %{run_user} -d /var/lib/bufanalyzer -s /sbin/nologin %{run_user}" >&2
    exit 1
fi

if ! getent group %{run_user} >/dev/null 2>&1; then
    echo "ОШИБКА: Группа %{run_user} не существует!" >&2
    exit 1
fi
echo "Пользователь %{run_user} найден, продолжаем установку..."

%post
# Создаём рабочие директории
mkdir -p /var/lib/bufanalyzer/{incoming,reports}
chown -R %{run_user}:%{run_user} /var/lib/bufanalyzer
chmod 750 /var/lib/bufanalyzer/{incoming,reports}

systemctl daemon-reload
systemctl enable bufanalyzer.service >/dev/null 2>&1 || :
systemctl start bufanalyzer.service >/dev/null 2>&1 || :

%preun
if [ $1 -eq 0 ]; then
    systemctl disable --now bufanalyzer.service >/dev/null 2>&1 || :
fi

%postun
if [ $1 -ge 1 ]; then
    systemctl try-restart bufanalyzer.service >/dev/null 2>&1 || :
fi

%files
%attr(4755,root,%{run_user}) /usr/bin/bufanalyzer
%attr(0755,root,root) /usr/bin/bufanalyzer-daemon
%config(noreplace) /etc/bufanalyzer.conf
/usr/lib/systemd/system/bufanalyzer.service
%dir %attr(0750,%{run_user},%{run_user}) /var/lib/bufanalyzer
%dir %attr(0750,%{run_user},%{run_user}) /var/lib/bufanalyzer/incoming
%dir %attr(0750,%{run_user},%{run_user}) /var/lib/bufanalyzer/reports
%doc README.md

%description
Анализатор + демон для поиска функций, подверженных переполнению буфера.

%prep
%setup -q

%build
make

%install
mkdir -p %{buildroot}/usr/bin
mkdir -p %{buildroot}/etc
mkdir -p %{buildroot}/usr/lib/systemd/system
mkdir -p %{buildroot}/var/lib/bufanalyzer/{incoming,reports}

install -m 4755 bufanalyzer %{buildroot}/usr/bin/bufanalyzer
install -m 0755 bufanalyzer-daemon %{buildroot}/usr/bin/bufanalyzer-daemon
install -m 0644 config/bufanalyzer.conf %{buildroot}/etc/bufanalyzer.conf

sed "s|@RUN_USER@|%{run_user}|g" service/bufanalyzer.service.in > \
    %{buildroot}/usr/lib/systemd/system/bufanalyzer.service

%changelog
* Mon Dec 01 2025 Юлия Горбачева <yuliya.gorbacheva.06@list.ru> - 1.0-1
- Первая версия с проверкой существования пользователя
- Добавлены зависимости: inotify-tools, systemd, coreutils, grep, shadow-utils
- Исправлена обработка файлов в демоне (устранено дублирование)
