CC = gcc
CFLAGS = -Wall -Wextra -O2
TARGET = bufanalyzer
DAEMON = bufanalyzer-daemon
PKGNAME = buffer-overflow-analyzer
VERSION = 1.0
RUN_AS_USER = user-12-31

all: $(TARGET) $(DAEMON)

$(TARGET): src/main.c
	$(CC) $(CFLAGS) -o $@ $^

$(DAEMON): src/daemon.c
	$(CC) $(CFLAGS) -o $@ $^

service/bufanalyzer.service:
	@mkdir -p service
	@echo "[Unit]" > $@
	@echo "Description=Buffer Overflow Analyzer Daemon" >> $@
	@echo "After=network.target" >> $@
	@echo "" >> $@
	@echo "[Service]" >> $@
	@echo "Type=simple" >> $@
	@echo "ExecStart=/usr/local/bin/bufanalyzer-daemon" >> $@
	@echo "Restart=always" >> $@
	@echo "RestartSec=5" >> $@
	@echo "User=$(RUN_AS_USER)" >> $@
	@echo "Group=$(RUN_AS_USER)" >> $@
	@echo "StandardOutput=syslog" >> $@
	@echo "StandardError=syslog" >> $@
	@echo "SyslogIdentifier=$(RUN_AS_USER)" >> $@
	@echo "" >> $@
	@echo "[Install]" >> $@
	@echo "WantedBy=multi-user.target" >> $@

install-deps:
	sudo dnf install -y gcc make inotify-tools systemd rpm-build rpmdevtools

install: all service/bufanalyzer.service
	sudo install -m 4755 $(TARGET) /usr/local/bin/
	sudo install -m 755 $(DAEMON) /usr/local/bin/
	sudo cp config/bufanalyzer.conf /etc/
	sudo cp service/bufanalyzer.service /etc/systemd/system/
	sudo systemctl daemon-reload

rpm: all service/bufanalyzer.service
	mkdir -p ~/rpmbuild/{BUILD,RPMS,SOURCES,SPECS,SRPMS}
	cp buffer-overflow-analyzer.template.spec ~/rpmbuild/SPECS/$(PKGNAME).spec
	tar -czf ~/rpmbuild/SOURCES/$(PKGNAME)-$(VERSION).tar.gz \
	    --exclude=.git \
	    --exclude='*.template.spec' \
	    --transform 's|^\.|$(PKGNAME)-$(VERSION)|' .
	rpmbuild -ba ~/rpmbuild/SPECS/$(PKGNAME).spec

clean:
	rm -f $(TARGET) $(DAEMON) service/bufanalyzer.service

.PHONY: all install install-deps rpm clean
