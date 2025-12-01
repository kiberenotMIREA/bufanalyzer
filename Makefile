CC      = gcc
CFLAGS  = -Wall -Wextra -O2
TARGET  = bufanalyzer
DAEMON  = bufanalyzer-daemon
PKGNAME = buffer-overflow-analyzer
VERSION = 1.0
RUN_USER ?= user-12-31

all: $(TARGET) $(DAEMON)

$(TARGET): src/main.c
	$(CC) $(CFLAGS) -o $@ $<

$(DAEMON): src/daemon.c
	$(CC) $(CFLAGS) -o $@ $<

rpm:
	@echo "Сборка RPM для пользователя: $(RUN_USER)"
	mkdir -p ~/rpmbuild/{BUILD,RPMS,SOURCES,SPECS,SRPMS}
	cp buffer-overflow-analyzer.template.spec ~/rpmbuild/SPECS/$(PKGNAME).spec
	sed -i "s|@RUN_AS_USER@|$(RUN_USER)|g" ~/rpmbuild/SPECS/$(PKGNAME).spec
	tar -czf ~/rpmbuild/SOURCES/$(PKGNAME)-$(VERSION).tar.gz \
	    --exclude=.git \
	    --exclude=*.spec \
	    --transform 's|^\.|$(PKGNAME)-$(VERSION)|' .
	rpmbuild -ba ~/rpmbuild/SPECS/$(PKGNAME).spec
	@echo "RPM собран в ~/rpmbuild/RPMS/"

clean:
	rm -f $(TARGET) $(DAEMON)

.PHONY: all rpm clean
