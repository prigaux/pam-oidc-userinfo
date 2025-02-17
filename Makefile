CFLAGS=-Wall -fPIC -std=gnu99
LIBDIR=/lib

ifeq ($(shell if uname -o | grep -q "GNU/Linux" ; then echo true; else echo false; fi),true)
    ifeq ($(shell if [ -e /etc/debian_version ] ; then echo true; else echo false; fi),true)
	DEB_HOST_MULTIARCH ?= $(shell dpkg -L libc6 | sed -nr 's|^/etc/ld\.so\.conf\.d/(.*)\.conf$$|\1|p')
	ifneq ($(DEB_HOST_MULTIARCH),)
	    LIBDIR=/lib/$(DEB_HOST_MULTIARCH)
	endif
    else ifeq ($(shell uname -m),x86_64)  # redhat?
	LIBDIR=/lib64
    endif
endif

PAM_DIR=$(LIBDIR)/security

all: pam_oidc_userinfo.so

pam_oidc_userinfo.so: pam_oidc_userinfo.o
	$(CC) -shared $^ -lcurl -o $@

install: pam_oidc_userinfo.so
	install -d $(DESTDIR)$(PAM_DIR)
	install -m 644 $< $(DESTDIR)$(PAM_DIR)

clean:
	rm -f *.o *.so
