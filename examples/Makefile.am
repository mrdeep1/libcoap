# examples/Makefile.am
#
# Copyright (C)      2015 Carsten Schoenert <c.schoenert@t-online.de>
#
# This file is part of the CoAP C library libcoap. Please see README and
# COPYING for terms of use.

EXTRA_DIST = share.libcoap.examples.Makefile share.libcoap.examples.README

# just do nothing if 'BUILD_EXAMPLES' isn't defined
if BUILD_EXAMPLES

# picking up the default warning CFLAGS into AM_CFLAGS
AM_CFLAGS = -I$(top_builddir)/include -I$(top_srcdir)/include \
            $(WARNING_CFLAGS) $(DTLS_CFLAGS) -std=c99

#

if BUILD_ADD_DEFAULT_NAMES
bin_PROGRAMS = coap-client \
               coap-server \
               coap-rd \
               coap-client@LIBCOAP_DTLS_LIB_EXTENSION_NAME@ \
               coap-server@LIBCOAP_DTLS_LIB_EXTENSION_NAME@ \
               coap-rd@LIBCOAP_DTLS_LIB_EXTENSION_NAME@
else # BUILD_ADD_DEFAULT_NAMES
bin_PROGRAMS = coap-client@LIBCOAP_DTLS_LIB_EXTENSION_NAME@ \
               coap-server@LIBCOAP_DTLS_LIB_EXTENSION_NAME@ \
               coap-rd@LIBCOAP_DTLS_LIB_EXTENSION_NAME@
endif # BUILD_ADD_DEFAULT_NAMES

check_PROGRAMS = coap-etsi_iot_01 coap-tiny

if BUILD_ADD_DEFAULT_NAMES
coap_client_SOURCES = coap-client.c
coap_client_LDADD =  $(DTLS_LIBS) \
             $(top_builddir)/.libs/libcoap-$(LIBCOAP_NAME_SUFFIX).la

coap_server_SOURCES = coap-server.c
coap_server_LDADD = $(DTLS_LIBS) \
             $(top_builddir)/.libs/libcoap-$(LIBCOAP_NAME_SUFFIX).la

coap_rd_SOURCES = coap-rd.c
coap_rd_LDADD = $(DTLS_LIBS) \
             $(top_builddir)/.libs/libcoap-$(LIBCOAP_NAME_SUFFIX).la
endif # BUILD_ADD_DEFAULT_NAMES

coap_client@LIBCOAP_DTLS_LIB_EXTENSION_NAME@_SOURCES = coap-client.c
coap_client@LIBCOAP_DTLS_LIB_EXTENSION_NAME@_LDADD =  $(DTLS_LIBS) \
             $(top_builddir)/.libs/libcoap-$(LIBCOAP_NAME_SUFFIX).la

coap_server@LIBCOAP_DTLS_LIB_EXTENSION_NAME@_SOURCES = coap-server.c
coap_server@LIBCOAP_DTLS_LIB_EXTENSION_NAME@_LDADD = $(DTLS_LIBS) \
             $(top_builddir)/.libs/libcoap-$(LIBCOAP_NAME_SUFFIX).la

coap_rd@LIBCOAP_DTLS_LIB_EXTENSION_NAME@_SOURCES = coap-rd.c
coap_rd@LIBCOAP_DTLS_LIB_EXTENSION_NAME@_LDADD = $(DTLS_LIBS) \
             $(top_builddir)/.libs/libcoap-$(LIBCOAP_NAME_SUFFIX).la

coap_etsi_iot_01_SOURCES = etsi_iot_01.c
coap_etsi_iot_01_LDADD = $(DTLS_LIBS) \
             $(top_builddir)/.libs/libcoap-$(LIBCOAP_NAME_SUFFIX).la

coap_tiny_SOURCES = tiny.c
coap_tiny_LDADD = $(DTLS_LIBS) \
             $(top_builddir)/.libs/libcoap-$(LIBCOAP_NAME_SUFFIX).la

endif # BUILD_EXAMPLES

if BUILD_EXAMPLES_SOURCE
EXAMPLES_DIR = $(DESTDIR)$(datadir)/libcoap/examples
EXAMPLES_SRC = coap-client.c coap-server.c

## Install example files
install-exec-hook:
	$(MKDIR_P) $(EXAMPLES_DIR)
	(cd $(top_srcdir)/examples ; \
	$(INSTALL_DATA) $(EXAMPLES_SRC) ../LICENSE ../COPYING $(EXAMPLES_DIR) ; \
	$(INSTALL_DATA) share.libcoap.examples.Makefile $(EXAMPLES_DIR)/Makefile; \
	$(INSTALL_DATA) share.libcoap.examples.README $(EXAMPLES_DIR)/README)

uninstall-hook:
	rm -rf $(DESTDIR)$(datadir)/libcoap/examples
endif # BUILD_EXAMPLES_SOURCE
