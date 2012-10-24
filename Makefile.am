INCLUDES = -I$(top_srcdir)

checkapi:
	$(PERL) $(top_srcdir)/tools/checkAPIs.pl -g abort -g termoutput \
	packet-ant.c

PLUGIN_NAME = ant

# the codec sources 
DISSECTOR_SRC = \
	packet-ant.c

DISSECTOR_INCLUDES = \
	packet-ant.h

DISSECTOR_SUPPORT_SRC =

plugindir = @plugindir@

plugin_LTLIBRARIES = ant.la
ant_la_SOURCES = plugin.c packet-ant.c moduleinfo.h
ant_la_LDFLAGS = -module -avoid-version
ant_la_LIBADD = @PLUGIN_LIBS@

LIBS =

CLEANFILES = \
	ant \
	*~

MAINTAINERCLEANFILES = \
	Makefile.in	\
	plugin.c


plugin.c: $(DISSECTOR_SRC) $(top_srcdir)/tools/make-dissector-reg \
    $(top_srcdir)/tools/make-dissector-reg.py
	@if test -n "$(PYTHON)"; then \
		echo Making plugin.c with python ; \
		$(PYTHON) $(top_srcdir)/tools/make-dissector-reg.py $(srcdir) \
		    plugin $(DISSECTOR_SRC) ; \
	else \
		echo Making plugin.c with shell script ; \
		$(top_srcdir)/tools/make-dissector-reg $(srcdir) \
		    $(plugin_src) plugin $(DISSECTOR_SRC) ; \
	fi

