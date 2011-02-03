SUBDIRS = src

.PHONY: cscope clear config

cscope:
	cd $(top_srcdir) && cscope -Rb $(CPPFLAGS)

distclean-local:
	rm -f cscope.out

clear:
	find $(top_srcdir) -type f -\( -name '*.c' -o -name '*.h' -\) | xargs sed -i -e 's/[ \t]\+$$//'

