-include Config.mk

################ Source files ##########################################

exe	:= $O${name}
srcs	:= $(wildcard *.c)
objs	:= $(addprefix $O,$(srcs:.c=.o))
deps	:= ${objs:.o=.d}
confs	:= Config.mk config.h
oname   := $(notdir $(abspath $O))
liba_r	:= $Olib${name}.a
liba_d	:= $Olib${name}_d.a
ifdef debug
liba	:= ${liba_d}
else
liba	:= ${liba_r}
endif

################ Compilation ###########################################

.SUFFIXES:
.PHONY: all clean distclean maintainer-clean

all:	${exe}

${exe}:	${objs}
	@echo "Linking $@ ..."
	@${CC} ${ldflags} -o $@ $^ ${libs}

${liba}:	$Olib${name}.o
	@echo "Linking $@ ..."
	@rm -f $@
	@${AR} qc $@ $^
	@${RANLIB} $@

$O%.o:	%.c
	@echo "    Compiling $< ..."
	@${CC} ${cflags} -MMD -MT "$(<:.c=.s) $@" -o $@ -c $<

%.s:	%.c
	@echo "    Compiling $< to assembly ..."
	@${CC} ${cflags} -S -o $@ -c $<

################ Installation ##########################################

.PHONY:	install installdirs uninstall uninstall-man uninstall-incs
.PHONY:	uninstall-lib uninstall-pc uninstall-svc

ifdef bindir
exed	:= ${DESTDIR}${bindir}
exei	:= ${exed}/$(notdir ${exe})

${exed}:
	@echo "Creating $@ ..."
	@${INSTALL} -d $@
${exei}:	${exe} | ${exed}
	@echo "Installing $@ ..."
	@${INSTALL_PROGRAM} $< $@

installdirs:	${exed}
install:	${exei}
uninstall:
	@if [ -f ${exei} ]; then\
	    echo "Removing ${exei} ...";\
	    rm -f ${exei};\
	fi
endif
ifdef includedir
incsd	:= ${DESTDIR}${includedir}
incsi	:= ${incsd}/lib${name}.h

${incsd}:
	@echo "Creating $@ ..."
	@${INSTALL} -d $@
${incsi}:	lib${name}.h | ${incsd}
	@echo "Installing $@ ..."
	@${INSTALL_DATA} $< $@

install:	${incsi}
installdirs:	${incsd}
uninstall:	uninstall-incs
uninstall-incs:
	@if [ -f ${incsi} ]; then\
	    echo "Removing headers ...";\
	    rm -f ${incsi};\
	fi
endif
ifdef libdir
libad	:= ${DESTDIR}${libdir}
libai	:= ${libad}/$(notdir ${liba})
libai_r	:= ${libad}/$(notdir ${liba_r})
libai_d	:= ${libad}/$(notdir ${liba_d})

${libad}:
	@echo "Creating $@ ..."
	@${INSTALL} -d $@
${libai}:	${liba} | ${libad}
	@echo "Installing $@ ..."
	@${INSTALL_DATA} $< $@

install:	${libai}
installdirs:	${libad}
uninstall:	uninstall-lib
uninstall-lib:
	@if [ -f ${libai_r} -o -f ${libai_d} ]; then\
	    echo "Removing ${libai} ...";\
	    rm -f ${libai_r} ${libai_d};\
	fi
endif
ifdef pkgconfigdir
pcd	:= ${DESTDIR}${pkgconfigdir}
pci	:= ${pcd}/${name}.pc

${pcd}:
	@echo "Creating $@ ..."
	@${INSTALL} -d $@
${pci}:	${name}.pc | ${pcd}
	@echo "Installing $@ ..."
	@${INSTALL_DATA} $< $@

install:	${pci}
installdirs:	${pcd}
uninstall:	uninstall-pc
uninstall-pc:
	@if [ -f ${pci} ]; then\
	    echo "Removing ${pci} ...";\
	    rm -f ${pci};\
	fi
endif
ifdef sysddir
svcd	:= ${DESTDIR}${sysddir}
svci	:= ${svcd}/${name}.service
socki	:= ${svcd}/${name}.socket

${svcd}:
	@echo "Creating $@ ..."
	@${INSTALL} -d $@
${svci}:	$(notdir ${svci}) | ${svcd}
	@echo "Installing $@ ..."
	@${INSTALL_DATA} $< $@
${socki}:	$(notdir ${socki}) | ${svcd}
	@echo "Installing $@ ..."
	@${INSTALL_DATA} $< $@

installdirs:	${svcd}
install:	${svci} ${socki}
uninstall:	uninstall-svc
uninstall-svc:
	@if [ -f ${svci} -o -f ${socki} ]; then\
	    echo "Removing ${svci} ...";\
	    rm -f ${svci} ${socki};\
	fi
endif

################ Maintenance ###########################################

clean:
	@if [ -d ${builddir} ]; then\
	    rm -f ${exe} ${liba_r} ${liba_d} ${objs} ${deps} $O.d;\
	    rmdir ${builddir};\
	fi

distclean:	clean
	@rm -f config.status ${confs} ${oname}

maintainer-clean: distclean

${builddir}/.d:
	@[ -d $(dir $@) ] || mkdir -p $(dir $@)
	@touch $@
$O.d:	| ${builddir}/.d
	@[ -h ${oname} ] || ln -sf ${builddir} ${oname}
$O%/.d:	| $O.d
	@[ -d $(dir $@) ] || mkdir $(dir $@)
	@touch $@

${objs}:	Makefile ${confs} | $O.d
config.h:	config.h.in | Config.mk
Config.mk:	Config.mk.in
${confs}:	configure
	@if [ -x config.status ]; then echo "Reconfiguring ...";\
	    ./config.status;\
	else echo "Running configure ...";\
	    ./configure;\
	fi

include test/Module.mk
-include ${deps}
