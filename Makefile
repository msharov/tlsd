-include Config.mk

################ Source files ##########################################

EXE	:= $O${NAME}
SRCS	:= $(wildcard *.c)
OBJS	:= $(addprefix $O,$(SRCS:.c=.o))
DEPS	:= ${OBJS:.o=.d}
LIB	:= $Olib${NAME}.a
LIBOBJ	:= $Olib${NAME}.o
CONFS	:= Config.mk config.h
ONAME   := $(notdir $(abspath $O))

################ Compilation ###########################################

.PHONY: all clean distclean maintainer-clean

all:	${CONFS} ${EXE} ${LIB}

run:	${EXE}
	@${EXE}

${EXE}:	${OBJS}
	@echo "Linking $@ ..."
	@${LD} ${LDFLAGS} -o $@ $^ ${LIBS}

${LIB}:	${LIBOBJ}
	@echo "Linking $@ ..."
	@rm -f $@
	@${AR} qc $@ $^
	@${RANLIB} $@

$O%.o:	%.c
	@echo "    Compiling $< ..."
	@[ -d $(dir $@) ] || mkdir -p $(dir $@)
	@${CC} ${CFLAGS} -MMD -MT "$(<:.c=.s) $@" -o $@ -c $<

%.s:	%.c
	@echo "    Compiling $< to assembly ..."
	@${CC} ${CFLAGS} -S -o $@ -c $<

################ Installation ##########################################

.PHONY:	install uninstall

ifdef BINDIR
EXEI	:= ${BINDIR}/$(notdir ${EXE})
LIBI	:= ${LIBDIR}/$(notdir ${LIB})
LIBH	:= ${INCDIR}/lib${NAME}.h
SYSDS	:= ${SYSDDIR}/${NAME}.service ${SYSDDIR}/${NAME}.socket

install:	${EXEI} ${LIBI} ${LIBH} ${SYSDS}

${EXEI}:	${EXE}
	@echo "Installing $< as $@ ..."
	@${INSTALLEXE} $< $@

${LIBI}:	${LIB}
	@echo "Installing $< as $@ ..."
	@${INSTALLDATA} $< $@

${LIBH}:	lib${NAME}.h
	@echo "Installing $< as $@ ..."
	@${INSTALLDATA} $< $@

${SYSDDIR}/${NAME}.service:	doc/${NAME}.service
	@echo "Installing $< as $@ ..."
	@${INSTALLDATA} $< $@

${SYSDDIR}/${NAME}.socket:	doc/${NAME}.socket
	@echo "Installing $< as $@ ..."
	@${INSTALLDATA} $< $@

uninstall:
	@echo "Uninstalling ..."
	@rm -f ${EXEI} ${LIBI} ${LIBH} ${SYSDS}
endif

################ Maintenance ###########################################

include test/Module.mk

clean:
	@if [ -h ${ONAME} ]; then\
	    rm -f $O.d ${EXE} ${LIB} ${OBJS} ${DEPS} ${ONAME};\
	    ${RMPATH} ${BUILDDIR};\
	fi

distclean:	clean
	@rm -f ${CONFS} config.status

maintainer-clean: distclean

$O.d:   ${BUILDDIR}/.d
	@[ -h ${ONAME} ] || ln -sf ${BUILDDIR} ${ONAME}
${BUILDDIR}/.d:     Makefile
	@mkdir -p ${BUILDDIR} && touch ${BUILDDIR}/.d

Config.mk:	Config.mk.in
config.h:	config.h.in
${OBJS}:	Makefile ${CONFS} $O.d
${CONFS}:	configure
	@if [ -x config.status ]; then echo "Reconfiguring ...";\
	    ./config.status;\
	else echo "Running configure ...";\
	    ./configure;\
	fi

-include ${DEPS}
