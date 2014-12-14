-include Config.mk

################ Source files ##########################################

EXE	:= $O${NAME}
SRCS	:= $(wildcard *.c)
OBJS	:= $(addprefix $O,$(SRCS:.c=.o))
DEPS	:= ${OBJS:.o=.d}
CONFS	:= Config.mk config.h
TMPO    := /tmp/${USER}/make/${NAME}
ONAME   := $(notdir $(abspath $O))

################ Compilation ###########################################

.PHONY: all clean distclean maintainer-clean

all:	${CONFS} ${EXE}

run:	${EXE}
	@${EXE}

${EXE}:	${OBJS}
	@echo "Linking $@ ..."
	@${LD} ${LDFLAGS} -o $@ $^ ${LIBS}

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
EXEI	:= ${BINDIR}/${NAME}

install:	${EXEI} ${PAMCNFI} ${SYSDCFI} ${MANI}

${EXEI}:	${EXE}
	@echo "Installing $< as $@ ..."
	@${INSTALLEXE} $< $@

uninstall:
	@if [ -f ${EXEI} ]; then\
	    echo "Removing ${EXEI} ...";\
	    rm -f ${EXEI};\
	fi
endif

################ Maintenance ###########################################

clean:
	@if [ -h ${ONAME} ]; then\
	    rm -f $O.d ${EXE} ${OBJS} ${DEPS} ${ONAME};\
	    rmdir ${TMPO};\
	fi

distclean:	clean
	@rm -f ${CONFS} config.status

maintainer-clean: distclean

$O.d:   ${TMPO}/.d
	@[ -h ${ONAME} ] || ln -sf ${TMPO} ${ONAME}
${TMPO}/.d:     Makefile
	@mkdir -p ${TMPO} && touch ${TMPO}/.d

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
