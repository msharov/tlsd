################ Source files ##########################################

test/SRCS	:= $(wildcard test/*.c)
test/TSRCS	:= $(wildcard test/?????.c)
test/ASRCS	:= $(filter-out ${test/TSRCS}, ${test/SRCS})
test/TESTS	:= $(addprefix $O,$(test/TSRCS:.c=))
test/TOBJS	:= $(addprefix $O,$(test/TSRCS:.c=.o))
test/AOBJS	:= $(addprefix $O,$(test/ASRCS:.c=.o))
test/OBJS	:= ${test/TOBJS} ${test/AOBJS}
test/DEPS	:= ${test/TOBJS:.o=.d} ${test/AOBJS:.o=.d}
test/OUTS	:= ${test/TOBJS:.o=.out}
ifdef DEBUG
    test/LIBS	:= -lcasycom_d
else
    test/LIBS	:= -lcasycom
endif

################ Compilation ###########################################

.PHONY:	test/all test/run test/clean test/check

test/all:	${test/TESTS}

# The correct output of a test is stored in testXX.std
# When the test runs, its output is compared to .std
#
check:		test/check
test/check:	${test/TESTS} ${EXE}
	@for i in ${test/TESTS}; do \
	    TEST="test/$$(basename $$i)";\
	    echo "Running $$TEST";\
	    PATH="$O" $$i &> $$i.out;\
	    diff $$TEST.std $$i.out && rm -f $$i.out;\
	done

${test/TESTS}: $Otest/%: $Otest/%.o ${test/AOBJS} ${LIB}
	@echo "Linking $@ ..."
	@${CC} ${LDFLAGS} -o $@ $^ ${test/LIBS}

################ Maintenance ###########################################

clean:	test/clean
test/clean:
	@if [ -d $O/test ]; then\
	    rm -f ${test/TESTS} ${test/OBJS} ${test/DEPS} ${test/OUTS};\
	    rmdir ${BUILDDIR}/test;\
	fi

${test/OBJS}: Makefile test/Module.mk ${CONFS} $O.d

-include ${test/DEPS}
