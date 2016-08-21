if DEBUG_ENABLED
AM_CFLAGS = -Wall -Werror -g -ggdb -O2 -std=c99 -Wno-unused-variable -Wno-pointer-to-int-cast -DDEBUG $(zeromq_CFLAGS)
else
AM_CFLAGS = -Wall -Werror -Wno-unused-variable -Os -s -std=c99 -DNDEBUG $(zeromq_CFLAGS)
endif

bin_PROGRAMS = snow snow_selftest provision stresstest

generic_sources = utils.c iwcontrol.c iwhelper.c config.c

snow_SOURCES = main.c processing.c packet.c zeromq.c fnv_64.c $(generic_sources)

snow_selftest_SOURCES = snow_selftest.c processing.c packet.c zeromq.c fnv_64.c $(generic_sources)
snow_selftest_CFLAGS = $(AM_CFLAGS) -DTESTING -Wno-pointer-to-int-cast -Wno-unused-function

provision_SOURCES = provision.c $(generic_sources)

stresstest_SOURCES = stresstest.c processing.c packet.c zeromq.c fnv_64.c $(generic_sources)


TESTS = snow_selftest

