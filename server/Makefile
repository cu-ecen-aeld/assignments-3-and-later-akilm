
INCLUDE_DIRS =
LIB_DIRS =

ifeq ($(CC),)
	CC = $(CROSS_COMPILE)gcc
endif
#CC = gcc
#CC = /usr/bin/gcc-11

CDEFS=

ifeq ($(CFLAGS),)
	CFLAGS= -O0 $(INCLUDE_DIRS) $(CDEFS)
endif

LIBS=

ifeq ($(LDFLAGS),)
	LDFLAGS = -g -Wall -Werror -pthread
endif

DAEMON_FLAGS =

OBJECTS =	aesdsocket.o


LIBS = -lm
INCLUDES = -I.

TARGET= aesdsocket

HFILES=
CFILES= aesdsocket.c




SRCS= ${HFILES} ${CFILES}
OBJS= ${CFILES:.c=.o}

all:	${TARGET}

aesdsocket: aesdsocket.o
	$(CC) $(LDFLAGS) $(LIBS) $(CFLAGS) ${DAEMON_FLAGS} $^ -o $@

clean :
	echo *.o *.i *.s *~ \#*# core .#* .new* aesdsocket
	rm -f *.o *.i *.s *~ ${TARGET} \#*# core .#* .new* aesdsocket

depend:

.c.o:
	$(CC) $(LDFLAGS) $(CFLAGS) ${DAEMON_FLAGS} $(INCLUDES) -c $< -o $@
#$(CC) $(CFLAGS) $^ -o $@ $(INCLUDES) $(LDFLAGS)

