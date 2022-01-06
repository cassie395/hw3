SHELL = /bin/bash
CC = gcc
CFLAGS = -lpcap -lbsd
SRC = $(wildcard *.c)
EXE = $(patsubst %.c, %, $(SRC))

all: ${EXE}

%:	%.c
	${CC} -g  $@.c -o $@ ${CFLAGS}

clean:
	rm ${EXE}
