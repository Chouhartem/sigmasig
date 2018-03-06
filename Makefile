DBGFLAGS=-ggdb3
PREFIX=/usr
INCLUDES_RELIC=$(PREFIX)/include/relic
LIB_RELIC=$(PREFIX)/lib
CFLAGS=-I $(INCLUDES_RELIC) -L $(LIB_RELIC) -W -Wall -O0
CC=gcc

all : main

main : main.c sigmasig.o
	$(CC) $(CFLAGS) -lrelic $^ -o $@

sigmasig.o : sigmasig.c
	$(CC) $(CFLAGS) -c $< -o $@
