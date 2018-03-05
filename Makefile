CFLAGS=-I /usr/include/relic -W -Wall
DBGFLAGS=-ggdb3
CC=gcc

all : main

main : main.c sigmasig.o
	$(CC) $(CFLAGS) -lrelic $^ -o $@

sigmasig.o : sigmasig.c
	$(CC) $(CFLAGS) -c $< -o $@
