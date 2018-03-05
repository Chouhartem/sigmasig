DBGFLAGS=-ggdb3
CFLAGS=-I /usr/include/relic -W -Wall -O0
CC=gcc

all : main

main : main.c sigmasig.o
	$(CC) $(CFLAGS) -lrelic $^ -o $@

sigmasig.o : sigmasig.c
	$(CC) $(CFLAGS) -c $< -o $@
