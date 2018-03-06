DBGFLAGS=-ggdb3
INCLUDES_RELIC=/usr/include/relic
LIB_RELIC=/usr/lib
CFLAGS=-I $(INCLUDES_RELIC) -L $(LIB_RELIC) -W -Wall -O0
CC=gcc

all : main

main : main.c sigmasig.o
	$(CC) $(CFLAGS) -lrelic $^ -o $@

sigmasig.o : sigmasig.c
	$(CC) $(CFLAGS) -c $< -o $@
