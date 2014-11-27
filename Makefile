#
# Makefile for Custom router
#


CC=gcc
CFLAGS=-g #-Wall -Werror
LFLAGS=-lpcap -lpthread
EXE=router

all: $(EXE)

clean:
	rm -f $(EXE)

my402list:
	$(CC) $(CFLAGS) my402list.c -o my402list $(LFLAGS)

router:
	$(CC) $(CFLAGS) router.c my402list.c -o router $(LFLAGS)
