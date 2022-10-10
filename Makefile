# Compiler
CC := cl

# linker
LK := link

# Compiler Flags
CFLAGS :=  /nologo /Ox /MT /W0 /GS- /DNDEBUG

# Linker Flags
LFLAGS := /SUBSYSTEM:CONSOLE /MACHINE:x64 

# Source Dir
SRCDIR := src

all: rewrite main

rewrite: $(SRCDIR)/rewrite.c $(SRCDIR)/rewrite.h
	$(CC) $(CFLAGS) /c /I$(SRCDIR) $(SRCDIR)/rewrite.c 

main: rewrite.obj
	$(CC) $(CFLAGS) /c /I$(SRCDIR) $(SRCDIR)/main.c
	$(LK) rewrite.obj main.obj /OUT:poc.exe
