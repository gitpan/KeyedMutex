PROGRAMS=keyedmutexd
SOURCES=keyedmutexd.c
MANS=keyedmutexd.1
CC=cc
CFLAGS=-g -Wall
HELP2MAN=help2man

all: $(PROGRAMS) $(MANS)

$(PROGRAMS): $(SOURCES)
	$(CC) $(CFLAGS) -o $@ $(SOURCES)

$(MANS): $(SOURCES)
	-$(HELP2MAN) -N --output $@ ./$(PROGRAMS)

clean:
	-rm -f $(PROGRAMS)

veryclean: clean
	-rm -f $(MANS)
