CXX=g++
OPTS=-O
CFLAGS=$(OPTS) -Wall

all: wof

wof: wof.cpp
	$(CXX) $(CFLAGS) $^ -o $@
clean:
	- rm -f wof wof.exe
