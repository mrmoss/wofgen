CXX=g++
OPTS=-O
CFLAGS=$(OPTS) -Wall

all: wof_iptables

wof_iptables: wof.cpp iptables.cpp
	$(CXX) $(CFLAGS) $^ -o $@
clean:
	- rm -f wof_iptables wof_iptables.exe
