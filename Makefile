CXX=g++
OPTS=-O
CFLAGS=$(OPTS) -Wall

all: wof_iptables wof_netsh

wof_iptables: wof.cpp iptables.cpp
	$(CXX) $(CFLAGS) $^ -o $@

wof_netsh: wof.cpp netsh.cpp
	$(CXX) $(CFLAGS) $^ -o $@

clean:
	- rm -f wof_iptables wof_iptables.exe
	- rm -f wof_netsh wof_netsh.exe