CXX=g++
OPTS=-O
CFLAGS=$(OPTS) -Wall

all: wof_iptables wof_netsh wof_pf wof_ufw

wof_iptables: wof.cpp iptables.cpp
	$(CXX) $(CFLAGS) $^ -o $@

wof_netsh: wof.cpp netsh.cpp
	$(CXX) $(CFLAGS) $^ -o $@

wof_pf: wof.cpp pf.cpp
	$(CXX) $(CFLAGS) $^ -o $@

wof_ufw: wof.cpp ufw.cpp
	$(CXX) $(CFLAGS) $^ -o $@

clean:
	- rm -f wof_iptables wof_iptables.exe
	- rm -f wof_netsh wof_netsh.exe
	- rm -f wof_pf wof_pf.exe
	- rm -f wof_ufw wof_ufw.exe
