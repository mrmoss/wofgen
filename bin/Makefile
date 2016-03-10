CXX=g++
OPTS=-O
CFLAGS=$(OPTS) -Wall
SRC=../src


all: wof_ipfw wof_iptables wof_netsh wof_pf wof_ufw wof_wipfw

wof_ipfw: $(SRC)/wof.cpp $(SRC)/ipfw.cpp
	$(CXX) $(CFLAGS) $^ -o $@ -D WOF_IPFW

wof_iptables: $(SRC)/wof.cpp $(SRC)/iptables.cpp
	$(CXX) $(CFLAGS) $^ -o $@ -D WOF_IPTABLES

wof_netsh: $(SRC)/wof.cpp $(SRC)/netsh.cpp
	$(CXX) $(CFLAGS) $^ -o $@ -D WOF_NETSH

wof_pf: $(SRC)/wof.cpp $(SRC)/pf.cpp
	$(CXX) $(CFLAGS) $^ -o $@ -D WOF_PF

wof_ufw: $(SRC)/wof.cpp $(SRC)/ufw.cpp
	$(CXX) $(CFLAGS) $^ -o $@ -D WOF_UFW

wof_wipfw: $(SRC)/wof.cpp $(SRC)/wipfw.cpp
	$(CXX) $(CFLAGS) $^ -o $@ -D WOF_WIPFW

clean:
	- rm -f wof_ipfw wof_ipfw.exe
	- rm -f wof_iptables wof_iptables.exe
	- rm -f wof_netsh wof_netsh.exe
	- rm -f wof_pf wof_pf.exe
	- rm -f wof_ufw wof_ufw.exe
	- rm -f wof_wipfw wof_wipfw.exe
