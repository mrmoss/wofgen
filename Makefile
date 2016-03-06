CXX=g++
OPTS=-O
CFLAGS=$(OPTS) -Wall

all: wof_iptables wof_netsh wof_pf wof_ufw wof_ipfw

wof_iptables: src/wof.cpp src/iptables.cpp
	mkdir -p bin
	$(CXX) $(CFLAGS) $^ -o bin/$@

wof_netsh: src/wof.cpp src/netsh.cpp
	mkdir -p bin
	$(CXX) $(CFLAGS) $^ -o bin/$@

wof_pf: src/wof.cpp src/pf.cpp
	mkdir -p bin
	$(CXX) $(CFLAGS) $^ -o bin/$@

wof_ufw: src/wof.cpp src/ufw.cpp
	mkdir -p bin
	$(CXX) $(CFLAGS) $^ -o bin/$@

wof_ipfw: src/wof.cpp src/ipfw.cpp
	mkdir -p bin
	$(CXX) $(CFLAGS) $^ -o bin/$@

clean:
	- rm -f bin/wof_iptables bin/wof_iptables.exe
	- rm -f bin/wof_netsh bin/wof_netsh.exe
	- rm -f bin/wof_pf bin/wof_pf.exe
	- rm -f bin/wof_ufw bin/wof_ufw.exe
	- rm -f bin/wof_ipfw bin/wof_ipfw.exe
