CXX      = g++
CXXFLAGS = -std=c++17 -Wall -Wextra -O2
LDFLAGS  = -static -static-libgcc -static-libstdc++ -mwindows -lbcrypt -lcomdlg32 -lshell32 -lole32 -loleaut32

SOURCES  = main.cpp ui.cpp vault.cpp security.cpp filterio.cpp filterstate.c
TARGET   = EchoVault.exe

all: $(TARGET)

$(TARGET): $(SOURCES) $(wildcard *.h) tests/file-safety-cases.inc
	$(CXX) $(CXXFLAGS) -o $@ $(SOURCES) $(LDFLAGS)

clean:
	rm -f $(TARGET)

.PHONY: all clean
