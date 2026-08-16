CXX      = g++
CXXFLAGS = -std=c++17 -Wall -Wextra -O2
LDFLAGS  = -mwindows -lbcrypt -lcomdlg32 -lshell32 -lole32 -loleaut32

SOURCES  = main.cpp ui.cpp vault.cpp security.cpp filterio.cpp filterstate.c
TARGET   = EchoVault.exe

all: $(TARGET)

$(TARGET): $(SOURCES)
	$(CXX) $(CXXFLAGS) -o $@ $^ $(LDFLAGS)

clean:
	rm -f $(TARGET)

.PHONY: all clean
