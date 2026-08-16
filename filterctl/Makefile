CXX      = g++
CXXFLAGS = -std=c++17 -O2 -Wall -Wextra
TARGET   = filterctl.exe

all: $(TARGET)

$(TARGET): filterctl.c ../shared/evfilter.h ../filterstate.h ../filterstate.c
	$(CXX) $(CXXFLAGS) -o $@ filterctl.c ../filterstate.c

clean:
	rm -f $(TARGET)

.PHONY: all clean
