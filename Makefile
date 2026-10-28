CXXFLAGS ?= -O2 -g
CFLAGS ?= -O2 -g
CPPFLAGS += -Ivendor/univalue/include $(shell pkg-config --cflags libcurl 2>/dev/null)
LDLIBS += $(shell pkg-config --libs libcurl 2>/dev/null || echo -lcurl)
UNIVALUE = $(wildcard vendor/univalue/lib/*.cpp)
OBJECTS = main.o config.o rpc.o dns.o $(UNIVALUE:.cpp=.o)

.PHONY: all clean test
all: dnsseed

dnsseed: $(OBJECTS)
	$(CXX) -pthread $(LDFLAGS) -o $@ $(OBJECTS) $(LDLIBS)

%.o: %.cpp
	$(CXX) $(CPPFLAGS) $(CXXFLAGS) -std=c++17 -pthread -Wall -Wextra -MMD -MP -c -o $@ $<

dns.o: dns.c dns.h
	$(CC) $(CPPFLAGS) $(CFLAGS) -std=c99 -pthread -Wall -Wextra -MMD -MP -c -o $@ $<

test: dnsseed
	python3 -m unittest discover -s tests -v

clean:
	rm -f dnsseed $(OBJECTS) $(OBJECTS:.o=.d)

-include $(OBJECTS:.o=.d)
