CXX := c++
CXXFLAGS := -std=c++17 -Wall

# Homebrew installs Crypto++ outside the default search path on macOS
BREW_PREFIX := $(shell brew --prefix 2>/dev/null)
ifneq ($(BREW_PREFIX),)
CPPFLAGS += -I$(BREW_PREFIX)/include
LDFLAGS += -L$(BREW_PREFIX)/lib
endif
LDLIBS := -lcryptopp

CORE := totp.cpp verifier.cpp
HEADERS := totp.h verifier.h

TARGETS := test_totp experiments

ifneq ($(wildcard main.cpp),)
TARGETS += totp_demo
endif

# Treat these as actions, not files
.PHONY: all test results clean

all: $(TARGETS)

test_totp: test_totp.cpp $(CORE) $(HEADERS) Makefile
	$(CXX) $(CPPFLAGS) $(CXXFLAGS) test_totp.cpp $(CORE) $(LDFLAGS) $(LDLIBS) -o $@

experiments: experiments.cpp $(CORE) $(HEADERS) Makefile
	$(CXX) $(CPPFLAGS) $(CXXFLAGS) experiments.cpp $(CORE) $(LDFLAGS) $(LDLIBS) -o $@

totp_demo: main.cpp $(CORE) $(HEADERS) Makefile
	$(CXX) $(CPPFLAGS) $(CXXFLAGS) main.cpp $(CORE) $(LDFLAGS) $(LDLIBS) -o $@

# Run the RFC 6238 vectors and verifier checks
test: test_totp
	./test_totp

# Regenerate results.csv from the window/clock-offset experiment
results: experiments
	./experiments results.csv

clean:
	$(RM) test_totp experiments totp_demo
