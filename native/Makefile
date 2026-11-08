CXX ?= c++
PKG_CONFIG ?= pkg-config
CPPFLAGS += $(shell $(PKG_CONFIG) --cflags libndpi libmnl libnetfilter_queue json-c)
CXXFLAGS ?= -O2 -g
CXXFLAGS += -std=c++17 -Wall -Wextra -Wpedantic -Werror -fstack-protector-strong -D_FORTIFY_SOURCE=3 -fPIE
LDLIBS += $(shell $(PKG_CONFIG) --libs libndpi libmnl libnetfilter_queue json-c)
LDFLAGS += -pie -Wl,-z,relro,-z,now,-z,noexecstack -Wl,--disable-new-dtags,-rpath,'$$ORIGIN/../lib'

.PHONY: all check clean
all: build/omr-app-supervisor
build/omr-app-supervisor: src/omr_app.cpp
	mkdir -p build
	$(CXX) $(CPPFLAGS) $(CXXFLAGS) $< -o $@ $(LDFLAGS) $(LDLIBS)
check: all
	python3 tests/test_native.py ./build/omr-app-supervisor
clean:
	rm -rf build

# Functional checks on an ARM developer host running x86 via Rosetta. This target
# is never packaged: capabilities marks it instrumented, and build_bundle rejects it.
build/omr-app-supervisor-emulation: src/omr_app.cpp
	mkdir -p build
	$(CXX) $(CPPFLAGS) $(CXXFLAGS) -DOMR_EMULATION_TEST $< -o $@ $(LDFLAGS) $(LDLIBS)
.PHONY: check-emulated
check-emulated: build/omr-app-supervisor-emulation
	python3 tests/test_native.py ./build/omr-app-supervisor-emulation
