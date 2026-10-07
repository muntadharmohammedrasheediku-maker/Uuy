#!/usr/bin/env make

# Anogs iOS Hook Framework
# Targets: arm64, arm64e
# No jailbreak, no crashes

PROJECT := anogs_hook
ARCHS := arm64 arm64e
MIN_OS := 12.0

# Tool paths
XCODE := /Applications/Xcode.app/Contents/Developer
SDK := $(shell xcrun --sdk iphoneos --show-sdk-path)
CC := $(shell xcrun -find clang)
CXX := $(shell xcrun -find clang++)
DSYMUTIL := $(XCODE)/Toolchains/XcodeDefault.xctoolchain/usr/bin/dsymutil
STRIP := $(shell xcrun -find strip)

# Compiler flags
CFLAGS = -isysroot $(SDK) \
         -miphoneos-version-min=$(MIN_OS) \
         -arch arm64 -arch arm64e \
         -fPIC -O3 -Wall \
         -fembed-bitcode \
         -fno-stack-protector \
         -fno-common \
         -fvisibility=hidden

CXXFLAGS = $(CFLAGS) -std=c++17 -stdlib=libc++ -fno-rtti
LDFLAGS = -dynamiclib -lSystem -lc++ -lObjC -fembed-bitcode
LDFLAGS_BIN = -lSystem -lc++ -fembed-bitcode

# Output
DYLIB = libAnogsHook.dylib
BIN = anogs_injector
FINDER = symbol_finder

# Source files
SRCS_HOOK = anogs_hook.cpp
SRCS_INJECT = inject_dylib.cpp
SRCS_FINDER = symbol_finder.cpp

OBJS_HOOK = $(SRCS_HOOK:.cpp=.o)
OBJS_INJECT = $(SRCS_INJECT:.cpp=.o)
OBJS_FINDER = $(SRCS_FINDER:.cpp=.o)

.PHONY: all clean install check-env

all: $(DYLIB) $(BIN) $(FINDER)

check-env:
	@which xcrun > /dev/null || (echo "Error: Xcode not found. Install Xcode Command Line Tools." && exit 1)
	@test -d "$(SDK)" || (echo "Error: iOS SDK not found at $(SDK)" && exit 1)
	@echo "[✓] Environment OK"

$(OBJS_HOOK): $(SRCS_HOOK) check-env
	$(CXX) $(CXXFLAGS) -c $< -o $@

$(OBJS_INJECT): $(SRCS_INJECT) check-env
	$(CXX) $(CXXFLAGS) -c $< -o $@

$(OBJS_FINDER): $(SRCS_FINDER) check-env
	$(CXX) $(CXXFLAGS) -c $< -o $@

$(DYLIB): $(OBJS_HOOK) check-env
	@echo "[+] Linking dylib..."
	$(CXX) $(CXXFLAGS) $(LDFLAGS) -o $@ $^
	@echo "[+] Code signing..."
	codesign -s - $@ 2>/dev/null || true
	@echo "[✓] Built: $@"
	@file $@

$(BIN): $(OBJS_INJECT) $(OBJS_HOOK) check-env
	@echo "[+] Linking injector binary..."
	$(CXX) $(CXXFLAGS) -o $@ $^ $(LDFLAGS_BIN)
	@echo "[+] Code signing..."
	codesign -s - $@ 2>/dev/null || true
	@echo "[✓] Built: $@"
	@file $@

$(FINDER): $(OBJS_FINDER) check-env
	@echo "[+] Linking symbol finder..."
	$(CXX) $(CXXFLAGS) -o $@ $^ $(LDFLAGS_BIN)
	@echo "[✓] Built: $@"
	@file $@

clean:
	rm -f $(OBJS_HOOK) $(OBJS_INJECT) $(OBJS_FINDER)
	rm -f $(DYLIB) $(BIN) $(FINDER)
	rm -f *.dSYM

install: all
	@echo "[*] Installation instructions:"
	@echo ""
	@echo "1. Current process injection:"
	@echo "   ./$(BIN) ./$(DYLIB)"
	@echo ""
	@echo "2. Remote process injection (requires task_for_pid):"
	@echo "   ./$(BIN) ./$(DYLIB) <pid>"
	@echo ""
	@echo "3. Via environment (set before app launch):"
	@echo "   export DYLD_INSERT_LIBRARIES=\$$(pwd)/$(DYLIB)"
	@echo ""

verify: all
	@echo "[*] Verifying build..."
	@echo ""
	@echo "Dylib:"
	@file $(DYLIB)
	@lipo -info $(DYLIB)
	@echo ""
	@echo "Binary:"
	@file $(BIN)
	@lipo -info $(BIN)
	@echo ""
	@echo "Symbol Finder:"
	@file $(FINDER)
	@lipo -info $(FINDER)
	@echo ""
	@echo "[✓] All components built for arm64 + arm64e"

# Debug build with symbols
debug: CFLAGS += -g -DDEBUG
debug: CXXFLAGS += -g -DDEBUG
debug: all

# Strip symbols for release
release: all
	@echo "[+] Stripping symbols..."
	$(STRIP) -x $(DYLIB)
	$(STRIP) -x $(BIN)
	$(STRIP) -x $(FINDER)
	@echo "[✓] Release build ready"

# Package for distribution
package: release
	@echo "[+] Creating package..."
	mkdir -p anogs_hook_release
	cp $(DYLIB) anogs_hook_release/
	cp $(BIN) anogs_hook_release/
	cp $(FINDER) anogs_hook_release/
	tar czf anogs_hook_release.tar.gz anogs_hook_release/
	@echo "[✓] Package: anogs_hook_release.tar.gz"
