# fencedns makefile
# 2020, Simon Zolin

# set OS
ifndef $(OS)
	uname := $(shell uname)
	ifeq ($(uname),Linux)
		OS := linux
	else ifeq ($(uname),FreeBSD)
		OS := freebsd
	else ifeq ($(uname),Darwin)
		OS := apple
	else
		OS := win
	endif
endif

# set compiler
CPREFIX :=
# CPREFIX := x86_64-w64-mingw32-
COMPILER := gcc
ifeq ($(OS),freebsd)
	COMPILER := clang
endif
ifeq ($(OS),apple)
	COMPILER := clang
endif
C := $(CPREFIX)gcc -c
CXX := $(CPREFIX)g++ -c
LINKER := $(CPREFIX)gcc
ifeq ($(COMPILER),clang)
	C := clang -c
	CXX := clang++ -c
	LINKER := clang
endif
OBJCOPY := $(CPREFIX)objcopy
STRIP := $(CPREFIX)strip

# set utils
RM := rm -vf
CP := cp -vu
MKDIR := mkdir -vp
SO := so
ifeq ($(OS),win)
	SO := dll
else ifeq ($(OS),apple)
	SO := dylib
endif

ROOT := ..
FDNS_DIR := $(ROOT)/fencedns
FFBASE_DIR := $(ROOT)/ffbase
FFOS_DIR := $(ROOT)/ffos
FF_DIR := $(ROOT)/ff
HDR := $(wildcard $(FDNS_DIR)/src/*.h) \
	$(wildcard $(FDNS_DIR)/src/dns/*.h) \
	$(wildcard $(FFBASE_DIR)/ffbase/*.h) \
	$(wildcard $(FF_DIR)/FF/*.h) \
	$(wildcard $(FF_DIR)/FF/net/*.h)

OUT_DIR := $(FDNS_DIR)

FDNS_BIN := $(OUT_DIR)/fencedns
ifeq ($(OS),win)
	FDNS_BIN := $(OUT_DIR)/fencedns.exe
endif

FDNS_OBJ := \
	$(OUT_DIR)/main.o \
	$(OUT_DIR)/log.o \
	\
	$(OUT_DIR)/server.o \
	$(OUT_DIR)/upstream.o \
	$(OUT_DIR)/cache.o \
	$(OUT_DIR)/hosts.o

all: $(FDNS_BIN)

clean:
	$(RM) $(FDNS_BIN) $(FDNS_OBJ)

FDNS_CFLAGS := -I$(FDNS_DIR)/src -I$(FFBASE_DIR) -I$(FFOS_DIR) -I$(FF_DIR) \
	-Wall -Wextra -Wno-unused-parameter \
	-DFFBASE_HAVE_FFERR_STR \
	-fvisibility=hidden -fno-strict-aliasing \
	-std=gnu99
ifneq ($(DEBUG),0)
	FDNS_CFLAGS += -DFF_DEBUG -O0 -g -Werror
endif
ifeq ($(DEBUG),1)
else ifeq ($(DEBUG),2)
	FDNS_CFLAGS += -fsanitize=address
	FDNS_LDFLAGS += -fsanitize=address
else
	FDNS_CFLAGS += -O3 -g
endif

$(OUT_DIR)/%.o: $(FDNS_DIR)/src/%.c $(HDR) $(FDNS_DIR)/Makefile
	$(C) $(FDNS_CFLAGS) $< -o $@

$(OUT_DIR)/%.o: $(FDNS_DIR)/src/dns/%.c $(HDR) $(FDNS_DIR)/Makefile
	$(C) $(FDNS_CFLAGS) $< -o $@

$(FDNS_BIN): $(FDNS_OBJ)
	$(LINKER) $(FDNS_LDFLAGS) $+ \
		-o $@

# rule for separate .debug files
%.debug: %
ifeq ($(OS),apple)
	# dsymutil $< -o $@
	$(STRIP) -u -r $<

else
	$(OBJCOPY) --only-keep-debug $< $@
	$(STRIP) $<
	$(OBJCOPY) --add-gnu-debuglink=$@ $<
	touch $@
endif

strip: $(OUT_DIR)/fencedns.debug

# copy files to install directory
INST_DIR := fencedns-0
install-only:
	$(MKDIR) $(INST_DIR)
	$(CP) \
		$(OUT_DIR)/fencedns \
		$(FDNS_DIR)/fencedns.conf \
		$(FDNS_DIR)/CHANGES.txt \
		$(FDNS_DIR)/LICENSE \
		$(INST_DIR)
	$(CP) $(FDNS_DIR)/README.md $(INST_DIR)/README.txt
	chmod 0644 $(INST_DIR)/*
	chmod 0755 $(INST_DIR)/fencedns

install: all
	$(MAKE) -f $(firstword $(MAKEFILE_LIST)) install-only

# package
VER := 0.1
ARCH := amd64
PACK := tar cvjf
PACK_EXT := tar.xz
package:
	$(RM) fencedns-$(VER)-$(OS)-$(ARCH).$(PACK_EXT)
	$(PACK) fencedns-$(VER)-$(OS)-$(ARCH).$(PACK_EXT) $(INST_DIR)
