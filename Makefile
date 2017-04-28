# Modified version of:
# https://github.com/zerotier/ZeroTierOne/blob/master/make-linux.mk

# Automagically pick clang or gcc, with preference for clang
# This is only done if we have not overridden these with an environment or CLI variable
ifeq ($(origin CC),default)
	CC=$(shell if [ -e /usr/bin/clang ]; then echo clang; else echo gcc; fi)
endif
ifeq ($(origin CXX),default)
	CXX=$(shell if [ -e /usr/bin/clang++ ]; then echo clang++; else echo g++; fi)
endif

INCLUDES?=
DEFS?=-D_FORTIFY_SOURCE=2
LDLIBS?=
DESTDIR?=

include ZeroTierOne/objects.mk

OBJS:=$(addprefix ZeroTierOne/,$(OBJS))
OBJS:=$(filter ZeroTierOne/node/%,$(OBJS))

DEFS+=-DZT_TRACE
override CFLAGS+=-Wall -fPIE -g -O -pthread $(INCLUDES) $(DEFS)
override CXXFLAGS+=-Wall -fPIE -g -O -std=c++11 -pthread $(INCLUDES) $(DEFS)
override LDFLAGS+=-fPIE
STRIP?=echo
# The following line enables optimization for the crypto code, since
# C25519 in particular is almost UNUSABLE in -O0 even on a 3ghz box!
ZeroTierOne/node/Salsa20.o ZeroTierOne/node/SHA512.o ZeroTierOne/node/C25519.o ZeroTierOne/node/Poly1305.o: CFLAGS = -Wall -O2 -g -pthread $(INCLUDES) $(DEFS)


# Determine system build architecture from compiler target
CC_MACH=$(shell $(CC) -dumpmachine | cut -d '-' -f 1)
ZT_ARCHITECTURE=999
ifeq ($(CC_MACH),x86_64)
        ZT_ARCHITECTURE=2
	ZT_USE_X64_ASM_SALSA2012=1
endif
ifeq ($(CC_MACH),amd64)
        ZT_ARCHITECTURE=2
	ZT_USE_X64_ASM_SALSA2012=1
endif
ifeq ($(CC_MACH),i386)
        ZT_ARCHITECTURE=1
endif
ifeq ($(CC_MACH),i686)
        ZT_ARCHITECTURE=1
endif
ifeq ($(CC_MACH),arm)
        ZT_ARCHITECTURE=3
	override DEFS+=-DZT_NO_TYPE_PUNNING
	ZT_USE_ARM32_NEON_ASM_SALSA2012=1
endif
ifeq ($(CC_MACH),armel)
        ZT_ARCHITECTURE=3
	override DEFS+=-DZT_NO_TYPE_PUNNING
	ZT_USE_ARM32_NEON_ASM_SALSA2012=1
endif
ifeq ($(CC_MACH),armhf)
        ZT_ARCHITECTURE=3
	override DEFS+=-DZT_NO_TYPE_PUNNING
	ZT_USE_ARM32_NEON_ASM_SALSA2012=1
endif
ifeq ($(CC_MACH),armv6)
        ZT_ARCHITECTURE=3
	override DEFS+=-DZT_NO_TYPE_PUNNING
	ZT_USE_ARM32_NEON_ASM_SALSA2012=1
endif
ifeq ($(CC_MACH),armv6zk)
        ZT_ARCHITECTURE=3
	override DEFS+=-DZT_NO_TYPE_PUNNING
	ZT_USE_ARM32_NEON_ASM_SALSA2012=1
endif
ifeq ($(CC_MACH),armv6kz)
        ZT_ARCHITECTURE=3
	override DEFS+=-DZT_NO_TYPE_PUNNING
	ZT_USE_ARM32_NEON_ASM_SALSA2012=1
endif
ifeq ($(CC_MACH),armv7)
        ZT_ARCHITECTURE=3
	override DEFS+=-DZT_NO_TYPE_PUNNING
	ZT_USE_ARM32_NEON_ASM_SALSA2012=1
endif
ifeq ($(CC_MACH),arm64)
        ZT_ARCHITECTURE=4
	override DEFS+=-DZT_NO_TYPE_PUNNING
endif
ifeq ($(CC_MACH),aarch64)
        ZT_ARCHITECTURE=4
	override DEFS+=-DZT_NO_TYPE_PUNNING
endif
ifeq ($(CC_MACH),mipsel)
        ZT_ARCHITECTURE=5
	override DEFS+=-DZT_NO_TYPE_PUNNING
endif
ifeq ($(CC_MACH),mips)
        ZT_ARCHITECTURE=5
	override DEFS+=-DZT_NO_TYPE_PUNNING
endif
ifeq ($(CC_MACH),mips64)
        ZT_ARCHITECTURE=6
	override DEFS+=-DZT_NO_TYPE_PUNNING
endif
ifeq ($(CC_MACH),mips64el)
        ZT_ARCHITECTURE=6
	override DEFS+=-DZT_NO_TYPE_PUNNING
endif

# Fail if system architecture could not be determined
ifeq ($(ZT_ARCHITECTURE),999)
ERR=$(error FATAL: architecture could not be determined from $(CC) -dumpmachine: $CC_MACH)
.PHONY: err
err: ; $(ERR)
endif

# Disable software updates by default on Linux since that is normally done with package management
override DEFS+=-DZT_BUILD_PLATFORM=1 -DZT_BUILD_ARCHITECTURE=$(ZT_ARCHITECTURE) -DZT_SOFTWARE_UPDATE_DEFAULT="\"disable\""

# Build faster crypto on some targets
ifeq ($(ZT_USE_X64_ASM_SALSA2012),1)
	override DEFS+=-DZT_USE_X64_ASM_SALSA2012
	override OBJS+=ZeroTierOne/ext/x64-salsa2012-asm/salsa2012.o
endif
ifeq ($(ZT_USE_ARM32_NEON_ASM_SALSA2012),1)
	override DEFS+=-DZT_USE_ARM32_NEON_ASM_SALSA2012
	override OBJS+=ZeroTierOne/ext/arm32-neon-salsa2012-asm/salsa2012.o
endif


override LDFLAGS+=-static
ifeq ($(ZT_ARCHITECTURE),3)
	ifeq ($(ZT_ARM_SOFTFLOAT),1)
		override CFLAGS+=-march=armv5te -mfloat-abi=soft -msoft-float -mno-unaligned-access -marm
		override CXXFLAGS+=-march=armv5te -mfloat-abi=soft -msoft-float -mno-unaligned-access -marm
	else
		override CFLAGS+=-march=armv6kz -mcpu=arm1176jzf-s -mfpu=vfp -mfloat-abi=hard -mno-unaligned-access -marm
		override CXXFLAGS+=-march=armv6kz -mcpu=arm1176jzf-s -mfpu=vfp -mfloat-abi=hard -mno-unaligned-access -marm
	endif
endif



all:	lib

lib:	$(OBJS)
	#$(CXX) -c $(CXXFLAGS) $(LDFLAGS) -o libzerotier.o $(OBJS) $(LDLIBS)
	ar -rcs libzerotier.a $(OBJS)

clean: FORCE
	rm -rf *.so *.o node/*.o controller/*.o osdep/*.o service/*.o ext/http-parser/*.o ext/miniupnpc/*.o ext/libnatpmp/*.o $(OBJS) zerotier-one zerotier-idtool zerotier-cli zerotier-selftest build-* ZeroTierOneInstaller-* *.deb *.rpm .depend debian/files debian/zerotier-one*.debhelper debian/zerotier-one.substvars debian/*.log debian/zerotier-one doc/node_modules
