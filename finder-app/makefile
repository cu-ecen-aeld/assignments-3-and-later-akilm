# ==========================================
#  Assignment2 Makefile
# ==========================================

# Try to detect the OS we are running on, and adjust commands as needed
TOOLCHAIN_PFX=aarch64-none-linux-gnu-
C_COMPILER=gcc

# CROSS_COMPILE=aarch64-none-linux-gnu-

COMPILER=$(C_COMPILER)

ifdef CROSS_COMPILE 
COMPILER=$(TOOLCHAIN_PFX)$(C_COMPILER)
else
COMPILER=$(C_COMPILER)
endif

CLEANUP = rm -f

CFLAGS += -Wall
CFLAGS += -Wextra

BUILD_ROOT=.

SRC_FILE=$(BUILD_ROOT)/writer.c
TGT_FILE=$(BUILD_ROOT)/writer

all: clean default

# A default target which builds the “writer” application
default: 
	$(COMPILER) $(CFLAGS) $(SRC_FILE) -o $(TGT_FILE)

# A clean target which removes the “writer” application and all .o files
clean:
	$(CLEANUP) $(TGT_FILE)

