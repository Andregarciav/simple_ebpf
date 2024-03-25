# DEF
makefile_path := $(abspath $(lastword $(MAKEFILE_LIST))) # This dir
SRCDIR = $(dir $makefile_path)
LIBBPF_DIR = $(SRCDIR)libbpf/src

all: libbpf kernel user

.PHONY: libbpf kernel user

libbpf:
	cd $(LIBBPF_DIR) && mkdir -p root; BUILD_STATIC_ONLY=y DESTDIR=root $(MAKE) install;

kernel:
	$(MAKE) -C src/kernel SRCDIR=$(SRCDIR)

user:
	$(MAKE) -C src/user SRCDIR=$(SRCDIR)
	
clean:
	cd libbpf/src && $(MAKE) clean;