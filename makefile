SHELL := /bin/bash
#
# OUTPUT PATHS
#
PREFIX          ?= /usr/local
QBIN_DIR        ?= $(PREFIX)/bin
QCONFIG_DIR     ?= /etc/quark
QLOG_DIR        ?= /var/log/quark

#
# BUILD PATHS
#
QKERNEL_BUILD   = build
QTARGET_RELEASE = target/release
QTARGET_DEBUG   = target/debug
QKERNEL_DEBUG   = $(QKERNEL_BUILD)/qkernel_d.bin
QKERNEL_RELEASE = $(QKERNEL_BUILD)/qkernel.bin
QUARK_DEBUG     = $(QTARGET_DEBUG)/quark
QUARK_RELEASE   = $(QTARGET_RELEASE)/quark
VDSO            = vdso/vdso.so
TDSHIM          = td-shim/shim.bin

ARCH := ${shell uname -m}
RUST_TOOLCHAIN  = nightly-2023-12-11-$(ARCH)-unknown-linux-gnu
BTYPE		?= debug
X86CPU_TYPE	:= $(shell lscpu | awk -F: '/Vendor ID/ {gsub(/^[ \t]+/, "", $$2); print $$2}')



.PHONY: all release debug clean install qvisor_release qvisor_debug cuda_make cuda_all cc_x86_debug cc_x86_release cleanall

all:: release debug

cuda_all:: cuda_release cuda_debug

tdx_all:: tdx_release tdx_debug

snp_all:: snp_release snp_debug

release:: qvisor_release qkernel_release $(VDSO)

debug:: qvisor_debug qkernel_debug $(VDSO)

qvisor_release:
	make -C ./qvisor TOOLCHAIN=$(RUST_TOOLCHAIN) release

qkernel_release:
	make -C ./qkernel TOOLCHAIN=$(RUST_TOOLCHAIN) release

qvisor_debug:
	make -C ./qvisor TOOLCHAIN=$(RUST_TOOLCHAIN) debug

qkernel_debug:
	make -C ./qkernel TOOLCHAIN=$(RUST_TOOLCHAIN) debug

$(VDSO):
	make -C ./vdso

clean:
	rm -rf target build
	make -C ./vdso clean

cleanall: clean
	make -C ./qservice clean
	make -C ./qserverless clean
	make -C ./rdma_cli clean
	make -C ./rdma_srv clean

docker:
	sudo systemctl restart docker

cuda_release:: qvisor_cuda_release qkernel_release cuda_make

cuda_debug:: qvisor_cuda_debug qkernel_debug cuda_make

qvisor_cuda_release:
	make -C ./qvisor TOOLCHAIN=$(RUST_TOOLCHAIN) cuda_release

qvisor_cuda_debug:
	make -C ./qvisor TOOLCHAIN=$(RUST_TOOLCHAIN) cuda_debug

cc_x86_debug:
ifeq ($(ARCH),x86_64)
	$(MAKE) cc_x86 BTYPE=debug
else
	$(error Wrong architecture - requires x86_64)
endif


cc_x86_release:
ifeq ($(ARCH),x86_64)
	$(MAKE) cc_x86 BTYPE=release
else
	$(error Wrong architecture - requires x86_64)
endif

cc_x86:
ifeq ($(X86CPU_TYPE),GenuineIntel)
	$(MAKE) tdx_$(BTYPE)
else
	$(MAKE) snp_$(BTYPE)
endif

tdx_release:: qvisor_tdx_release qkernel_tdx_release $(VDSO) tdx_make

tdx_debug:: qvisor_tdx_debug qkernel_tdx_debug $(VDSO) tdx_make

qkernel_tdx_release:
	make -C ./qkernel TOOLCHAIN=$(RUST_TOOLCHAIN) tdx_release

qkernel_tdx_debug:
	make -C ./qkernel TOOLCHAIN=$(RUST_TOOLCHAIN) tdx_debug

qvisor_tdx_release:
	make -C ./qvisor TOOLCHAIN=$(RUST_TOOLCHAIN) tdx_release

qvisor_tdx_debug:
	make -C ./qvisor TOOLCHAIN=$(RUST_TOOLCHAIN) tdx_debug

snp_release:: qvisor_snp_release qkernel_snp_release $(VDSO)

snp_debug:: qvisor_snp_debug qkernel_snp_debug $(VDSO)

qkernel_snp_release:
	make -C ./qkernel TOOLCHAIN=$(RUST_TOOLCHAIN) snp_release

qkernel_snp_debug:
	make -C ./qkernel TOOLCHAIN=$(RUST_TOOLCHAIN) snp_debug

qvisor_snp_release:
	make -C ./qvisor TOOLCHAIN=$(RUST_TOOLCHAIN) snp_release

qvisor_snp_debug:
	make -C ./qvisor TOOLCHAIN=$(RUST_TOOLCHAIN) snp_debug

install:
	@if [ -f "$(QKERNEL_RELEASE)" ]; then sudo cp -f "$(QKERNEL_RELEASE)" "$(QBIN_DIR)/" && echo "copied $(QKERNEL_RELEASE)"; fi
	@if [ -f "$(QUARK_RELEASE)" ]; then \
	    sudo cp -f "$(QUARK_RELEASE)" "$(QBIN_DIR)/quark"; \
	    sudo cp -f "$(QUARK_RELEASE)" "$(QBIN_DIR)/containerd-shim-quark-v1"; \
	    echo "copied $(QUARK_RELEASE)"; \
	fi
	@if [ -f "$(QKERNEL_DEBUG)" ]; then sudo cp -f "$(QKERNEL_DEBUG)" "$(QBIN_DIR)/" && echo "copied $(QKERNEL_DEBUG)"; fi
	@if [ -f "$(QUARK_DEBUG)" ]; then \
	    sudo cp -f "$(QUARK_DEBUG)" "$(QBIN_DIR)/quark_d"; \
	    sudo cp -f "$(QUARK_DEBUG)" "$(QBIN_DIR)/containerd-shim-quarkd-v1"; \
	    echo "copied $(QUARK_DEBUG)"; \
	fi
	@if [ -f "$(VDSO)" ]; then sudo cp -f "$(VDSO)" "$(QBIN_DIR)/vdso.so" && echo "copied $(VDSO)"; fi
	@if [ -f "$(TDSHIM)" ]; then sudo cp -f "$(TDSHIM)" "$(QBIN_DIR)/shim.bin" && echo "copied $(TDSHIM)"; fi
	@sudo mkdir -p "$(QCONFIG_DIR)"
	@sudo cp -f config.json "$(QCONFIG_DIR)" && echo "copied config.json"

cuda_make:
	make -C cudaproxy release
	sudo cp -f $(QTARGET_RELEASE)/libcudaproxy.so $(QBIN_DIR)/libcudaproxy.so
	sudo cp -f $(QTARGET_RELEASE)/libcudaproxy.so $(QROOT_DIR)/test

tdx_make:
	git submodule update --init --recursive
	make -C td-shim quark_shim
