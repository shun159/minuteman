PROJECT := minuteman

CURDIR := $(abspath .)
BPFDIR := $(CURDIR)/bpf
BINDIR := $(CURDIR)/bin

BPFTOOL ?= bpftool
CLANG ?= clang
GO ?= go
RM ?= rm

GOOS ?= linux
GOARCH ?= amd64
CGO_ENABLED ?= 0

VMLINUX_BTF ?= $(wildcard /sys/kernel/btf/vmlinux)
ifeq ($(VMLINUX_BTF),)
$(error Cannot find a vmlinux)
endif

GO_BUILD_ENV := CGO_ENABLED=$(CGO_ENABLED) GOOS=$(GOOS) GOARCH=$(GOARCH)
GO_LDFLAGS := -trimpath -buildvcs=false -ldflags='-s -w'

$(PROJECT): build-bpf $(BINDIR)
	@$(GO_BUILD_ENV) $(GO) build $(GO_LDFLAGS) -o ./bin/$@ ./cmd/$@

.PHONY: vmlinux
vmlinux: $(BPFDIR)/vmlinux.h

.PHONY: build-bpf
build-bpf: vmlinux
	@$(GO_BUILD_ENV) $(GO) generate ./pkg/...

$(BPFDIR)/vmlinux.h:
	@$(BPFTOOL) btf dump file $(VMLINUX_BTF) format c > $@

$(BINDIR):
	@mkdir -p $(BINDIR)

.PHONY: clean
clean:
	-@$(RM) -f $(BPFDIR)/vmlinux.h
	-@$(RM) -f bin/*
	-@$(RM) -f ./*.o
	-@$(RM) -f pkg/datapath/bpf_x86_*.go
	-@$(RM) -f pkg/datapath/bpf_x86_*.o
