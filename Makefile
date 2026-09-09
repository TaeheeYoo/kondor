# SPDX-License-Identifier: GPL-2.0

BINARY = kondor

.PHONY: all deps generate build clean

MULTIARCH_INC := $(dir $(firstword $(wildcard /usr/include/*-linux-*/asm)))

all: build

deps:
	go mod tidy
	go install github.com/cilium/ebpf/cmd/bpf2go@latest

generate: deps
	# clang, invoked by bpf2go, needs the arch-specific uapi headers
	# (asm/types.h); point CPATH at the multiarch dir so a box without the
	# /usr/include/asm compatibility symlink still builds.  The dir is found
	# by glob so no gcc/clang is required to name the triple.
	cd internal/lb && CPATH="$(MULTIARCH_INC)$${CPATH:+:$$CPATH}" go generate ./...

build: generate
	go build -o $(BINARY) ./cmd/kondor

clean:
	rm -f internal/lb/balancer_bpf*.go internal/lb/balancer_bpf*.o $(BINARY)
