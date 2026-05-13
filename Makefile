# SPDX-License-Identifier: GPL-2.0

BINARY = kondor

.PHONY: all deps generate build clean

all: build

deps:
	go mod tidy
	go install github.com/cilium/ebpf/cmd/bpf2go@latest

generate: deps
	cd internal/lb && go generate ./...

build: generate
	go build -o $(BINARY) ./cmd/kondor

clean:
	rm -f internal/lb/balancer_bpf*.go internal/lb/balancer_bpf*.o $(BINARY)
