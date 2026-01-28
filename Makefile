# Makefile for wantasticd

# Go parameters
GOCMD=go
VERSION?=$(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
COMMIT?=$(shell git rev-parse --short HEAD 2>/dev/null || echo "unknown")
DATE?=$(shell date -u +'%Y-%m-%dT%H:%M:%SZ')
LDFLAGS="-s -w -X wantastic-agent/pkg/version.Version=$(VERSION) -X wantastic-agent/pkg/version.Commit=$(COMMIT) -X wantastic-agent/pkg/version.BuildDate=$(DATE)"
GOBUILD=$(GOCMD) build -ldflags=$(LDFLAGS)
GOCLEAN=$(GOCMD) clean
GOTEST=$(GOCMD) test
GOGET=$(GOCMD) get
BINARY_NAME=wantasticd
COMPRESS=upx -9 -v
CMD_PATH=./cmd/wantasticd

# Build targets
TARGETS := \
	darwin/arm64 \
	linux/386 \
	linux/amd64 \
	linux/arm \
	linux/arm64 \
	linux/loong64 \
	linux/mips \
	linux/mips64 \
	linux/mips64le \
	linux/mipsle \
	linux/ppc64 \
	linux/ppc64le \
	linux/riscv64 \
	linux/s390x \
	windows/amd64

# Demo server parameters
DEMO_BINARY_NAME=demoserver
DEMO_CMD_PATH=./cmd/demoserver

all: build

build:
	$(GOBUILD) -o bin/$(BINARY_NAME) $(CMD_PATH)

build-all:
	@for target in $(TARGETS); do \
		echo "Building for $$target"; \
		mkdir -p bin; \
		GOOS=$$(echo $$target | cut -d'/' -f1) GOARCH=$$(echo $$target | cut -d'/' -f2) $(GOBUILD) -o bin/$(BINARY_NAME)-$$(echo $$target | cut -d'/' -f1)-$$(echo $$target | cut -d'/' -f2) $(CMD_PATH); \
		$(COMPRESS) bin/$(BINARY_NAME)-$$(echo $$target | cut -d'/' -f1)-$$(echo $$target | cut -d'/' -f2); \
	done
	@echo "Building for linux/armv7"
	@mkdir -p bin
	GOOS=linux GOARCH=arm GOARM=7 $(GOBUILD) -o bin/$(BINARY_NAME)-linux-armv7 $(CMD_PATH)


# Note: tinygo is not used because it is designed for microcontrollers and WebAssembly,
# not for building desktop applications.

build-%:
	@echo "Building for $*"
	@mkdir -p bin
	$(eval GOOS := $(word 1, $(subst /, ,$*)))
	$(eval GOARCH := $(word 2, $(subst /, ,$*)))
	GOOS=$(GOOS) GOARCH=$(GOARCH) $(GOBUILD) -o bin/$(BINARY_NAME)-$(GOOS)-$(GOARCH) $(CMD_PATH)



clean:
	$(GOCLEAN)
	rm -rf bin

run:
	$(GOBUILD) -o bin/$(BINARY_NAME) $(CMD_PATH)
	./bin/$(BINARY_NAME) connect -config traditional_wg.conf -v

# Demo server targets
build-demo:
	$(GOBUILD) -o bin/$(DEMO_BINARY_NAME) $(DEMO_CMD_PATH)

run-demo:
	$(GOBUILD) -o bin/$(DEMO_BINARY_NAME) $(DEMO_CMD_PATH)
	./bin/$(DEMO_BINARY_NAME)

genproto:
	protoc -Iproto --go_out=internal/grpc/proto --go_opt=paths=source_relative \
		--go-grpc_out=internal/grpc/proto --go-grpc_opt=paths=source_relative \
		auth.proto

release:
# create tag with release action first arg and push it
	git tag -a $(firstword $(filter-out release,$(MAKECMDGOALS))) -m "Release $(firstword $(filter-out release,$(MAKECMDGOALS)))"
	git push origin $(firstword $(filter-out release,$(MAKECMDGOALS)))
test:
	$(GOTEST) -v ./...

.PHONY: all build build-all clean run test genproto
