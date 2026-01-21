# Makefile for wantasticd

# Go parameters
GOCMD=go
GOBUILD=$(GOCMD) build
GOCLEAN=$(GOCMD) clean
GOTEST=$(GOCMD) test
GOGET=$(GOCMD) get
BINARY_NAME=wantasticd
CMD_PATH=./cmd/wantasticd

# Build targets
TARGETS := \
	darwin/arm64 \
	linux/amd64 \
	linux/arm64 \
	linux/arm \
	windows/amd64

all: build

build:
	$(GOBUILD) -o bin/$(BINARY_NAME) $(CMD_PATH)

build-all:
	@for target in $(TARGETS); do \
		echo "Building for $$target"; \
		mkdir -p bin; \
		GOOS=$$(echo $$target | cut -d'/' -f1) GOARCH=$$(echo $$target | cut -d'/' -f2) $(GOBUILD) -o bin/$(BINARY_NAME)-$$(echo $$target | cut -d'/' -f1)-$$(echo $$target | cut -d'/' -f2) $(CMD_PATH); \
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
	./bin/$(BINARY_NAME)

test:
	$(GOTEST) -v ./...

.PHONY: all build build-all clean run test
