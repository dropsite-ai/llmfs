.PHONY: build install release test

BINARY_NAME=llmfs
DIST_DIR=dist
INSTALL_DIR=/usr/local/bin

OS := $(shell uname | tr '[:upper:]' '[:lower:]')
ARCH := $(shell uname -m)

ifeq ($(ARCH),x86_64)
  ARCH=amd64
else ifeq ($(ARCH),i386)
  ARCH=386
else ifeq ($(ARCH),arm64)
  ARCH=arm64
else ifeq ($(ARCH),armv7)
  ARCH=armv7
endif

TARGET_BINARY=$(DIST_DIR)/$(BINARY_NAME)_$(OS)_$(ARCH)

build:
	goreleaser release --snapshot --clean

install: build
	sudo cp $(TARGET_BINARY)_*/$(BINARY_NAME) $(INSTALL_DIR)/$(BINARY_NAME)

release:
	@echo "Creating a new release..."
	@read -p "Enter release target (dev, patch, minor, major) [default: dev]: " target && \
	if [ -z "$$target" ]; then \
		target="dev"; \
	fi && \
	version=$$(git-semver -target $$target) && \
	if [ -z "$$version" ]; then \
		echo "Error: Unable to determine version using git-semver."; \
		exit 1; \
	fi && \
	echo "New version: $$version" && \
	read -p "Enter release message: " message && \
	if [ -z "$$message" ]; then \
		echo "Error: Release message cannot be empty."; \
		exit 1; \
	fi && \
	git tag -a $$version -m "$$message" && \
	git push origin $$version && \
	goreleaser release --clean

test:
	go test -v ./...