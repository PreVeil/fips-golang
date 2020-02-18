define USAGE
USAGE:
> make [
	build: build for the current platform
	install: build for the current platform

	test: run all unit tests
	test-unit: run all unit tests
	clean: clean test cache and other builds
]
endef
export USAGE

# name of the package
BUILD_PKG	:= fips
BIN	:= $(PWD)/bin
GO	:= go

# if fipspath is set, use it
# otherwise, library should be in /usr/local/lib and headers should be in /usr/local/include
ifneq ($(FIPSDIR),)
GO := CGO_CFLAGS="-I$(FIPSDIR)" CGO_LDFLAGS="-L$(FIPSDIR)" $(GO)
GO_LINUX := CGO_CFLAGS="-I$(FIPSDIR)" CGO_LDFLAGS="-ldl -lm -L$(FIPSDIR)" go
endif

GOBUILD := $(GO) build -gcflags="-e"
GOINSTALL := $(GO) install -gcflags="-e"

sense:
	@echo "$$USAGE"

help: sense

all: install

install: clean
	$(GOINSTALL)

build: clean
	$(GOBUILD)

test:
	$(GO) clean -testcache || true
ifeq ($(OS),Windows_NT)
	@echo "TODO"
else
ifeq ($(shell uname -s),Linux)
	$(GO_LINUX) test ./...
else
	$(GO) test ./...
endif
endif


clean:
	$(GO) clean -cache
