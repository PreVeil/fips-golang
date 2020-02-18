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

ifeq ($(GOPATH),)
GOPATH := $(PWD)
endif

$(info $$GOPATH is [${GOPATH}])
BIN	:= $(GOPATH)/bin
GO	:= env GOPATH="$(GOPATH)" go

# if fipspath is set, use it
# otherwise, library should be in /usr/local/lib and headers should be in /usr/local/include
ifneq ($(FIPSPATH),)
GO := CGO_CFLAGS="-I$(FIPSPATH)" CGO_LDFLAGS="-L$(FIPSPATH)" $(GO)
endif

DEP	:= env GOPATH="$(GOPATH)" dep
GOBUILD := $(GO) build -gcflags="-e"
GOINSTALL := $(GO) install -gcflags="-e"

sense:
	@echo "$$USAGE"

help: sense

all: deps install

deps:
	env GOPATH="$(GOPATH)" dep ensure

## install commands
install:
	$(GO) clean -cache
	$(GOINSTALL) 

build:
	$(GOBUILD)

run: deps install
	$(GOPATH)/bin/fips

test:
	$(GO) clean -testcache
	$(GO) test ./...

clean:
	$(GO) clean -cache
