define USAGE
USAGE:
> make [
	test: run all unit tests
	test-unit: run all unit tests
	clean: ...
]
endef
export USAGE

# name of the package
BUILD_PKG := fips
BIN	:= $(PWD)/bin
GO := go

# if fipspath is set, use it
# otherwise, library should be in /usr/local/lib and headers should be in /usr/local/include
ifneq ($(FIPSDIR),)
GO_WIN := CGO_CFLAGS="-I$(FIPSDIR)" CGO_LDFLAGS="-L$(FIPSDIR)" go
GO := env DYLD_LIBRARY_PATH="$(FIPSDIR):$(DYLD_LIBRARY_PATH)" CGO_CFLAGS="-I$(FIPSDIR)" CGO_LDFLAGS="-L$(FIPSDIR)" go
GO_LINUX := env LD_LIBRARY_PATH="$(FIPSDIR):$(LD_LIBRARY_PATH)" CGO_CFLAGS="-I$(FIPSDIR)" CGO_LDFLAGS="-ldl -lm -L$(FIPSDIR)" go
endif


sense:
	@echo "$$USAGE"

help: sense

test: test-unit

test-unit:
	go clean -testcache || true
ifeq ($(OS),Windows_NT)
	$(GO_WIN) test ./...
else
ifeq ($(shell uname -s),Linux)
	$(GO_LINUX) test ./...
else
	$(GO) test ./...
endif
endif

clean:
	go clean -cache || true
	go clean -testcache || true
