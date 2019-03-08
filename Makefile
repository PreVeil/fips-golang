#name of the package
BUILD_PKG	:= fips
GOPATH := $(realpath $(dir $(realpath $(dir $(shell pwd)))))

UNAME	:= $(shell uname)
ifeq ($(UNAME), CYGWIN_NT-10.0)
GOPATH	:= $(shell cygpath -w "$(GOPATH)")
endif
ifeq ($(UNAME), CYGWIN_NT-6.3)
GOPATH	:= $(shell cygpath -w "$(GOPATH)")
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
	#now run it.
	$(GOPATH)/bin/fips

test: 
	$(GO) clean -testcache
	$(GO) test ./...

clean:
	$(GO) clean -cache
