define USAGE
USAGE:
> make [
	test: run all unit tests
	test-unit: run all unit tests
	clean: ...
]
endef
export USAGE


# build & test flags
# if fipspath is set, use it
# otherwise, library should be in /usr/local/lib and headers should be in /usr/local/include for darwin
ifneq ($(FIPSDIR),)
    CGO_CFLAGS := -I$(FIPSDIR)
    CGO_LDFLAGS := -L$(FIPSDIR)
    FLAGS := CGO_CFLAGS="$(CGO_CFLAGS)"
    ifeq ($(OS),Windows_NT)
        @echo "i am simple"
    else
        ifeq ($(shell uname -s),Linux)
            CGO_LDFLAGS := -ldl -lm $(CGO_LDFLAGS)
            FLAGS := env LD_LIBRARY_PATH="$(FIPSDIR):$(LD_LIBRARY_PATH)" CGO_LDFLAGS="$(CGO_LDFLAGS)" $(FLAGS)
        else
            FLAGS := env DYLD_LIBRARY_PATH="$(FIPSDIR):$(DYLD_LIBRARY_PATH)" CGO_LDFLAGS="$(CGO_LDFLAGS)" $(FLAGS)
        endif
    endif
endif

GO := $(FLAGS) go

sense:
	@echo "$$USAGE"

help: sense

test: test-unit

test-unit:
	go clean -testcache || true
	$(GO) test ./...

clean:
	go clean -cache || true
	go clean -testcache || true
