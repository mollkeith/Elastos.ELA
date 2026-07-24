# F-210 reproducible-build pins.
#
# Float behaviour is architecture-dependent (the compiler may contract a*b+c
# into a single FMA on arm64/ppc64/s390x but never on amd64), so a consensus
# binary must be built for a pinned target with a pinned toolchain. The
# toolchain patch level lives in .go-version; GOAMD64 is pinned here so the
# build does not silently inherit a builder-local microarchitecture level.
GOAMD64 ?= v1
export GOAMD64

GOVER := $(shell go version)
VERSION := $(shell git describe --abbrev=4 --dirty --always --tags)
BUILD = go build -ldflags "-X main.Version=$(VERSION) -X 'main.GoVersion=$(GOVER)'"

DEV_BRANCH := $(shell git rev-parse --abbrev-ref HEAD)
DEV_VERSION := $(shell git rev-list HEAD -n 1 | cut -c 1-8)
DEV_BUILD = go build -ldflags "-X main.Version=$(DEV_BRANCH)-$(DEV_VERSION) -X 'main.GoVersion=$(GOVER)'" #-race

all:
	$(BUILD) -o ela log.go main.go
	$(BUILD) -o ela-cli cmd/ela-cli.go
	$(BUILD) -o ela-dns elanet/dns/main/main.go

dev:
	$(DEV_BUILD) -race -o ela log.go main.go
	$(DEV_BUILD) -o ela-cli cmd/ela-cli.go
	$(DEV_BUILD) -o ela-dns elanet/dns/main/main.go

linux:
	GOARCH=amd64 GOOS=linux $(BUILD) -o ela log.go main.go
	GOARCH=amd64 GOOS=linux $(BUILD) -o ela-cli cmd/ela-cli.go
	GOARCH=amd64 GOOS=linux $(BUILD) -o ela-dns elanet/dns/main/main.go

cli:
	$(BUILD) -o ela-cli cmd/ela-cli.go

dns:
	$(BUILD) -o ela-dns elanet/dns/main/main.go

tools:
	$(BUILD) -o ela-datagen benchmark/tools/generator/main.go
	$(BUILD) -o ela-inputcounter benchmark/tools/inputcounter/main.go

# release builds the shipped, byte-reproducible binaries: pinned GOOS/GOARCH/
# GOAMD64, no cgo (so the toolchain, not the builder's libc, decides the
# output) and -trimpath (so the builder's directory layout does not leak into
# the binary). Verify with `make repro-check`.
RELEASE_ENV = GOOS=linux GOARCH=amd64 GOAMD64=$(GOAMD64) CGO_ENABLED=0
RELEASE_FLAGS = -trimpath

release:
	$(RELEASE_ENV) $(BUILD) $(RELEASE_FLAGS) -o ela log.go main.go
	$(RELEASE_ENV) $(BUILD) $(RELEASE_FLAGS) -o ela-cli cmd/ela-cli.go
	$(RELEASE_ENV) $(BUILD) $(RELEASE_FLAGS) -o ela-dns elanet/dns/main/main.go

# repro-check builds the node twice into separate outputs and fails if the
# two binaries differ, i.e. if anything about the build is not pinned.
repro-check:
	$(RELEASE_ENV) $(BUILD) $(RELEASE_FLAGS) -o ela.repro1 log.go main.go
	$(RELEASE_ENV) $(BUILD) $(RELEASE_FLAGS) -o ela.repro2 log.go main.go
	cmp ela.repro1 ela.repro2
	rm -f ela.repro1 ela.repro2
	@echo "reproducible build OK ($(shell cat .go-version) GOAMD64=$(GOAMD64))"

format:
	go fmt ./*

clean:
	rm -rf *.8 *.o *.out *.6

