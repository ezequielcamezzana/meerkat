VERSION ?= dev
COMMIT  ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo "none")
DATE    ?= $(shell date -u +%Y-%m-%dT%H:%M:%SZ)

LDFLAGS := -X github.com/ezequielcamezzana/meerkat/cmd/meerkat/commands.Version=$(VERSION) \
           -X github.com/ezequielcamezzana/meerkat/cmd/meerkat/commands.Commit=$(COMMIT) \
           -X github.com/ezequielcamezzana/meerkat/cmd/meerkat/commands.Date=$(DATE)

.PHONY: build install test clean

build:
	go build -ldflags "$(LDFLAGS)" -o meerkat ./cmd/meerkat

install:
	go install -ldflags "$(LDFLAGS)" ./cmd/meerkat

test:
	go test ./...

clean:
	rm -f meerkat
