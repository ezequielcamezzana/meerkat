BINARY  := meerkat
CMD     := ./cmd/meerkat
BIN     := bin/$(BINARY)
UI_SRC  := $(HOME)/Proyectos/apps/ui
VERSION ?= dev
COMMIT  ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo "none")
DATE    ?= $(shell date -u +%Y-%m-%dT%H:%M:%SZ)

LDFLAGS := -X github.com/ezequielcamezzana/meerkat/cmd/meerkat/commands.Version=$(VERSION) \
           -X github.com/ezequielcamezzana/meerkat/cmd/meerkat/commands.Commit=$(COMMIT) \
           -X github.com/ezequielcamezzana/meerkat/cmd/meerkat/commands.Date=$(DATE)

.PHONY: build install run test vet fmt tidy clean ui-sync

# TODO: meerkat inlines its CSS in internal/server/ui/index.html and does not
# consume the shared design system yet. Wire tokens.css/base.css into the UI,
# then this sync becomes meaningful. Pending: shared design system integration.
## ui-sync: copy the shared design system (~/Proyectos/apps/ui) into the UI
ui-sync:
	cp $(UI_SRC)/tokens.css $(UI_SRC)/base.css internal/server/ui/assets/

## build: build the binary into ./bin/meerkat
build:
	go build -ldflags "$(LDFLAGS)" -o $(BIN) $(CMD)

## install: install the binary globally (go env GOPATH/bin, on your PATH)
install:
	go install -ldflags "$(LDFLAGS)" $(CMD)

## run: run the server from source (without installing)
run:
	go run -ldflags "$(LDFLAGS)" $(CMD)

## test: run the full suite
test:
	go test ./...

## vet: static analysis
vet:
	go vet ./...

## fmt: format the code
fmt:
	go fmt ./...

## tidy: tidy go.mod/go.sum
tidy:
	go mod tidy

## clean: remove local binaries (bin/ and the legacy root binary)
clean:
	rm -rf bin $(BINARY)
