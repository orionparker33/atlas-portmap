VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -s -w -X main.version=$(VERSION)
GO      ?= go
PLATFORMS := linux/amd64 linux/arm64 windows/amd64 windows/arm64 darwin/arm64

.PHONY: build test race vet e2e dist data clean jscheck demo gui-demo

build:
	CGO_ENABLED=0 $(GO) build -trimpath -ldflags '$(LDFLAGS)' -o bin/atlas-portmap ./cmd/atlas-portmap

test:
	$(GO) test ./...

race:
	$(GO) test -race ./...

vet:
	$(GO) vet ./... && $(GO) vet -tags e2e ./e2e/ && test -z "$$(gofmt -l .)"

e2e:
	./scripts/e2e.sh

dist:
	@set -e; rm -rf dist; mkdir -p dist; for p in $(PLATFORMS); do \
	    os=$${p%/*}; arch=$${p#*/}; ext=; [ "$$os" = windows ] && ext=.exe; \
	    echo "building $$os/$$arch"; \
	    CGO_ENABLED=0 GOOS=$$os GOARCH=$$arch $(GO) build -trimpath -ldflags '$(LDFLAGS)' \
	        -o dist/atlas-portmap-$$os-$$arch$$ext ./cmd/atlas-portmap; \
	done; cp LICENSE THIRD_PARTY_NOTICES dist/; cd dist && for b in atlas-portmap-*; do \
	    case $$b in *.exe) python3 -m zipfile -c $${b%.exe}.zip $$b LICENSE THIRD_PARTY_NOTICES ;; \
	    *) tar -czf $$b.tar.gz $$b LICENSE THIRD_PARTY_NOTICES ;; esac; done; \
	    sha256sum atlas-portmap-*.zip atlas-portmap-*.tar.gz > SHA256SUMS

data:
	$(GO) run ./tools/gendata -out internal/vendor/data

jscheck:
	@tmp=$$(mktemp -d); cp -r internal/gui/web/js $$tmp/; echo '{"type":"module"}' > $$tmp/package.json; \
	    cd $$tmp && for f in $$(find js -name '*.js'); do node --check $$f || exit 1; done; rm -rf $$tmp; echo 'js ok'

demo:
	$(GO) run ./tools/demoreport > demo.json

gui-demo: demo
	$(GO) run ./cmd/atlas-portmap gui -open demo.json

clean:
	rm -rf bin dist
