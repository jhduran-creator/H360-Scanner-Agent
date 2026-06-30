VERSION ?= dev
BIN     := hd360-scanner

.PHONY: build build-all build-linux build-windows build-mac docker test clean

build:
	go build -ldflags="-X main.version=$(VERSION)" -o bin/$(BIN) ./cmd/hd360-scanner

build-linux:
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
		go build -ldflags="-s -w -X main.version=$(VERSION)" \
		-o dist/$(BIN)-linux-amd64 ./cmd/hd360-scanner
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 \
		go build -ldflags="-s -w -X main.version=$(VERSION)" \
		-o dist/$(BIN)-linux-arm64 ./cmd/hd360-scanner

build-windows:
	CGO_ENABLED=0 GOOS=windows GOARCH=amd64 \
		go build -ldflags="-s -w -X main.version=$(VERSION)" \
		-o dist/$(BIN)-windows-amd64.exe ./cmd/hd360-scanner

build-mac:
	CGO_ENABLED=0 GOOS=darwin GOARCH=amd64 \
		go build -ldflags="-s -w -X main.version=$(VERSION)" \
		-o dist/$(BIN)-darwin-amd64 ./cmd/hd360-scanner
	CGO_ENABLED=0 GOOS=darwin GOARCH=arm64 \
		go build -ldflags="-s -w -X main.version=$(VERSION)" \
		-o dist/$(BIN)-darwin-arm64 ./cmd/hd360-scanner

build-all: build-linux build-windows build-mac
	@echo "Build cross-platform completo en dist/"
	@ls -la dist/

# Build via Docker (útil si no hay Go local instalado)
docker:
	docker build --build-arg VERSION=$(VERSION) -t hd360-scanner:$(VERSION) -t hd360-scanner:latest .

test:
	go test -v ./...

clean:
	rm -rf bin/ dist/
