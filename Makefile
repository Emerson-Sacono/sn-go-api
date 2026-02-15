run:
	go run ./cmd/api

build:
	go build -o ./bin/sn-go-api ./cmd/api

fmt:
	gofmt -w ./cmd ./internal

