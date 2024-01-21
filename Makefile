build:
	@cd ./cmd/app && go build -o bin/testsigner

run: build
	@cd ./cmd/app && ./bin/testsigner

testsigner:
	@go test -v ./...
