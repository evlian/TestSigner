build:
	@go build -o bin/testsigner

run: build
	@./bin/testsigner

testsigner:
	@go test -v ./...