package main

import (
	"log"

	"github.com/evlian/TestSigner/internal/app/database"
	"github.com/evlian/TestSigner/internal/app/http"
)

func main() {
	store, err := database.NewPostgresStore()
	if err != nil {
		log.Fatal(err)
	}

	if err := store.Init(); err != nil {
		log.Fatal(err)
	}

	server := http.NewApiServer(":3000", store)
	server.Run()
}
