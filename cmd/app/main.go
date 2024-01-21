package main

import (
	"fmt"
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

	fmt.Printf("%+v\n", store)
	server := http.NewApiServer(":3000", store)
	server.Run()
}
