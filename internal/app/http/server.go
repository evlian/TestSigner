package http

import (
	"log"
	"net/http"

	"github.com/evlian/TestSigner/internal/app/database"
	"github.com/evlian/TestSigner/internal/app/middleware"
	"github.com/evlian/TestSigner/internal/app/utils"
	"github.com/gorilla/mux"
)

type ApiError struct {
	Error string ``
}

type apiFunc func(http.ResponseWriter, *http.Request) error

func makeHttpHandleFunc(f apiFunc) http.HandlerFunc {
	return func(writer http.ResponseWriter, response *http.Request) {
		if err := f(writer, response); err != nil {
			utils.WriteJson(writer, http.StatusBadRequest, ApiError{Error: err.Error()})
		}
	}
}

type ApiServer struct {
	listenAddress string
	store         database.Storage
}

func NewApiServer(listenAddress string, store database.Storage) *ApiServer {
	return &ApiServer{
		listenAddress: listenAddress,
		store:         store,
	}
}

func (s *ApiServer) Run() {
	router := mux.NewRouter()

	router.Use(middleware.CommonMiddleware())
	router.HandleFunc("/sign-answers", makeHttpHandleFunc(s.handleSignAnswers))
	router.HandleFunc("/verify-signature", makeHttpHandleFunc(s.handleVerifySignature))

	router.HandleFunc("/register", makeHttpHandleFunc(s.handleRegister))
	router.HandleFunc("/login", makeHttpHandleFunc(s.handleLogin))

	log.Println("Test Signer service running on port: ", s.listenAddress)

	http.ListenAndServe(s.listenAddress, router)
}
