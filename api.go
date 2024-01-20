package main

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net/http"

	"golang.org/x/crypto/bcrypt"

	"github.com/gorilla/mux"
)

func WriteJson(writer http.ResponseWriter, status int, value any) error {
	writer.WriteHeader(status)
	writer.Header().Set("Content-Type", "application/json")
	return json.NewEncoder(writer).Encode(value)
}

type apiFunc func(http.ResponseWriter, *http.Request) error

type ApiError struct {
	Error string
}

func makeHttpHandleFunc(f apiFunc) http.HandlerFunc {
	return func(writer http.ResponseWriter, response *http.Request) {
		if err := f(writer, response); err != nil {
			WriteJson(writer, http.StatusBadRequest, ApiError{Error: err.Error()})
		}
	}
}

type ApiServer struct {
	listenAddress string
	store         Storage
}

func NewApiServer(listenAddress string, store Storage) *ApiServer {
	return &ApiServer{
		listenAddress: listenAddress,
		store:         store,
	}
}

func (s *ApiServer) Run() {
	router := mux.NewRouter()

	router.HandleFunc("/sign-answers", makeHttpHandleFunc(s.handleSignAnswers))
	router.HandleFunc("/verify-signature", makeHttpHandleFunc(s.handleVerifySignature))

	router.HandleFunc("/register", makeHttpHandleFunc(s.handleRegister))
	router.HandleFunc("/login", makeHttpHandleFunc(s.handleLogin))

	log.Println("Test Signer service running on port: ", s.listenAddress)

	http.ListenAndServe(s.listenAddress, router)
}

func (s *ApiServer) handleTests(
	writer http.ResponseWriter,
	reader *http.Request) error {

	return nil
}

func (s *ApiServer) handleSignAnswers(
	writer http.ResponseWriter,
	request *http.Request) error {

	if request.Method != "POST" {
		return fmt.Errorf("method not allowed %s", request.Method)
	}

	Authorize(writer, request)

	var loginRequest LoginRequest
	json.NewDecoder(request.Body).Decode(&loginRequest)

	// sign answers
	return nil
}

func (s *ApiServer) handleVerifySignature(
	writer http.ResponseWriter,
	request *http.Request) error {

	if request.Method != "POST" {
		return fmt.Errorf("method not allowed %s", request.Method)
	}
	Authorize(writer, request)

	return nil
}

func (s *ApiServer) handleLogin(
	w http.ResponseWriter,
	r *http.Request) error {
	w.Header().Set("Content-Type", "application/json")

	var loginRequest LoginRequest
	json.NewDecoder(r.Body).Decode(&loginRequest)

	user, err := s.store.GetUser(loginRequest.Email)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return fmt.Errorf("email not registered")
	}

	passwordErr := verifyPassword(user.Password, loginRequest.Password, user.Salt)
	if passwordErr == nil {
		tokenString, err := CreateToken(user.Email)

		if err != nil {
			return fmt.Errorf("email not registered")
		}

		var loggedInUser SuccessfulAuthResponse
		loggedInUser.Email = user.Email
		loggedInUser.Token = tokenString
		return WriteJson(w, http.StatusOK, &loggedInUser)

	} else {
		return fmt.Errorf("password was incorrect")
	}

}

func (s *ApiServer) handleRegister(
	w http.ResponseWriter,
	r *http.Request) error {
	w.Header().Set("Content-Type", "application/json")

	var user User
	json.NewDecoder(r.Body).Decode(&user)

	salt, err := generateSalt()
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return fmt.Errorf("error generating salt")
	}

	user.Salt = salt

	hashedPassword, err := hashPassword(user.Password, user.Salt)

	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return fmt.Errorf("error hashing password")
	}
	user.Password = hashedPassword

	s.store.CreateUser(&user)

	tokenString, err := CreateToken(user.Email)
	if err != nil {
		return fmt.Errorf("email not registered")
	}

	var loggedInUser SuccessfulAuthResponse
	loggedInUser.Email = user.Email
	loggedInUser.Token = tokenString

	w.WriteHeader(http.StatusCreated)
	return WriteJson(w, http.StatusCreated, loggedInUser)
}

func generateSalt() (string, error) {
	saltBytes := make([]byte, 16)
	_, err := rand.Read(saltBytes)
	if err != nil {
		return "", err
	}

	salt := hex.EncodeToString(saltBytes)

	return salt, nil
}

func hashPassword(password, salt string) (string, error) {
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password+salt), bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}
	return string(hashedPassword), nil
}

func verifyPassword(hashedPassword, inputPassword, salt string) error {
	// Combine input password and salt, then compare with the hashed password
	err := bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(inputPassword+salt))
	if err != nil {
		return fmt.Errorf("invalid password")
	}
	return nil
}

func Authorize(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	tokenString := r.Header.Get("Authorization")
	if tokenString == "" {
		w.WriteHeader(http.StatusUnauthorized)
		fmt.Fprint(w, "missing authorization header")
		return
	}
	tokenString = tokenString[len("Bearer "):]

	err := VerifyToken(tokenString)
	if err != nil {
		w.WriteHeader(http.StatusUnauthorized)
		fmt.Fprint(w, "invalid token")
		return
	}
}
