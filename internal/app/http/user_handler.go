package http

import (
	"encoding/json"
	"fmt"
	"net/http"
)

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
		tokenString, err := CreateToken(user.Id)

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

	hashedPassword, err := hashPassword(user.Id, user.Salt)

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
