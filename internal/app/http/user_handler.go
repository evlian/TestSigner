package http

import (
	"encoding/json"
	"net/http"
	"strconv"

	"github.com/evlian/TestSigner/internal/app/models"
	"github.com/evlian/TestSigner/internal/app/utils"
)

func (s *ApiServer) handleLogin(
	writer http.ResponseWriter,
	request *http.Request) error {

	if request.Method != "POST" {
		return utils.WriteJson(writer, http.StatusMethodNotAllowed, "Method not allowed")
	}

	var loginRequest models.LoginRequest
	json.NewDecoder(request.Body).Decode(&loginRequest)

	user, err := s.store.GetUser(loginRequest.Email)
	if err != nil {
		return utils.WriteJson(writer, http.StatusNotFound, "not found")
	}

	passwordErr := utils.VerifyPassword(user.Password, loginRequest.Password, user.Salt)
	if passwordErr == nil {
		tokenString, err := utils.CreateToken(strconv.Itoa(user.Id))

		if err != nil {
			return utils.WriteJson(writer, http.StatusInternalServerError, "error creating token")
		}

		var loggedInUser models.SuccessfulAuthResponse
		loggedInUser.Id = user.Id
		loggedInUser.Email = user.Email
		loggedInUser.Token = tokenString
		return utils.WriteJson(writer, http.StatusOK, &loggedInUser)

	} else {
		return utils.WriteJson(writer, http.StatusUnauthorized, "unauthorized")
	}

}

func (s *ApiServer) handleRegister(
	writer http.ResponseWriter,
	request *http.Request) error {

	if request.Method != "POST" {
		return utils.WriteJson(writer, http.StatusMethodNotAllowed, "Method not allowed")
	}

	var user models.User
	json.NewDecoder(request.Body).Decode(&user)

	existingUser, err := s.store.GetUser(user.Email)
	if err != nil {
		return utils.WriteJson(writer, http.StatusInternalServerError, "internal server error")
	}

	if existingUser != nil {
		return utils.WriteJson(writer, http.StatusNotModified, "user already exists")
	}

	salt, err := utils.GenerateSalt()
	if err != nil {
		return utils.WriteJson(writer, http.StatusInternalServerError, "internal server error")
	}

	user.Salt = salt

	hashedPassword, err := utils.HashPassword(user.Password, user.Salt)

	if err != nil {
		return utils.WriteJson(writer, http.StatusInternalServerError, "internal server error")
	}
	user.Password = hashedPassword

	s.store.CreateUser(&user)

	tokenString, err := utils.CreateToken(user.Email)
	if err != nil {
		return utils.WriteJson(writer, http.StatusUnauthorized, "Unauthorized")
	}

	var loggedInUser models.SuccessfulAuthResponse
	loggedInUser.Id = user.Id
	loggedInUser.Email = user.Email
	loggedInUser.Token = tokenString

	return utils.WriteJson(writer, http.StatusCreated, loggedInUser)
}
