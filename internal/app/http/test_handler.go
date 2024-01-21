package http

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"

	"github.com/evlian/TestSigner/internal/app/middleware"
	"github.com/evlian/TestSigner/internal/app/models"
	"github.com/evlian/TestSigner/internal/app/utils"
)

func (s *ApiServer) handleSignAnswers(
	writer http.ResponseWriter,
	request *http.Request) error {

	if request.Method != "POST" {
		return utils.WriteJson(writer, http.StatusMethodNotAllowed, "Method not allowed")
	}

	middleware.Authorize(writer, request)

	var signAnswersRequest models.CreateSignatureRequest
	json.NewDecoder(request.Body).Decode(&signAnswersRequest)

	tokenString := request.Header.Get("Authorization")
	userIdString, err := utils.GetUserIdFromClaims(tokenString)
	if err != nil {
		return utils.WriteJson(writer, http.StatusInternalServerError, "internal server error")
	}

	userId, err := strconv.Atoi(userIdString)
	if err != nil {
		return utils.WriteJson(writer, http.StatusInternalServerError, "internal server error")
	}

	questionStrings := make([]string, len(signAnswersRequest.Answers))
	answerStrings := make([]string, len(signAnswersRequest.Answers))

	// Extract the question strings from AnswersDto and store them in the slice
	for i, answer := range signAnswersRequest.Answers {
		questionStrings[i] = answer.Question
		answerStrings[i] = answer.Answer
	}

	questionsJson, err := json.Marshal(questionStrings)
	answersJson, err := json.Marshal(answerStrings)

	questionsHash := utils.GenerateHash(string(questionsJson))
	hash := utils.GenerateHash(string(questionsJson) + string(answersJson) + userIdString)

	submissionExists, err := s.store.SignatureExists(questionsHash, userId)
	if err != nil {
		return utils.WriteJson(writer, http.StatusInternalServerError, "Internal server error")
	}

	if submissionExists {
		return utils.WriteJson(writer, http.StatusBadRequest, "Test submission already exists")
	}

	var signature models.Signature

	signature.Questions = questionStrings
	signature.Answers = answerStrings
	signature.UserId = userId

	signature.QuestionsHash = questionsHash
	signature.Signature = hash

	createErr := s.store.CreateSignature(&signature)

	if createErr != nil {
		return utils.WriteJson(writer, http.StatusInternalServerError, "internal server error")
	}

	return utils.WriteJson(writer, http.StatusOK, signature.Signature)
}

func (s *ApiServer) handleVerifySignature(
	writer http.ResponseWriter,
	request *http.Request) error {

	if request.Method != "POST" {
		return utils.WriteJson(writer, http.StatusMethodNotAllowed, "Method not allowed")
	}

	var verifySignatureRequest models.VerifySignatureRequest
	json.NewDecoder(request.Body).Decode(&verifySignatureRequest)

	signature, err := s.store.GetSignature(verifySignatureRequest.Signature, verifySignatureRequest.UserId)
	if err != nil {
		fmt.Println(err)
		return utils.WriteJson(writer, http.StatusNotFound, "Invalid signature")
	}

	answers := make([]models.AnswersDto, len(signature.Questions))
	for i := 0; i < len(signature.Questions); i++ {
		answers[i].Question = signature.Questions[i]
		answers[i].Answer = signature.Answers[i]
	}

	var verifySignatureResponse models.VerifySignatureResponse
	verifySignatureResponse.Answers = answers
	verifySignatureResponse.Timestamp = signature.FinishedAt
	return utils.WriteJson(writer, http.StatusOK, verifySignatureResponse)
}
