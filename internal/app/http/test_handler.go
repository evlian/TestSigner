package http

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
)

func (s *ApiServer) handleSignAnswers(
	writer http.ResponseWriter,
	request *http.Request) error {

	if request.Method != "POST" {
		return fmt.Errorf("method not allowed %s", request.Method)
	}

	Authorize(writer, request)

	var signAnswersRequest CreateSignatureRequest
	json.NewDecoder(request.Body).Decode(&signAnswersRequest)

	tokenString := request.Header.Get("Authorization")
	userIdString, err := GetUserIdFromClaims(tokenString)
	if err != nil {
		return fmt.Errorf("error getting userId from claims")
	}

	userId, err := strconv.Atoi(userIdString)
	if err != nil {
		return fmt.Errorf("internal server error")
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

	questionsHash := GenerateHash(string(questionsJson))
	hash := GenerateHash(string(questionsJson) + string(answersJson) + userIdString)

	submissionExists, err := s.store.SignatureExists(questionsHash, userId)
	if err != nil {
		return fmt.Errorf("internal server error")
	}

	if submissionExists {
		return WriteJson(writer, http.StatusBadRequest, "Test submission already exists")
	}

	var signature Signature

	signature.Questions = questionStrings
	signature.Answers = answerStrings
	signature.UserId = userId

	signature.QuestionsHash = questionsHash
	signature.Signature = hash

	createErr := s.store.CreateSignature(&signature)

	if createErr != nil {
		return WriteJson(writer, http.StatusInternalServerError, "internal server error")
	}

	return WriteJson(writer, http.StatusOK, signature.Signature)
}

func (s *ApiServer) handleVerifySignature(
	writer http.ResponseWriter,
	request *http.Request) error {

	if request.Method != "POST" {
		return fmt.Errorf("method not allowed %s", request.Method)
	}
	Authorize(writer, request)

	var verifySignatureRequest VerifySignatureRequest
	json.NewDecoder(request.Body).Decode(&verifySignatureRequest)

	signature, err := s.store.GetSignature(verifySignatureRequest.Signature)
	if err != nil {
		fmt.Println(err)
		return WriteJson(writer, http.StatusNotFound, "Invalid signature")
	}

	answers := make([]AnswersDto, len(signature.Questions))
	for i := 0; i < len(signature.Questions); i++ {
		answers[i].Question = signature.Questions[i]
		answers[i].Answer = signature.Answers[i]
	}

	var verifySignatureResponse VerifySignatureResponse
	verifySignatureResponse.Answers = answers
	verifySignatureResponse.Timestamp = signature.FinishedAt
	return WriteJson(writer, http.StatusOK, verifySignatureResponse)
}
