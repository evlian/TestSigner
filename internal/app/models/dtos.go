package models

type CreateUserRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

type LoginRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

type SuccessfulAuthResponse struct {
	Id    int    `json:"id"`
	Email string `json:"email"`
	Token string `json:"token"`
}

type CreateSignatureRequest struct {
	Answers []AnswersDto `json:"answers"`
}

type VerifySignatureRequest struct {
	UserId    int    `json:"userId"`
	Signature string `json:"signature"`
}

type VerifySignatureResponse struct {
	Answers   []AnswersDto `json:"answers"`
	Timestamp string       `json:"timestamp"`
}

type AnswersDto struct {
	Question string `json:"question"`
	Answer   string `json:"answer"`
}
