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
	Email string `json:"email"`
	Token string `json:"token"`
}

type CreateSignatureRequest struct {
	Answers []AnswersDto `json:"answers"`
}

type VerifySignatureRequest struct {
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

type User struct {
	Id       string
	Email    string
	Password string
	Token    string
	Salt     string
}

type Signature struct {
	Id            int
	UserId        int
	QuestionsHash string
	Questions     []string
	Answers       []string
	Signature     string
	FinishedAt    string
}
