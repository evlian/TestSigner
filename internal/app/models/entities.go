package models

type User struct {
	Id       int
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
