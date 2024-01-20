package main

import (
	"database/sql"
	"fmt"
	"time"

	_ "github.com/lib/pq"
)

type PostgresStore struct {
	database *sql.DB
}

type Storage interface {
	CreateSignature(*Signature) error
	GetSignature(string, string) (*Signature, error)
	CreateUser(*User) error
	GetUser(string) (*User, error)
	GetUserByEmail(string) (*User, error)
}

func NewPostgresStore() (*PostgresStore, error) {
	connectionString := "user=postgres dbname=postgres password=postgres sslmode=disable"
	database, err := sql.Open("postgres", connectionString)
	if err != nil {
		return nil, err
	}

	if err := database.Ping(); err != nil {
		return nil, err
	}

	return &PostgresStore{
		database: database,
	}, nil
}

func (store *PostgresStore) Init() error {
	err := store.CreateUserTable()
	if err != nil {
		return err
	}

	return store.CreateSignatureTable()
}

func (store *PostgresStore) CreateUserTable() error {
	createTableQuery := `
        CREATE TABLE IF NOT EXISTS users (
			id SERIAL PRIMARY KEY,
            email VARCHAR(255),
            password VARCHAR(255),
            salt BYTEA NOT NULL,
			created_at TIMESTAMP
        );
    `
	_, err := store.database.Exec(createTableQuery)
	return err
}

func (store *PostgresStore) CreateSignatureTable() error {
	createTableQuery := `
        CREATE TABLE IF NOT EXISTS signatures (
			signature_id SERIAL PRIMARY KEY,
            user_id INT,
            questions_hash VARCHAR(255),
            answers_hash VARCHAR(255),
            questions TEXT,
            answers TEXT,
            signature VARCHAR(255),
			finished_at TIMESTAMP
        );
    `
	_, err := store.database.Exec(createTableQuery)
	return err
}

func (store *PostgresStore) CreateUser(user *User) error {
	query := `
        INSERT INTO users
		(
			email,
			password, 
			salt,
			created_at
		)
        VALUES ($1, $2, $3, $4)
    `

	// Execute the SQL statement
	_, err := store.database.Exec(
		query,
		user.Email,
		user.Password,
		user.Salt,
		time.Now(),
	)

	if err != nil {
		fmt.Println("Data inserted not." + err.Error())

		return err
	}

	fmt.Println("Data inserted successfully.")
	return nil
}

func (store *PostgresStore) CreateSignature(signature *Signature) error {
	query := `
        INSERT INTO signature
		(
			user_id, 
			questions_hash, 
			answers_hash, 
			questions, 
			answers, 
			signature, 
			finished_at
		)
        VALUES ($1, $2, $3, $4, $5, $6, $7)
    `

	_, err := store.database.Exec(
		query,
		signature.UserId,
		signature.QuestionsHash,
		signature.AnswersHash,
		signature.Questions,
		signature.Answers,
		signature.Signature,
		time.Now())

	if err != nil {
		return err
	}

	return nil
}

func (store *PostgresStore) GetSignature(targetSignature string, userId string) (*Signature, error) {
	query := `
        SELECT signature_id, user_id, questions_hash, answers_hash, questions, answers, signature, finished_at
        FROM signatures
        WHERE user_id = $1 AND signature = $2
    `

	var signature Signature
	err := store.database.QueryRow(query, userId, targetSignature).Scan(
		&signature.Id,
		&signature.UserId,
		&signature.QuestionsHash,
		&signature.AnswersHash,
		&signature.Questions,
		&signature.Answers,
		&signature.Signature,
		&signature.FinishedAt)

	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}

	return &signature, nil
}

func (store *PostgresStore) GetUser(email string) (*User, error) {
	query := `
        SELECT email, password, salt
        FROM users
        WHERE email = $1
    `

	// Execute the SQL statement and scan the result into the User struct
	var user User
	err := store.database.QueryRow(query, email).Scan(&user.Email, &user.Password, &user.Salt)
	if err != nil {
		if err == sql.ErrNoRows {
			// Return nil and an error indicating that the user was not found
			return nil, fmt.Errorf("User not found")
		}
		return nil, err
	}

	return &user, nil
}

func (store *PostgresStore) GetUserByEmail(email string) (*User, error) {
	query := `
        SELECT email, password
        FROM users
        WHERE email = $1 AND password = $2
    `

	var user User
	err := store.database.QueryRow(query, email).Scan(&email)

	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}

	return &user, nil
}
