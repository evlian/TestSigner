package database

import (
	"database/sql"
	"fmt"
	"time"

	"github.com/evlian/TestSigner/internal/app/models"
	"github.com/lib/pq"
	_ "github.com/lib/pq"
)

type PostgresStore struct {
	database *sql.DB
}

type Storage interface {
	CreateSignature(*models.Signature) error
	GetSignature(targetSignature string, userId int) (*models.Signature, error)
	CreateUser(*models.User) error
	GetUser(email string) (*models.User, error)
	GetUserByEmail(email string) (*models.User, error)
	SignatureExists(questions string, user_id int) (bool, error)
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
            questions TEXT,
            answers TEXT,
            signature VARCHAR(255),
			finished_at TIMESTAMP
        );
    `
	_, err := store.database.Exec(createTableQuery)
	return err
}

func (store *PostgresStore) CreateUser(user *models.User) error {
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
		return err
	}

	return nil
}

func (store *PostgresStore) CreateSignature(signature *models.Signature) error {
	query := `
        INSERT INTO signatures
		(
			user_id, 
			questions_hash,
			questions, 
			answers, 
			signature, 
			finished_at
		)
        VALUES ($1, $2, $3, $4, $5, $6)
    `

	_, err := store.database.Exec(
		query,
		signature.UserId,
		signature.QuestionsHash,
		pq.Array(signature.Questions),
		pq.Array(signature.Answers),
		signature.Signature,
		time.Now())

	if err != nil {
		fmt.Println(err.Error())
		return err
	}

	return nil
}

func (store *PostgresStore) GetSignature(targetSignature string, userId int) (*models.Signature, error) {
	query := `
        SELECT signature_id, user_id, questions_hash, questions, answers, signature, finished_at
        FROM signatures
        WHERE signature = $1 AND user_id = $2
    `

	var signature models.Signature
	err := store.database.QueryRow(query, targetSignature, userId).Scan(
		&signature.Id,
		&signature.UserId,
		&signature.QuestionsHash,
		pq.Array(&signature.Questions),
		pq.Array(&signature.Answers),
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

func (store *PostgresStore) SignatureExists(questionsHash string, userId int) (bool, error) {
	query := `
        SELECT signature_id
        FROM signatures
        WHERE user_id = $1 AND questions_hash = $2
    `

	var signature models.Signature
	err := store.database.QueryRow(query, userId, questionsHash).Scan(&signature.Id)

	if err != nil {
		if err == sql.ErrNoRows {
			return false, nil
		}
		return false, err
	}

	return true, nil
}

func (store *PostgresStore) GetUser(email string) (*models.User, error) {
	query := `
        SELECT id, email, password, salt
        FROM users
        WHERE email = $1
    `

	var user models.User
	err := store.database.QueryRow(query, email).Scan(&user.Id, &user.Email, &user.Password, &user.Salt)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}

	return &user, nil
}

func (store *PostgresStore) GetUserByEmail(email string) (*models.User, error) {
	query := `
        SELECT email, password
        FROM users
        WHERE email = $1 AND password = $2
    `

	var user models.User
	err := store.database.QueryRow(query, email).Scan(&email)

	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}

	return &user, nil
}
