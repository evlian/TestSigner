evlian
evlianm
Do Not Disturb

evlian — 01/10/2024 1:55 AM
hajt assets
Donut🍩 — 01/10/2024 1:55 AM
Image
nuk o .sln
evlian — 01/10/2024 1:56 AM
hajt shko te assets
qo ss
Donut🍩 — 01/10/2024 1:57 AM
o plot folders
jon
evlian — 01/10/2024 1:57 AM
a jne krejt dmth
Donut🍩 — 01/10/2024 1:57 AM
kto te unity po
amo jo te c#
evlian — 01/10/2024 1:58 AM
e scripts
Donut🍩 — 01/10/2024 1:58 AM
projects
project
joska
mu nal llaptopi
evlian — 01/10/2024 1:58 AM
scripts folder nuk ka?
Donut🍩 — 01/10/2024 1:58 AM
per bateri
nuk pat nese nuk gaboj
evlian — 01/10/2024 1:58 AM
gabon ti valla
shpesh
Donut🍩 — 01/10/2024 1:59 AM
shnosh bebe
se mu nal
w kqyrem neser
evlian — 01/10/2024 1:59 AM
oki
Donut🍩 — 01/10/2024 1:59 AM
se sun po qona
se krejt fjet
evlian — 01/10/2024 1:59 AM
neser e ndreqim
Donut🍩 — 01/10/2024 1:59 AM
u bo
snap
evlian — 01/10/2024 3:01 PM
Attachment file type: code
Invaders.sln
917 bytes
Attachment file type: unknown
Assembly-CSharp.csproj
72.06 KB
evlian
 started a call that lasted a few seconds.
 — 01/18/2024 11:48 PM
evlian — 01/18/2024 11:48 PM
1 sec
Donut🍩 — 01/18/2024 11:48 PM
oki
evlian
 started a call that lasted 2 hours.
 — 01/18/2024 11:49 PM
evlian — 01/18/2024 11:49 PM
qele
mut
evlian — 01/19/2024 12:05 AM
SPARQL 
Protocol 
and 
RDF 
Query 
Language 
Donut🍩 — 01/19/2024 12:13 AM
rejhanja o qetu just so you know
evlian — 01/19/2024 12:14 AM
a o tu mni a
Donut🍩 — 01/19/2024 12:14 AM
po
evlian — 01/19/2024 12:14 AM
ahahahahah
budall
tregom ma heret
Donut🍩 — 01/19/2024 12:14 AM
hahhhahahaah sorry i thought u knew
evlian — 01/19/2024 12:14 AM
a thash najsen a
Donut🍩 — 01/19/2024 12:14 AM
jo
evlian — 01/19/2024 12:14 AM
oki good
Donut🍩
 started a call that lasted 2 hours.
 — Yesterday at 1:51 AM
Donut🍩 — 01/19/2024 1:52 AM
ej
evlian — Yesterday at 6:25 PM
```
# Unattended Programming Test: The Test Signer

# Task

The Test signer is a service that accepts a set of answers and questions and signs that the user has finished the " test " at this point in time. The signatures are stored and can later be verified by a different service.
Expand
message.txt
3 KB
Donut🍩 — Yesterday at 7:51 PM
version: '3'

services:
  postgres:
    image: postgres
    container_name: postgres
Expand
docker-compose.yml
1 KB
Donut🍩 — Yesterday at 8:26 PM
CREATE TABLE IF NOT EXISTS signatures (
    UserId SERIAL PRIMARY KEY,
    QuestionsHash VARCHAR(255),
    AnswersHash VARCHAR(255),
    Questions TEXT,
    Answers TEXT,
    Signature VARCHAR(255)
);
createTableQuery := `
        CREATE TABLE IF NOT EXISTS signatures (
            UserID SERIAL PRIMARY KEY,
            QuestionsHash VARCHAR(255),
            AnswersHash VARCHAR(255),
            Questions TEXT,
            Answers TEXT,
            Signature VARCHAR(255)
        );
    `
Donut🍩 — Yesterday at 9:59 PM
https://github.com/cheildo/jwt-auth-golang
GitHub
GitHub - cheildo/jwt-auth-golang: Simple implementation of JWT auth...
Simple implementation of JWT authentication. Contribute to cheildo/jwt-auth-golang development by creating an account on GitHub.
GitHub - cheildo/jwt-auth-golang: Simple implementation of JWT auth...
Donut🍩 — Yesterday at 10:14 PM
https://github.com/techagentng/GoAuth-JWT/tree/main
GitHub
GitHub - techagentng/GoAuth-JWT: A simple login and register using ...
A simple login and register using golang and jwt. Contribute to techagentng/GoAuth-JWT development by creating an account on GitHub.
GitHub - techagentng/GoAuth-JWT: A simple login and register using ...
https://github.com/PanutV/Golang-image-store-with-JWT-Login-Register/blob/main/controller/authController.go
GitHub
Golang-image-store-with-JWT-Login-Register/controller/authControlle...
Create Image store API along side Register/Login system by JWT auth with Golang - PanutV/Golang-image-store-with-JWT-Login-Register
Golang-image-store-with-JWT-Login-Register/controller/authControlle...
Donut🍩 — Yesterday at 10:32 PM
package login

import (
    "encoding/json"
    "fmt"
    "net/http"
    "golang.org/x/crypto/bcrypt"
)

type User struct {
    Username string `json:"username"`
    Password string `json:"password"`
    Salt     string `json:"salt"`
}

func RegisterHandler(w http.ResponseWriter, r *http.Request) {
    w.Header().Set("Content-Type", "application/json")

    var u User
    json.NewDecoder(r.Body).Decode(&u)

    // Generate a random salt
    salt, err := generateSalt()
    if err != nil {
        w.WriteHeader(http.StatusInternalServerError)
        fmt.Fprint(w, "Error generating salt")
        return
    }
    u.Salt = salt

    // Hash the password with the salt
    hashedPassword, err := hashPassword(u.Password, u.Salt)
    if err != nil {
        w.WriteHeader(http.StatusInternalServerError)
        fmt.Fprint(w, "Error hashing password")
        return
    }
    u.Password = hashedPassword

    // Store the user information (you should implement your own storage logic here)

    w.WriteHeader(http.StatusCreated)
    fmt.Fprint(w, "User registered successfully")
}

func generateSalt() (string, error) {
    // Implement logic to generate a random salt (you can use crypto/rand package)
    // For simplicity, let's use a static salt in this example.
    return "static_salt", nil
}

func hashPassword(password, salt string) (string, error) {
    // Combine password and salt, then hash using bcrypt
    hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password+salt), bcrypt.DefaultCost)
    if err != nil {
        return "", err
    }
    return string(hashedPassword), nil
}
package login

import (
    "crypto/rand"
    "encoding/hex"
    "fmt"
)

func generateSalt() (string, error) {
    // Generate a random byte slice to be used as a salt
    saltBytes := make([]byte, 16)
    _, err := rand.Read(saltBytes)
    if err != nil {
        return "", err
    }

    // Convert the byte slice to a hexadecimal string
    salt := hex.EncodeToString(saltBytes)

    return salt, nil
}
Donut🍩 — Yesterday at 11:49 PM
func verifyPassword(hashedPassword, inputPassword, salt string) error {
    // Combine input password and salt, then compare with the hashed password
    err := bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(inputPassword+salt))
    if err != nil {
        return fmt.Errorf("invalid password")
    }
    return nil
}
err := verifyPassword(storedHashedPassword, u.Password, storedSalt)
        if err == nil {
            tokenString, err := CreateToken(u.Username)
            if err != nil {
                w.WriteHeader(http.StatusInternalServerError)
                fmt.Errorf("Error creating token")
                return
            }
            w.WriteHeader(http.StatusOK)
            fmt.Fprint(w, tokenString)
            return
        }
Donut🍩 — Today at 12:07 AM
// SignAnswers is a function for signing answers.
func (s *ApiServer) SignAnswers(userJWT string, questions, answers []AnswersDto) (string, error) {
    // Find the user in the database based on the provided JWT
    var user User
    err := s.Db.Get(&user, "SELECT * FROM users WHERE token = $1", userJWT)
    if err != nil {
        return "", fmt.Errorf("failed to find user: %v", err)
    }

    // Concatenate questions and answers to create signature
    var concatenatedAnswers string
    for _, ans := range answers {
        concatenatedAnswers += ans.Question + ans.Answer
    }

    // Calculate hash values for questions and answers using a simple hash function
    questionsHash := calculateSimpleHash(concatenatedAnswers)

    // Concatenate questions, answers, and user JWT to create a unique signature
    signatureData := fmt.Sprintf("%s:%v:%v", userJWT, questions, answers)
    signature := calculateSimpleHash(signatureData)

    // Get the current time as the FinishedAt timestamp
    finishedAt := time.Now()

    // Store the signature in the database
    _, err = s.Db.Exec(`
        INSERT INTO signatures (user_id, questions_hash, answers_hash, questions, answers, signature, finished_at)
        VALUES ($1, $2, $3, $4, $5, $6, $7)`,
        user.Id, questionsHash, calculateSimpleHash(concatenatedAnswers), questions, answers, signature, finishedAt)
    if err != nil {
        return "", fmt.Errorf("failed to store signature: %v", err)
    }

    return signature, nil
}

// Helper function to calculate simple hash using FNV-1a algorithm
func calculateSimpleHash(data string) string {
    hash := fnv.New32a()
    hash.Write([]byte(data))
    return fmt.Sprintf("%x", hash.Sum(nil))
}
import (
    "fmt"
    "hash/fnv"
    "github.com/jmoiron/sqlx"
    _ "github.com/lib/pq"
    "time"
)
func (s *ApiServer) handleSignAnswers(writer http.ResponseWriter, request *http.Request) error {
    if request.Method != "POST" {
        return fmt.Errorf("method not allowed %s", request.Method)
    }

    // Assuming you have an authorization function
    Authorize(writer, request)

    var loginRequest LoginRequest
    if err := json.NewDecoder(request.Body).Decode(&loginRequest); err != nil {
        return fmt.Errorf("failed to decode request body: %v", err)
    }

    // Perform the signing of answers using the provided data
    signature, err := s.SignAnswers(loginRequest.UserJWT, loginRequest.Questions, loginRequest.Answers)
    if err != nil {
        return fmt.Errorf("failed to sign answers: %v", err)
    }

    // Return the signature in the response
    response := map[string]string{"test_signature": signature}
    writer.Header().Set("Content-Type", "application/json")
    if err := json.NewEncoder(writer).Encode(response); err != nil {
        return fmt.Errorf("failed to encode response: %v", err)
    }

    return nil
}
Donut🍩 — Today at 12:22 AM
// handleVerifySignature is an HTTP handler for verifying a signature.
func (s *ApiServer) handleVerifySignature(writer http.ResponseWriter, request *http.Request) {
    var verifyRequest VerifyRequest
    if err := json.NewDecoder(request.Body).Decode(&verifyRequest); err != nil {
        http.Error(writer, fmt.Sprintf("failed to decode request body: %v", err), http.StatusInternalServerError)
        return
    }

    ok, answers, timestamp, err := s.VerifySignature(verifyRequest.User, verifyRequest.Signature)
    if err != nil {
        http.Error(writer, fmt.Sprintf("failed to verify signature: %v", err), http.StatusInternalServerError)
        return
    }

    response := map[string]interface{}{
        "status":    "OK",
        "answers":   answers,
        "timestamp": timestamp,
        "valid":     ok,
    }

    writer.Header().Set("Content-Type", "application/json")
    if err := json.NewEncoder(writer).Encode(response); err != nil {
        http.Error(writer, fmt.Sprintf("failed to encode response: %v", err), http.StatusInternalServerError)
        return
    }
}
type VerifyRequest struct {
    User     int    `json:"user"`
    Signature string `json:"signature"`
}
// VerifySignature is a function for verifying a signature.
func (s *ApiServer) VerifySignature(userID int, signature string) (bool, []AnswersDto, time.Time, error) {
    // Check if the user with the provided ID exists
    var user User
    err := s.Db.Get(&user, "SELECT * FROM users WHERE id = $1", userID)
    if err != nil {
        return false, nil, time.Time{}, fmt.Errorf("failed to find user: %v", err)
    }

    // Check if the signature of the user matches the provided signature
    if user.Signature != signature {
        return false, nil, time.Time{}, nil
    }

    // Retrieve the actual questions, answers, and timestamps from the database
    var storedData []struct {
        Question   string    `db:"question"`
        Answer     string    `db:"answer"`
        Timestamp  time.Time `db:"timestamp"`
    }

    err = s.Db.Select(&storedData, "SELECT question, answer, timestamp FROM user_answers WHERE user_id = $1", userID)
    if err != nil {
        return false, nil, time.Time{}, fmt.Errorf("failed to retrieve data from the database: %v", err)
    }

    // Convert the retrieved data to AnswersDto
    var storedAnswers []AnswersDto
    for _, data := range storedData {
        storedAnswers = append(storedAnswers, AnswersDto{
            Question: data.Question,
            Answer:   data.Answer,
        })
    }

    // Return the retrieved answers and timestamp
    return true, storedAnswers, storedData[0].Timestamp, nil
}
Donut🍩 — Today at 2:00 AM
# Test Signer Service

The Test Signer is a service written in Go that allows users to register, sign answers, and verify signatures. It uses PostgreSQL as the database for storing user information and signatures.

## Prerequisites
Make sure you have the following installed:
Expand
README.txt
3 KB
﻿
Donut🍩
edonah_
# Test Signer Service

The Test Signer is a service written in Go that allows users to register, sign answers, and verify signatures. It uses PostgreSQL as the database for storing user information and signatures.

## Prerequisites
Make sure you have the following installed:

- Go
- PostgreSQL

## Setup

1. Clone the repository:

   ```bash
   git clone <repository-url>
   cd test-signer-service
   ```

2. Install dependencies:

   ```bash
   go get
   ```

3. Set up the PostgreSQL database:

   - Create a PostgreSQL database and update the database connection details in the `config.json` file.

4. Build and run the application:

   ```bash
   go build
   ./test-signer-service
   ```

   The service should now be running on `http://localhost:8080`.

## Usage

### 1. Register User

Send a POST request to register a new user:

```bash
curl -X POST -H "Content-Type: application/json" -d '{"email": "user@example.com", "password": "password123"}' http://localhost:3000/register
```

### 2. Login

Send a POST request to login and obtain a bearer token:

```bash
curl -X POST -H "Content-Type: application/json" -d '{"email": "user@example.com", "password": "password123"}' http://localhost:3000/login
```
Copy the `token` from the response.

### 3. Sign Answers

Send a POST request to sign answers using the obtained bearer token:

```bash
curl -X POST -H "Content-Type: application/json" -H "Authorization: Bearer <token>" -d '{"answers": [{"question": "Q1", "answer": "A1"}, {"question": "Q2", "answer": "A2"}]}' http://localhost:3000/sign-answers
```

### 4. Verify Signature

Send a POST request to verify a signature:

```bash
curl -X POST -H "Content-Type: application/json" -H "Authorization: Bearer <token>" -d '{"userId": <userId>, "signature": "<signature>"}' http://localhost:3000/verify-signature
```

Replace `<token>`, `<userId>`, and `<signature>` with the actual values obtained during the login and sign process.

## Additional Information

- This project uses PostgreSQL as the database.
```
README.txt
3 KB