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