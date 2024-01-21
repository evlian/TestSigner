package utils

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"
)

var (
	secretKey = []byte("secret -key")
)

func CreateToken(userId string) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256,
		jwt.MapClaims{
			"user_id": userId,
			"exp":     time.Now().Add(time.Hour * 24).Unix(),
		})
	tokenString, err := token.SignedString(secretKey)
	if err != nil {
		return "", nil
	}
	return tokenString, nil
}

func GetUserIdFromClaims(tokenString string) (string, error) {
	// Parse the token
	if strings.HasPrefix(tokenString, "Bearer ") {
		tokenString = tokenString[len("Bearer "):]
	}

	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		return secretKey, nil
	})

	if err != nil {
		fmt.Print(err.Error())

		return "", err
	}

	// Check if the token is valid
	if !token.Valid {

		return "", fmt.Errorf("Invalid token")
	}

	// Type-assert the claims to jwt.MapClaims
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {

		return "", fmt.Errorf("Invalid claims type")
	}

	// Extract the user_id from claims
	userID, ok := claims["user_id"].(string)
	if !ok {
		return "", fmt.Errorf("user_id not found in claims")
	}

	return userID, nil
}

func VerifyToken(tokenString string) error {
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		return secretKey, nil
	})
	if err != nil {
		return err
	}
	if !token.Valid {
		return fmt.Errorf("invalid token")
	}
	return nil
}

func HashPassword(password, salt string) (string, error) {
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password+salt), bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}
	return string(hashedPassword), nil
}

func VerifyPassword(hashedPassword, inputPassword, salt string) error {
	// Combine input password and salt, then compare with the hashed password
	err := bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(inputPassword+salt))
	if err != nil {
		return fmt.Errorf("invalid password")
	}
	return nil
}

func GenerateSalt() (string, error) {
	saltBytes := make([]byte, 16)
	_, err := rand.Read(saltBytes)
	if err != nil {
		return "", err
	}

	salt := hex.EncodeToString(saltBytes)

	return salt, nil
}
