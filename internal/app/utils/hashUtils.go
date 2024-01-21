package utils

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
)

func GenerateHash(rawText string) string {
	questionsJSON, err := json.Marshal(rawText)
	if err != nil {
		fmt.Println("Error:", err)
		return ""
	}

	hash := sha256.New()
	hash.Write(questionsJSON)
	hashBytes := hash.Sum(nil)

	result := hex.EncodeToString(hashBytes)

	return result
}
