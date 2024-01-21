package middleware

import (
	"fmt"
	"net/http"

	"github.com/evlian/TestSigner/internal/app/utils"
)

func Authorize(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	tokenString := r.Header.Get("Authorization")
	if tokenString == "" {
		w.WriteHeader(http.StatusUnauthorized)
		fmt.Fprint(w, "missing authorization header")
		return
	}
	tokenString = tokenString[len("Bearer "):]

	err := utils.VerifyToken(tokenString)
	if err != nil {
		w.WriteHeader(http.StatusUnauthorized)
		fmt.Fprint(w, "invalid token")
		return
	}
}
