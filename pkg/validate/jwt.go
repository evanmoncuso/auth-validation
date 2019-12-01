package validate

import (
	"errors"
	"fmt"
	"net/http"

	jwt "github.com/dgrijalva/jwt-go"
	"github.com/gomodule/redigo/redis"
)

// InvalidTokenStore is a global connection to the redis store for token checking
var InvalidTokenStore *redis.Pool

// TokenSecret is the secret with which to decode the jwt
var TokenSecret []byte

// Initialize handles all DB and application specific setup work for the package
func Initialize(redisURL, tokenSecret string) error {
	if redisURL == "" {
		return errors.New("No token store connection url")
	} else if tokenSecret == "" {
		return errors.New("No token secret included")
	}

	// connect to invalidation store
	InvalidTokenStore = connectToRedis(redisURL)

	// remember that token secret
	TokenSecret = []byte(tokenSecret)

	fmt.Println("Validation initialized...")

	return nil
}

// AuthenticateRoute is the middleware that allows valid requests through, and 401s invalid requests
func AuthenticateRoute(next http.Handler) http.Handler {
	return http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
		// get token from headers
		tokenString := req.Header.Get("Authorization")

		if len(tokenString) <= 7 {
			http.Error(res, "Authorization is not set", http.StatusBadRequest)
			return
		}

		tokenString = tokenString[7:]

		// check token for validity
		valid, err := validateToken(tokenString)
		if !valid {
			http.Error(res, "Token is Invalid", http.StatusUnauthorized)
			return
		} else if err != nil {
			http.Error(res, err.Error(), http.StatusUnauthorized)
			return
		}

		// check if token has been invalidated manually
		err = checkForInvalidToken(tokenString)
		if err != nil {
			http.Error(res, err.Error(), http.StatusUnauthorized)
			return
		}

		// TODO refresh the token?
		res.Header().Set("x-token-checked", "true")
		// continue
		next.ServeHTTP(res, req)
	})
}

func parseToken(tokenString string) (*jwt.Token, error) {
	sb := []byte(TokenSecret)

	return jwt.ParseWithClaims(tokenString, &jwt.StandardClaims{}, func(token *jwt.Token) (interface{}, error) {
		return sb, nil
	})
}

// ValidateToken is the checker for whather a token is valid
func validateToken(tokenString string) (bool, error) {
	_, err := parseToken(tokenString)

	// I'm not interested in getting any of the information off the jwt, just verification and expiration
	if err != nil {
		return false, err
	}

	return true, nil
}
