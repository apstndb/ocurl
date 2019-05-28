package main

import (
	"encoding/json"
	"github.com/dgrijalva/jwt-go"
	"time"
)

func sign(claims jwt.Claims, key interface{}) (string, error) {
	return jwt.NewWithClaims(jwt.SigningMethodRS256, claims).SignedString(key)
}

func claims(account string, audience string, targetAudience string) jwt.Claims {
	now := time.Now().UTC()
	claims := jwt.MapClaims{
		"iss": account,
		"sub": account,
		"aud": audience,
		"iat": now.Unix(),
		"exp": now.Add(time.Hour).Unix(),
	}
	if targetAudience != "" {
		claims["target_audience"] = targetAudience
	}
	return claims
}

func decodeToken(tokenString string) ([]byte, error) {
	token, _, err := new(jwt.Parser).ParseUnverified(tokenString, jwt.MapClaims{})
	if err != nil {
		return nil, err
	}
	b, err := json.MarshalIndent(&token.Claims, "", "  ")
	if err != nil {
		return nil, err
	}

	return b, nil
}
