package main

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
	"golang.org/x/oauth2/jwt"
	"io"
	"io/ioutil"
	"net/http"
	"net/url"
)

const defaultGrantType = "urn:ietf:params:oauth:grant-type:jwt-bearer"
const tokenURL = "https://www.googleapis.com/oauth2/v4/token"

func signJWTForIdToken(cfg *jwt.Config, audience string) (string, error) {
	claims := claims(cfg.Email, tokenURL, audience)
	block, _ := pem.Decode(cfg.PrivateKey)
	if block.Type != "PRIVATE KEY" {
		return "", fmt.Errorf("unknown key file: %s", block.Type)
	}
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return "", err
	}

	return sign(claims, key)
}

func idTokenImpl(signedJWT string) (string, error) {
	v := url.Values{}
	v.Set("grant_type", defaultGrantType)
	v.Set("assertion", signedJWT)
	resp, err := http.PostForm(tokenURL, v)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	body, err := ioutil.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return "", fmt.Errorf("oauth2: cannot fetch token: %v", err)
	}
	if c := resp.StatusCode; c < 200 || c > 299 {
		return "", &oauth2.RetrieveError{
			Response: resp,
			Body:     body,
		}
	}
	// tokenRes is the JSON response body.
	var tokenRes struct {
		AccessToken string `json:"access_token"`
		TokenType   string `json:"token_type"`
		IDToken     string `json:"id_token"`
		ExpiresIn   int64  `json:"expires_in"` // relative seconds from now
	}
	if err := json.Unmarshal(body, &tokenRes); err != nil {
		return "", fmt.Errorf("oauth2: cannot fetch token: %v", err)
	}
	return tokenRes.IDToken, nil

}

func jwtAccessTokenSource(json []byte, audience string) (oauth2.TokenSource, error) {
	config, err := google.JWTAccessTokenSourceFromJSON(json, audience)
	if err != nil {
		return nil, err
	}
	return config, nil
}

func jwtConfigTokenSource(ctx context.Context, json []byte, scopes ...string) (oauth2.TokenSource, error) {
	config, err := google.JWTConfigFromJSON(json, scopes...)
	if err != nil {
		return nil, err
	}
	return config.TokenSource(ctx), err
}
