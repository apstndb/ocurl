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

type keyFileTokenSource struct {
	jsonKey []byte
	cfg     *jwt.Config
}

func newKeyFileTokenSourceFromFile(keyFile string) (*keyFileTokenSource, error) {
	buf, err := ioutil.ReadFile(keyFile)
	if err != nil {
		return nil, err
	}
	return newKeyFileTokenSource(buf)
}

func newKeyFileTokenSource(jsonKey []byte) (*keyFileTokenSource, error) {
	cfg, err := google.JWTConfigFromJSON(jsonKey)
	if err != nil {
		return nil, err
	}

	return &keyFileTokenSource{jsonKey: jsonKey, cfg: cfg}, nil
}

func (kfts *keyFileTokenSource) Email() string {
	return kfts.cfg.Email
}

func (kfts *keyFileTokenSource) Token() (*oauth2.Token, error) {
	token, err := kfts.cfg.TokenSource(context.Background()).Token()
	if err != nil {
		return nil, err
	}

	return token, nil
}

func (kfts *keyFileTokenSource) AccessToken(ctx context.Context, scopes ...string) (string, error) {
	tokenSource, err := jwtConfigTokenSource(ctx, kfts.jsonKey, scopes...)
	if err != nil {
		return "", err
	}

	token, err := tokenSource.Token()
	if err != nil {
		return "", err
	}

	return token.AccessToken, nil
}
const defaultGrantType = "urn:ietf:params:oauth:grant-type:jwt-bearer"
func (kfts *keyFileTokenSource) IDToken(ctx context.Context, audience string) (string, error) {
	tokenURL := "https://www.googleapis.com/oauth2/v4/token"
	claims := claims(kfts.Email(), tokenURL, audience)
	block, _ := pem.Decode(kfts.cfg.PrivateKey)
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return "", err
	}

	signedJWT, err := sign(claims, key)

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

func (kfts *keyFileTokenSource) JWTToken(ctx context.Context, audience string) (string, error) {
	ts, err := jwtAccessTokenSource(kfts.jsonKey, audience)
	if err != nil {
		return "", err
	}

	token, err := ts.Token()
	if err != nil {
		return "", err
	}
	return token.AccessToken, nil
}

func jwtAccessTokenSource(json []byte, audience string) (oauth2.TokenSource, error) {
	config, err := google.JWTAccessTokenSourceFromJSON(json, audience)
	if err != nil {
		return nil, err
	}
	return config, nil
}

func jwtAccessTokenSourceFromFile(keyFile string, audience string) (oauth2.TokenSource, error) {
	buf, err := ioutil.ReadFile(keyFile)
	if err != nil {
		return nil, err
	}
	return jwtAccessTokenSource(buf, audience)
}

func jwtConfigTokenSource(ctx context.Context, json []byte, scopes ...string) (oauth2.TokenSource, error) {
	config, err := google.JWTConfigFromJSON(json, scopes...)
	if err != nil {
		return nil, err
	}
	return config.TokenSource(ctx), err
}

func jwtConfigTokenSourceFromFile(ctx context.Context, keyFile string, scopes ...string) (oauth2.TokenSource, error) {
	buf, err := ioutil.ReadFile(keyFile)
	if err != nil {
		return nil, err
	}
	return jwtConfigTokenSource(ctx, buf, scopes...)
}
