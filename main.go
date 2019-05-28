package main

import (
	"context"
	"flag"
	"fmt"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"
	"strings"
)

var defaultScopes = []string{
	"https://www.googleapis.com/auth/cloud-platform",
	"https://www.googleapis.com/auth/userinfo.email",
}

const scopePrefix = "https://www.googleapis.com/auth/"

func toName(serviceAccount string) string {
	return "projects/-/serviceAccounts/" + serviceAccount
}

func toNames(serviceAccounts []string) []string {
	var slice []string
	for _, s := range serviceAccounts {
		slice = append(slice, toName(s))
	}
	return slice
}

func main() {
	var err error

	// token types
	var accessToken = flag.Bool("access-token", false, "Use access token")
	var idToken = flag.Bool("id-token", false, "Use ID token")
	var jwt = flag.Bool("jwt", false, "Use JWT")

	// token sources
	var keyFile = flag.String("key-file", "", "Service Account JSON Key")
	var gcloud = flag.Bool("gcloud", false, "gcloud default account")
	var gcloudAccount = flag.String("gcloud-account", "", "gcloud registered account(implies --gcloud)")
	var adc = flag.Bool("adc", false, "Use Application Default Credentials")

	// impersonate chain
	var impersonateServiceAccount stringsType
	flag.Var(&impersonateServiceAccount, "impersonate-service-account", "Specify delegate chain(near to far order). Implies --gcloud")

	// action
	var printToken = flag.Bool("print-token", false, "Print token")
	var tokenInfo = flag.Bool("token-info", false, "Print token info")
	var decodeTokenFlag = flag.Bool("decode-token", false, "Print local decoded token")

	// id token option
	var audience = flag.String("audience", "", "Audience")

	// access token option
	var rawScopes stringsType
	flag.Var(&rawScopes, "scopes", "Scopes")

	flag.Parse()

	delegateChain, serviceAccount := splitInitLast(impersonateServiceAccount)

	ctx := context.Background()

	// --gcloud-account implies --gcloud
	if *gcloudAccount != "" {
		*gcloud = true
	}

	keyEnv := os.Getenv("GOOGLE_APPLICATION_CREDENTIALS")

	var tokenString string
	switch {
	case countTrue(*idToken, *accessToken, *jwt) == 0:
		log.Fatalln("--id-token or --access-token or --jwt is required")
	case countTrue(*idToken, *accessToken, *jwt) > 1:
		log.Fatalln("--id-token and --access-token and --jwt are exclusive")
	case countTrue(*gcloud, *adc, *keyFile != "", keyEnv != "") == 0:
		log.Fatalln("credential source is required")
	case countTrue(*gcloud, *adc, *keyFile != "") > 1:
		log.Fatalln("credential source are exclusive")
	case *idToken && serviceAccount != "" && *audience == "":
		log.Fatalln("--audience is required when --id-token is used")
	case *idToken && len(rawScopes) != 0:
		log.Fatalln("--id-token and --scopes are exclusive")
	case *accessToken && *audience != "":
		log.Fatalln("--access-token and --audience are exclusive")
	case *printToken && *tokenInfo:
		log.Fatalln("--print-token and --token-info are exclusive")
	case (*printToken || *tokenInfo) && flag.NArg() > 0:
		log.Fatalln("remaining argument is not permitted when --print-token or --token-info")
	}

	var scopes []string
	for _, s := range rawScopes {
		if !strings.HasPrefix(s, scopePrefix) {
			s = scopePrefix + s
		}
		scopes = append(scopes, s)
	}

	if len(scopes) == 0 {
		scopes = defaultScopes
	}

	var tokenSource TokenSource
	switch {
	case *gcloud:
		tokenSource, err = newGcloudTokenSource(*gcloudAccount)
	case *keyFile != "":
		tokenSource, err = newKeyFileTokenSourceFromFile(*keyFile)
	case keyEnv != "":
		tokenSource, err = newKeyFileTokenSourceFromFile(keyEnv)
	default:
		tokenSource, err = google.DefaultTokenSource(ctx, scopes...)
	}

	if serviceAccount != "" {
		tokenSource = newImpersonateTokenSource(tokenSource, serviceAccount, delegateChain...)
	}
	if err != nil {
		log.Fatalln(err)
	}

	switch {
	case *idToken:
		tokenString, err = IDToken(ctx, tokenSource, *audience)
	case *accessToken:
		tokenString, err = AccessToken(ctx, tokenSource, scopes...)
	case *jwt:
		tokenString, err = JWTToken(ctx, tokenSource, *audience)
	default:
		log.Fatalln("unknown branch")
	}

	if err != nil {
		log.Fatalln(err)
	}

	switch {
	case *decodeTokenFlag && *accessToken:
		log.Println("--access-token can't work with --decode-token, fallback to --token-info")
		*tokenInfo = true
		*decodeTokenFlag = false
	case *tokenInfo && *jwt:
		log.Println("--jwt can't work with --token-info, fallback to --decode-token")
		*tokenInfo = false
		*decodeTokenFlag = true
	}

	if *printToken {
		fmt.Println(tokenString)
		return
	}

	if *tokenInfo {
		var resp *http.Response
		if *idToken {
			resp, err = http.Get("https://www.googleapis.com/oauth2/v3/tokeninfo?id_token=" + tokenString)
		} else {
			resp, err = http.Get("https://www.googleapis.com/oauth2/v3/tokeninfo?access_token=" + tokenString)
		}
		if err != nil {
			log.Fatalln(err)
		}
		_, err = io.Copy(os.Stdout, resp.Body)
		if err != nil {
			log.Fatalln(err)
		}
		return
	}

	if *decodeTokenFlag {
		var b []byte
		b, err = decodeToken(tokenString)
		if err != nil {
			log.Fatalln(err)
		}
		fmt.Println(string(b))
		return
	}

	var args []string
	args = append(args, "-H", fmt.Sprintf("Authorization: Bearer %s", tokenString))
	args = append(args, flag.Args()...)
	cmd := exec.Command("curl", args...)
	cmd.Stderr = os.Stderr
	cmd.Stdout = os.Stdout
	cmd.Stdin = os.Stdin
	err = cmd.Run()
	if err != nil {
		log.Fatalln(err)
	}
}

func getAccessToken(tokenSource oauth2.TokenSource) (string, error) {
	token, err := tokenSource.Token()
	if err != nil {
		return "", err
	}
	return token.AccessToken, nil
}
