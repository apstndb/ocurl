package main

import (
	"context"
	"flag"
	"fmt"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
	"google.golang.org/api/iamcredentials/v1"
	"google.golang.org/api/option"
	"io"
	"io/ioutil"
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
	var rawScopes stringsType
	flag.Var(&rawScopes, "scopes", "Scopes")
	var impersonateServiceAccount stringsType
	flag.Var(&impersonateServiceAccount, "impersonate-service-account", "Specify delegate chain(near to far order). Implies --gcloud")
	var printToken = flag.Bool("print-token", false, "Print token")
	var keyFile = flag.String("key-file", "", "Service Account JSON Key")
	var gcloud = flag.Bool("gcloud", false, "gcloud default account")
	var gcloudAccount = flag.String("gcloud-account", "", "gcloud registered account")
	var accessToken = flag.Bool("access-token", false, "Use access token")
	var audience = flag.String("audience", "", "Audience")
	var idToken = flag.Bool("id-token", false, "Use ID token")
	var jwt = flag.Bool("jwt", false, "Use JWT")
	var tokenInfo = flag.Bool("token-info", false, "Print token info")
	flag.Parse()

	delegateChain, serviceAccount := splitInitLast(impersonateServiceAccount)

	ctx := context.Background()

	var tokenString string
	switch {
	case countTrue(*idToken, *accessToken, *jwt) == 0:
		log.Fatalln("--id-token or --access-token or --jwt is required")
	case countTrue(*idToken, *accessToken, *jwt) > 1:
		log.Fatalln("--id-token and --access-token and --jwt are exclusive")
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

	// --gcloud-account implies --gcloud
	if *gcloudAccount != "" {
		*gcloud = true
	}

	var tokenSource oauth2.TokenSource
	switch {
	case *gcloud:
		tokenSource, err = newGcloudTokenSource(*gcloudAccount)
	// jwt uses JWTAccessTokenSourceFromJSON if not impersonate
	case *jwt && serviceAccount == "":
		actualKeyFile := firstNotEmpty(*keyFile, os.Getenv("GOOGLE_APPLICATION_CREDENTIALS"))
		tokenSource, err = keyFileJWTTokenSource(actualKeyFile, *audience)
	// uses JWTConfig.TokenSource if keyFile is set
	case *keyFile != "":
		tokenSource, err = keyFileTokenSource(ctx, *keyFile, scopes)
	default:
		tokenSource, err = google.DefaultTokenSource(ctx, scopes...)
	}

	if err != nil {
		log.Fatalln(err)
	}

	switch {
	case *idToken && *gcloud:
		log.Println("Use experimental gcloud ID token.")
		tokenString, err = gcloudIdToken(*gcloudAccount)
	case *idToken && serviceAccount != "":
		tokenString, err = impersonateIdToken(ctx, tokenSource, serviceAccount, delegateChain, *audience)
	case *accessToken && serviceAccount != "":
		tokenString, err = impersonateAccessToken(ctx, tokenSource, serviceAccount, delegateChain, scopes)
	case *jwt && serviceAccount != "":
		tokenString, err = impersonateJWT(ctx, tokenSource, serviceAccount, delegateChain, claims(serviceAccount, *audience))
	case *accessToken, *jwt:
		tokenString, err = getAccessToken(tokenSource)
	default:
		log.Fatalln("unknown branch")
	}

	if err != nil {
		log.Fatalln(err)
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

func keyFileJWTTokenSource(keyFile string, audience string) (oauth2.TokenSource, error) {
	buf, err := ioutil.ReadFile(keyFile)
	if err != nil {
		return nil, err
	}
	config, err := google.JWTAccessTokenSourceFromJSON(buf, audience)
	if err != nil {
		return nil, err
	}
	return config, nil
}

func keyFileTokenSource(ctx context.Context, keyFile string, scope []string) (oauth2.TokenSource, error) {
	buf, err := ioutil.ReadFile(keyFile)
	if err != nil {
		return nil, err
	}
	config, err := google.JWTConfigFromJSON(buf, scope...)
	if err != nil {
		return nil, err
	}
	return config.TokenSource(ctx), err
}

func getAccessToken(tokenSource oauth2.TokenSource) (string, error) {
	token, err := tokenSource.Token()
	if err != nil {
		return "", err
	}
	return token.AccessToken, nil
}

func impersonateIdToken(ctx context.Context, tokenSource oauth2.TokenSource, serviceAccount string, delegateChain []string, audience string) (string, error) {
	service, err := iamcredentials.NewService(ctx, option.WithTokenSource(tokenSource))
	if err != nil {
		return "", err
	}
	projectsService := iamcredentials.NewProjectsService(service)

	response, err := projectsService.ServiceAccounts.GenerateIdToken(toName(serviceAccount),
		&iamcredentials.GenerateIdTokenRequest{
			Audience:     audience,
			Delegates:    toNames(delegateChain),
			IncludeEmail: true,
		}).Do()
	if err != nil {
		return "", err
	}
	return response.Token, nil
}

func impersonateAccessToken(ctx context.Context, tokenSource oauth2.TokenSource, serviceAccount string, delegateChain []string, scopes []string) (string, error) {
	service, err := iamcredentials.NewService(ctx, option.WithTokenSource(tokenSource))
	if err != nil {
		return "", err
	}
	projectsService := iamcredentials.NewProjectsService(service)

	response, err := projectsService.ServiceAccounts.GenerateAccessToken(toName(serviceAccount),
		&iamcredentials.GenerateAccessTokenRequest{
			Scope:     scopes,
			Delegates: toNames(delegateChain),
		}).Do()
	if err != nil {
		return "", err
	}
	return response.AccessToken, nil
}
