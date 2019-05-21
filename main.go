package main

import (
	"context"
	"flag"
	"fmt"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
	"golang.org/x/oauth2/jws"
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

type stringsType []string

var defaultScope = []string{
	"https://www.googleapis.com/auth/cloud-platform",
	"https://www.googleapis.com/auth/userinfo.email",
}

func (ss *stringsType) String() string {
	return fmt.Sprintf("%v", *ss)
}

const authPrefix = "https://www.googleapis.com/auth/"

func (ss *stringsType) Set(v string) error {
	for _, scope := range strings.Split(v, ",") {
		*ss = append(*ss, scope)
	}
	return nil
}

func firstNotEmpty(ss ...string) string {
	for _, s := range ss {
		if s != "" {
			return s
		}
	}
	return ""
}

func countTrue(bools ...bool) int {
	count := 0
	for _, b := range bools {
		if b{
			count++
		}
	}
	return count
}

func main() {
	var err error
	var rawScopes stringsType
	flag.Var(&rawScopes, "scopes", "Scopes")
	var impersonateServiceAccount stringsType
	flag.Var(&impersonateServiceAccount, "impersonate-service-account", "Delegates")
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

	serviceAccount, delegateChain := processImpersonateServiceAccount(impersonateServiceAccount)

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
	}

	var scopes []string
	for _, s := range rawScopes {
		if !strings.HasPrefix(s, authPrefix) {
			s = authPrefix + s
		}
		scopes = append(scopes, s)
	}

	if len(scopes) == 0 {
		scopes = defaultScope
	}

	if *gcloudAccount != "" {
		*gcloud = true
	}

	var tokenSource oauth2.TokenSource
	switch {
	case *gcloud:
		tokenSource, err = NewGcloudTokenSource(*gcloudAccount)
	case *jwt && serviceAccount == "":
		actualKeyFile := firstNotEmpty(*keyFile, os.Getenv("GOOGLE_APPLICATION_CREDENTIALS"))
		tokenSource, err = KeyFileJWTTokenSource(actualKeyFile, *audience)
	case *keyFile != "":
		tokenSource, err = KeyFileTokenSource(ctx, *keyFile, scopes)
	default:
		tokenSource, err = google.DefaultTokenSource(ctx, scopes...)
	}

	if err != nil {
		log.Fatalln(err)
	}

	log.Println("tokenSource is created")

	switch {
	case *idToken && *gcloud:
		log.Println("Use experimental gcloud ID token.")
		tokenString, err = GcloudIdToken(*gcloudAccount)
	case *idToken && serviceAccount != "":
		tokenString, err = ImpersonateIdToken(ctx, tokenSource, serviceAccount, delegateChain, audience)
	case *accessToken && serviceAccount != "":
		tokenString, err = ImpersonateAccessToken(ctx, tokenSource, serviceAccount, delegateChain, scopes)
	case *accessToken:
		tokenString, err = GetAccessToken(tokenSource)
	case *jwt && serviceAccount != "":
		tokenString, err = GetAccessToken(tokenSource)
	case *jwt:
		tokenString, err = GetAccessToken(tokenSource)
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
		io.Copy(os.Stdout, resp.Body)
		return
	}

	var args []string
	args = append(args, "-H", fmt.Sprintf("Authorization: Bearer %s", tokenString))
	args = append(args, flag.Args()...)
	cmd := exec.Command("curl", args...)
	cmd.Stderr = os.Stderr
	cmd.Stdout = os.Stdout
	err = cmd.Run()
	if err != nil {
		log.Fatalln(err)
	}
}

func processImpersonateServiceAccount(impersonateServiceAccount []string) (string, []string) {
	var serviceAccount string
	var delegateChain []string
	if len(impersonateServiceAccount) > 0 {
		serviceAccount = impersonateServiceAccount[len(impersonateServiceAccount)-1]
		delegateChain = impersonateServiceAccount[:len(impersonateServiceAccount)-1]
	}
	return serviceAccount, delegateChain
}

func KeyFileJWTTokenSource(keyFile string, audience string) (oauth2.TokenSource, error) {
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


func KeyFileTokenSource(ctx context.Context, keyFile string, scope []string) (oauth2.TokenSource, error) {
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

func GetAccessToken(tokenSource oauth2.TokenSource) (string, error) {
	token, err := tokenSource.Token()
	if err != nil {
		return "", err
	}
	return token.AccessToken, nil
}

func toName(serviceAccount string) string {
	return "projects/-/serviceAccounts/" + serviceAccount
}

func toNameSlice(serviceAccounts []string) []string {
	var slice []string
	for _, s := range serviceAccounts {
		slice = append(slice, toName(s))
	}
	return slice
}

func ImpersonateIdToken(ctx context.Context, tokenSource oauth2.TokenSource, serviceAccount string, delegateChain []string, audience *string) (string, error) {
	service, err := iamcredentials.NewService(ctx, option.WithTokenSource(tokenSource))
	if err != nil {
		return "", err
	}
	projectsService := iamcredentials.NewProjectsService(service)

	response, err := projectsService.ServiceAccounts.GenerateIdToken(toName(serviceAccount),
		&iamcredentials.GenerateIdTokenRequest{
			Audience:     *audience,
			Delegates: toNameSlice(delegateChain),
			IncludeEmail: true,
		}).Do()
	if err != nil {
		return "", err
	}
	return response.Token, nil
}

func ImpersonateAccessToken(ctx context.Context, tokenSource oauth2.TokenSource, serviceAccount string, delegateChain []string, scopes []string) (string, error) {
	service, err := iamcredentials.NewService(ctx, option.WithTokenSource(tokenSource))
	if err != nil {
		return "", err
	}
	projectsService := iamcredentials.NewProjectsService(service)

	response, err := projectsService.ServiceAccounts.GenerateAccessToken(toName(serviceAccount),
		&iamcredentials.GenerateAccessTokenRequest{
			Scope: scopes,
			Delegates: toNameSlice(delegateChain),
		}).Do()
	if err != nil {
		return "", err
	}
	return response.AccessToken, nil
}

func ImpersonateJWT(ctx context.Context, tokenSource oauth2.TokenSource, serviceAccount string, delegateChain []string, claims jws.ClaimSet) (string, error) {
	service, err := iamcredentials.NewService(ctx, option.WithTokenSource(tokenSource))
	if err != nil {
		return "", err
	}
	projectsService := iamcredentials.NewProjectsService(service)

	response, err := projectsService.ServiceAccounts.SignJwt(toName(serviceAccount),
		&iamcredentials.SignJwtRequest{
			Delegates: toNameSlice(delegateChain),
			Payload: "",
		}).Do()
	if err != nil {
		return "", err
	}
	return response.SignedJwt, nil
}
