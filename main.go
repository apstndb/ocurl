package main

import (
	"bytes"
	"context"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"
	"strings"

	"golang.org/x/oauth2/google"
	"google.golang.org/api/iamcredentials/v1"
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

func GcloudIdToken() (string, error) {
	var buf bytes.Buffer

	cmd := exec.Command("gcloud", "config", "config-helper", "--format=value(credential.id_token)",  "--force-auth-refresh")
	cmd.Stdout = &buf
	err := cmd.Run()
	if err != nil {
		return "", err
	}

	return strings.TrimSpace(buf.String()), nil
}

func main() {
	var err error
	var rawScopes stringsType
	flag.Var(&rawScopes, "scopes", "Scopes")
	var impersonateServiceAccount stringsType
	flag.Var(&impersonateServiceAccount, "impersonate-service-account", "Delegates")
	var printToken = flag.Bool("print-token", false, "Print token")
	var accessToken = flag.Bool("access-token", false, "Use access token")
	var audience = flag.String("audience", "", "Audience")
	var idToken = flag.Bool("id-token", false, "Use ID token")
	var tokenInfo = flag.Bool("token-info", false, "Print token info")
	flag.Parse()

	var serviceAccount string
	var delegateChain []string
	if len(impersonateServiceAccount) > 0 {
		serviceAccount = impersonateServiceAccount[len(impersonateServiceAccount)-1]
		delegateChain = impersonateServiceAccount[:len(impersonateServiceAccount)-1]
	}
	ctx := context.Background()

	var tokenString string
	switch {
	case *idToken && *accessToken:
		log.Fatalln("--id-token and --access-token are exclusive")
	case *idToken && serviceAccount != "" && *audience == "":
		log.Fatalln("--audience is required when --id-token is used")
	case !*idToken && !*accessToken:
		log.Fatalln("--id-token or --access-token are required")
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

	switch {
	case *idToken && serviceAccount == "":
		log.Println("--service-account is missing. Use experimental gcloud ID token.")
		tokenString, err = GcloudIdToken()
	case *idToken && serviceAccount != "":
		tokenString, err = ImpersonateIdToken(ctx, serviceAccount, delegateChain, audience)
	case *accessToken && serviceAccount == "":
		tokenString, err = DefaultAccessToken(ctx)
	case *accessToken && serviceAccount != "":
		tokenString, err = ImpersonateAccessToken(ctx, serviceAccount, delegateChain, scopes)
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
		if *accessToken {
			resp, err = http.Get("https://www.googleapis.com/oauth2/v3/tokeninfo?access_token=" + tokenString)
		} else {
			resp, err = http.Get("https://www.googleapis.com/oauth2/v3/tokeninfo?id_token=" + tokenString)
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

func DefaultAccessToken(ctx context.Context) (string, error) {
	tokenSource, err := google.DefaultTokenSource(ctx, defaultScope...)
	if err != nil {
		return "", err
	}
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

func ImpersonateIdToken(ctx context.Context, serviceAccount string, delegateChain []string, audience *string) (string, error) {
	service, err := iamcredentials.NewService(ctx)
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

func ImpersonateAccessToken(ctx context.Context, serviceAccount string, delegateChain []string, scopes []string) (string, error) {
	service, err := iamcredentials.NewService(ctx)
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
