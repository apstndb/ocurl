package main

import (
	"bytes"
	"context"
	"database/sql"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"
	"strings"

	_ "github.com/mattn/go-sqlite3"
	"golang.org/x/oauth2/google"
	"google.golang.org/api/iamcredentials/v1"
)

type scopesType []string

func (ss *scopesType) String() string {
	return fmt.Sprintf("%v", *ss)
}

func (ss *scopesType) Set(v string) error {
	for _, scope := range strings.Split(v, ",") {
		const authPrefix = "https://www.googleapis.com/auth/"
		if !strings.HasPrefix(scope, authPrefix) {
			scope = authPrefix + scope
		}
		*ss = append(*ss, scope)
	}
	return nil
}

func GcloudIdToken() (string, error) {
	var err error
	// reflesh token
	err = exec.Command("gcloud", "auth", "print-access-token").Run()
	if err != nil {
		return "", err
	}
	cmd := exec.Command("gcloud", "config", "get-value", "core/account")
	var buf bytes.Buffer
	cmd.Stdout = &buf
	err = cmd.Run()
	if err != nil {
		return "", err
	}
	email := strings.TrimSpace(buf.String())
	db, err := sql.Open("sqlite3", os.Getenv("HOME")+"/.config/gcloud/access_tokens.db")
	if err != nil {
		return "", err
	}
	defer db.Close()
	var tokenString string
	err = db.QueryRow(`SELECT id_token FROM access_tokens WHERE account_id = ?`, email).Scan(&tokenString)
	return tokenString, err
}

func main() {
	var err error
	var scopes scopesType
	flag.Var(&scopes, "scopes", "")
	var printToken = flag.Bool("print-token", false, "Print token")
	var accessToken = flag.Bool("access-token", false, "Use access token")
	var audience = flag.String("audience", "", "Audience")
	var idToken = flag.Bool("id-token", false, "Use ID token")
	var gcloudIdToken = flag.Bool("gcloud-id-token", false, "Use gcloud ID token")
	var serviceAccount = flag.String("service-account", "", "Service Account")
	var tokenInfo = flag.Bool("token-info", false, "Print token info")
	flag.Parse()

	ctx := context.Background()

	if len(scopes) == 0 {
		scopes = []string{"https://www.googleapis.com/auth/cloud-platform"}
	}

	var tokenString string
	if *gcloudIdToken {
		tokenString, err = GcloudIdToken()
		if err != nil {
			log.Fatalln(err)
		}
	}

	if *idToken {
		if *serviceAccount == "" {
			log.Fatalln("--service-account is required if --id-token")
		}
		tokenString, err = ImpersonateIdToken(ctx, *serviceAccount, audience)
		if err != nil {
			log.Fatalln(err)
		}
	}

	if *accessToken {
		if *serviceAccount == "" {
			tokenString, err = DefaultAccessToken(ctx)
			if err != nil {
				log.Fatalln(err)
			}
		} else {
			tokenString, err = ImpersonateAccessToken(ctx, *serviceAccount, scopes)
			if err != nil {
				log.Fatalln(err)
			}
		}
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
	tokenSource, err := google.DefaultTokenSource(ctx)
	if err != nil {
		log.Fatalln(err)
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

func ImpersonateIdToken(ctx context.Context, serviceAccount string, audience *string) (string, error) {
	service, err := iamcredentials.NewService(ctx)
	if err != nil {
		log.Fatalln(err)
	}
	projectsService := iamcredentials.NewProjectsService(service)

	response, err := projectsService.ServiceAccounts.GenerateIdToken(toName(serviceAccount),
		&iamcredentials.GenerateIdTokenRequest{
			Audience:     *audience,
			IncludeEmail: true,
		}).Do()
	if err != nil {
		return "", err
	}
	return response.Token, nil
}

func ImpersonateAccessToken(ctx context.Context, serviceAccount string, scopes []string) (string, error) {
	service, err := iamcredentials.NewService(ctx)
	if err != nil {
		log.Fatalln(err)
	}
	projectsService := iamcredentials.NewProjectsService(service)

	response, err := projectsService.ServiceAccounts.GenerateAccessToken(toName(serviceAccount),
		&iamcredentials.GenerateAccessTokenRequest{
			Scope: scopes,
		}).Do()
	if err != nil {
		return "", err
	}
	return response.AccessToken, nil
}
