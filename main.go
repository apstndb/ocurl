package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"
	"strings"

	"golang.org/x/oauth2"
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
	// token types
	var accessTokenFlag = flag.Bool("access-token", false, "Use access token")
	var idTokenFlag = flag.Bool("id-token", false, "Use ID token")
	var jwtFlag = flag.Bool("jwt", false, "Use JWT")

	// token sources
	var keyFile = flag.String("key-file", "", "Service Account JSON Key")
	var gcloudFlag = flag.Bool("gcloud", false, "gcloud default account")
	var wellKnownFlag = flag.Bool("well-known", false, "well known file credential")
	var gcloudAccount = flag.String("gcloud-account", "", "gcloud registered account(implies --gcloud)")
	var metadataFlag = flag.Bool("metadata", false, "Use metadata token source")

	// impersonate chain
	var impersonateServiceAccount stringsType
	flag.Var(&impersonateServiceAccount, "impersonate-service-account", "Specify delegate chain(near to far order). Implies --gcloud")

	// action
	var printTokenFlag = flag.Bool("print-token", false, "Print token")
	var tokenInfoFlag = flag.Bool("token-info", false, "Print token info")
	var decodeTokenFlag = flag.Bool("decode-token", false, "Print local decoded token")

	// id token option
	var audience = flag.String("audience", "", "Audience")

	// access token option
	var rawScopes stringsType
	flag.Var(&rawScopes, "scopes", "Scopes")

	flag.Parse()

	delegateChain, serviceAccount := splitInitLast(impersonateServiceAccount)

	// --gcloud-account implies --gcloud
	if *gcloudAccount != "" {
		*gcloudFlag = true
	}

	// adjust action
	switch {
	case *decodeTokenFlag && *accessTokenFlag:
		log.Println("--access-token can't work with --decode-token, fallback to --token-info")
		*tokenInfoFlag = true
		*decodeTokenFlag = false
	case *tokenInfoFlag && *jwtFlag:
		log.Println("--jwt can't work with --token-info, fallback to --decode-token")
		*tokenInfoFlag = false
		*decodeTokenFlag = true
	}

	keyEnv := os.Getenv("GOOGLE_APPLICATION_CREDENTIALS")

	switch {
	case countTrue(*idTokenFlag, *accessTokenFlag, *jwtFlag) == 0:
		log.Fatalln("--id-token or --access-token or --jwt is required")
	case countTrue(*idTokenFlag, *accessTokenFlag, *jwtFlag) > 1:
		log.Fatalln("--id-token and --access-token and --jwt are exclusive")
	case countTrue(*gcloudFlag, *metadataFlag, *wellKnownFlag, *keyFile != "", keyEnv != "") == 0:
		log.Fatalln("credential source is required")
	case countTrue(*gcloudFlag, *metadataFlag, *wellKnownFlag, *keyFile != "") > 1:
		log.Fatalln("credential source are exclusive")
	case *idTokenFlag && serviceAccount != "" && *audience == "":
		log.Fatalln("--audience is required when --id-token is used")
	case *idTokenFlag && len(rawScopes) != 0:
		log.Fatalln("--id-token and --scopes are exclusive")
	case *accessTokenFlag && *audience != "":
		log.Fatalln("--access-token and --audience are exclusive")
	case *printTokenFlag && *tokenInfoFlag:
		log.Fatalln("--print-token and --token-info are exclusive")
	case (*printTokenFlag || *tokenInfoFlag || *decodeTokenFlag) && flag.NArg() > 0:
		log.Fatalln("remaining argument is not permitted when --print-token or --token-info or --decode-token")
	}

	scopes := normalizeScopes(rawScopes)
	if len(scopes) == 0 {
		scopes = defaultScopes
	}

	var err error
	var tokenSource TokenSource
	switch {
	case *gcloudFlag:
		tokenSource, err = GcloudTokenSource(*gcloudAccount)
	case *wellKnownFlag:
		tokenSource, err = WellKnownTokenSource()
	case *keyFile != "":
		tokenSource, err = KeyFileTokenSourceFromFile(*keyFile)
	case *metadataFlag:
		tokenSource, err = MetadataTokenSourceDefault()
	case keyEnv != "":
		tokenSource, err = KeyFileTokenSourceFromFile(keyEnv)
	default:
		log.Fatalln("token source is missing")
	}

	if err != nil {
		log.Fatalln(err)
	}

	ctx := context.Background()
	if serviceAccount != "" {
		var oauth2TokenSource oauth2.TokenSource
		oauth2TokenSource, err = OAuth2TokenSource(ctx, tokenSource, defaultScopes...)
		if err != nil {
			log.Fatalln(err)
		}

		tokenSource = ImpersonateTokenSource(oauth2TokenSource, serviceAccount, delegateChain...)
	}

	if email, err := Email(tokenSource); err == nil {
		log.Println("Use account:", email)
	} else {
		log.Println("Can't get email:", err)
	}

	var tokenString string
	switch {
	case *idTokenFlag:
		tokenString, err = IDToken(ctx, tokenSource, *audience)
	case *accessTokenFlag:
		tokenString, err = AccessToken(ctx, tokenSource, scopes...)
	case *jwtFlag:
		tokenString, err = JWTToken(ctx, tokenSource, *audience)
	default:
		log.Fatalln("unknown branch")
	}

	if err != nil {
		log.Fatalln(err)
	}

	if *printTokenFlag {
		fmt.Println(tokenString)
		return
	}

	if *tokenInfoFlag {
		var resp *http.Response
		if *idTokenFlag {
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

func normalizeScopes(rawScopes []string) []string {
	var scopes []string
	for _, s := range rawScopes {
		if !strings.HasPrefix(s, scopePrefix) {
			s = scopePrefix + s
		}
		scopes = append(scopes, s)
	}
	return scopes
}
