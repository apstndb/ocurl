
```sh
$ go get -u github.com/apstndb/ocurl 
$ ocurl --help
Usage of ocurl:
  -access-token
        Use access token
  -audience string
        Audience
  -decode-token
        Print local decoded token
  -gcloud
        gcloud default account
  -gcloud-account string
        gcloud registered account(implies --gcloud)
  -id-token
        Use ID token
  -impersonate-service-account value
        Specify delegate chain(near to far order). Implies --gcloud
  -jwt
        Use JWT
  -key-file string
        Service Account JSON Key
  -metadata
        Use metadata token source
  -print-token
        Print token
  -scopes value
        Scopes
  -subject string
        Overwrite subject for domain-wide delegation(EXPERIMENTAL)
  -token-info
        Print token info
  -well-known
        well known file credential

# Use `gcloud auth application-default login` credential
$ ocurl -well-known -access-token -- https://cloudresourcemanager.googleapis.com/v1/projects 
# Use `gcloud auth login` credential
$ ocurl -gcloud -access-token -- https://cloudresourcemanager.googleapis.com/v1/projects 
```