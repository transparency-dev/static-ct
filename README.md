# SCTFE

This personality implements [CT Static API](https://c2sp.org/static-ct-api) 
using [Trillian Tessera](https://github.com/transparency-dev/trillian-tessera) 
to store data. It is based on 
[Trillian's CTFE](https://github.com/google/certificate-transparency-go/tree/master/trillian/ctfe).

It is under active development.

## Deployment
Each Tessera storage backend needs its own SCTFE binary.

At the moment, these storage backends are supported:

 - [GCP](./cmd/gcp/): [deployment instructions](./deployment/live/gcp/test/)
 - more to come soon!

## Working on the Code
The following files are auto-generated:
 - [`mock_ct_storage.go`](./mockstorage/mock_ct_storage.go): a mock CT storage implementation for tests

To re-generate these files, first install the right tools:
 - [mockgen](https://github.com/golang/mock?tab=readme-ov-file#installation)

Then, generate the files:

```bash
cd $(go list -f '{{ .Dir }}' github.com/transparency-dev/static-ct); \
go generate -x ./...  # hunts for //go:generate comments and runs them
```

### Contact

- Slack: https://transparency-dev.slack.com/ ([invitation](https://join.slack.com/t/transparency-dev/shared_invite/zt-27pkqo21d-okUFhur7YZ0rFoJVIOPznQ))
- Mailing list: https://groups.google.com/forum/#!forum/trillian-transparency
