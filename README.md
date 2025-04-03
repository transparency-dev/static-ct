# SCTFE

[![Go Report Card](https://goreportcard.com/badge/github.com/transparency-dev/static-ct)](https://goreportcard.com/report/github.com/transparency-dev/static-ct)
[![Slack Status](https://img.shields.io/badge/Slack-Chat-blue.svg)](https://transparency-dev.slack.com/)

This personality implements [Static CT API](https://c2sp.org/static-ct-api) 
using [Trillian Tessera](https://github.com/transparency-dev/trillian-tessera) 
to store data. It is based on 
[Trillian's CTFE](https://github.com/google/certificate-transparency-go/tree/master/trillian/ctfe).

It is under active development.

## Deployment
Each Tessera storage backend needs its own SCTFE binary.

At the moment, these storage backends are supported:

 - [GCP](./cmd/gcp/): [deployment instructions](./deployment/live/gcp/test/)
 - [AWS](./cmd/aws/): [deployment instructions](./deployment/live/aws/test/)
 - more to come soon!

### Contact

- Slack: https://transparency-dev.slack.com/ ([invitation](https://join.slack.com/t/transparency-dev/shared_invite/zt-27pkqo21d-okUFhur7YZ0rFoJVIOPznQ))
- Mailing list: https://groups.google.com/forum/#!forum/trillian-transparency
