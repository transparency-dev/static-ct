# static-ct-staging

This directory contains Terragrunt configs for the `static-ct-staging` GCP project.

The [./logs](./logs/) directory contains the configs for the `arche2025{h1,h2}`
staging logs.

The [./cloudbuild](./cloudbuild/) directory contains the configs for:

- Building the TesseraCT binary, and deploying it automatically to logs under
[./logs](`./logs`) by applying their Terragrunt configurations.
- Running
[preloaders](https://github.com/google/certificate-transparency-go/blob/56b77cf4eff480d1ac5d969a6f8fb7b8b714abde/preload/preloader/preloader.go),
preloading `arche2025{h1,h2}` with entries from Google's `argon2025{h1,h2}`.
