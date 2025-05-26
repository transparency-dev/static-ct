# GCP live configs

This directory contains Terragrunt configs we use to run static-ct-api logs and other related pieces of infrastructure:

- `static-ct`: configures a continuous integration environment using the [hammer](/internal/hammer/)
- `static-ct-staging`: configures staging logs, `arche2025{h1,h2}` preloaded with entries from Google's `argon2025{h1,h2}`
- `test`: configures a test log using a GCP VM
