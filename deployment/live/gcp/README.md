# GCP live configs

This directory contains Terragrunt configs we use to run static-ct-api logs and other related pieces of infrastructure:
 - `static-ct`: configures a continuous integration environment using the [hammer](/internal/hammer/)
 - `static-ct-staging`: configures a staging log, `arche2025h1` preloaded with entries from Google's `argon2025h1`
 - `test`: configures a test log using a GCP VM
