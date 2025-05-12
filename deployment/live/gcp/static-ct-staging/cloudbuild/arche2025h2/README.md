# GCP Cloud Build Triggers and Steps

This directory contains terragrunt files to configure our Cloud Build pipeline(s).

The Cloud Build pipeline is triggered when a commit in the repo is tagged with
`^staging-deploy-(.+)$` and is responsible for:

1. Building the `cmd/gcp` and `cmd/gcp/staging` docker images from the last commit with a `^staging-deploy-(.+)$` tag,
1. Deploying the `cmd/gcp/staging` image to Cloud Run,
1. Update [arche2025h2](/deployment/live/gcp/static-ct-staging/logs/arche2025h2/) Cloud Run service with the latest docker image,
1. Update [arche2025h2](/deployment/live/gcp/static-ct-staging/logs/arche2025h2/) infrastructure with the latest Terraform config.

## Initial setup

The first time this is run for a pair of {GCP Project, GitHub Repo} you will get an error 
message such as the following:

```
Error: Error creating Trigger: googleapi: Error 400: Repository mapping does not exist. Please visit $URL to connect a repository to your project
```

This is a manual one-time step that needs to be followed to integrate GCP Cloud Build 
and the GitHub repository.
