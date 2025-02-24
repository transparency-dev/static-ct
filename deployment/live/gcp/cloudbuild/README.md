# GCP Cloud Build Triggers and Steps

This directory contains terragrunt files to configure our Cloud Build pipeline(s).

The Cloud Build pipeline is triggered on commits to the `main` branch of the repo, and
is responsible for:

1. Building the `cmd/gcp` and `cmd/gcp/ci` docker images from the `main` branch,
1. Deploying the `cmd/gcp/ci` image to Cloud Run,
1. Creating a fresh conformance testing environment,
1. Running the conformance test with [CT Hammer](/internal/hammer/) against the newly build conformance docker image,
1. Turning-down the conformance testing environment.

## Initial setup

The first time this is run for a pair of {GCP Project, GitHub Repo} you will get an error 
message such as the following:

```
Error: Error creating Trigger: googleapi: Error 400: Repository mapping does not exist. Please visit $URL to connect a repository to your project
```

This is a manual one-time step that needs to be followed to integrate GCP Cloud Build 
and the GitHub repository.
