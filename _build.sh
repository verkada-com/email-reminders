#!/bin/bash
image_tag="mops-serverless-service-template"

# Collect AWS credentials
access_key=$(aws --profile default configure get aws_access_key_id)
secret_key=$(aws --profile default configure get aws_secret_access_key)

# Check to see if both AWS keys were retrieved
if [ -z "$access_key" ] || [ -z "$secret_key" ] ; then
  echo "Could not determine AWS credentials, please check your configuration."
  exit 1
else
  echo "======================================================================"
  echo "Building Docker Image..."
  echo "======================================================================"
fi

# Copy SSH creds to ./var to pull private python packages from our github
(mkdir -p ./var && cp -r ~/.ssh ./var/) || (echo "Couldn't find your SSH keys at ~/.ssh Please make sure your SSH keys are set up with Github."; exit 1)

# Build the dev container
docker build . \
  --build-arg AWS_ACCESS_KEY=$access_key \
  --build-arg AWS_SECRET_ACCESS_KEY=$secret_key \
  -f Dockerfile \
  -t $image_tag || exit

# Get a shell into the dev container
docker run \
  --rm \
  -it \
  -v /var/run/docker.sock:/var/run/docker.sock \
  --mount type=bind,src="$(pwd)",dst=/app \
  -p 5678:5678 \
  $image_tag
