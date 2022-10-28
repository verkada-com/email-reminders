FROM ubuntu:20.04

# Create AWS CLI Configuration
ARG AWS_ACCESS_KEY=None
ARG AWS_SECRET_ACCESS_KEY=None

ENV AWS_ACCESS_KEY ${AWS_ACCESS_KEY}
ENV AWS_SECRET_ACCESS_KEY ${AWS_SECRET_ACCESS_KEY}
ENV AWS_CONFIG_FILE "/.aws/config"
ENV AWS_SHARED_CREDENTIALS_FILE "/.aws/credentials"
ENV GOOGLE_APPLICATION_CREDENTIALS "./var/creds/google/bigquery_api.json"

WORKDIR /app

RUN mkdir /.aws \
  && echo [default] >> /.aws/credentials \
  && echo "aws_access_key_id = ${AWS_ACCESS_KEY}" >> /.aws/credentials \
  && echo "aws_secret_access_key = ${AWS_SECRET_ACCESS_KEY}" >> /.aws/credentials \
  && echo [default] >> /.aws/config \
  && echo "region = us-west-1" >> /.aws/config \
  && echo "output = json" >> /.aws/config
 

# Base layer of tools needed to create a Python Lambda
RUN apt-get update \
  && apt-get install -y -qq python3-pip git \
  && cd /usr/local/bin \
  && ln -s /usr/bin/python3 python \
  && python3 -m pip install --upgrade pip \
  && python3 -m pip install ipython \
  && rm -rf /var/lib/apt/lists/* \
  && apt-get update \
  && apt-get install zip -y \
  && apt-get install curl -y \
  && apt-get install vim -y \
  && apt-get install docker.io -y \
  && pip3 install awscli --upgrade \
  && curl -sL https://deb.nodesource.com/setup_15.x  | bash - \
  && apt-get -y install nodejs \
  && npm install \
  && npm install -g serverless 
  
# Install Python libraries that are always needed
RUN pip3 install boto3

# Install any serverless plugins

# NOTE: We're installing the plugins into the global context rather than using 
# `sls plugin install` because that only supports installing in local node_modules
# We want to install into global scope since the local workdir will
# get overwritten by the host due to the bind mount in our `docker run` cmd (see _build.sh).
# This works because sls plugins are mere npm packages.
# See: https://github.com/serverless/serverless/issues/3319#issuecomment-920768501
RUN npm install -g serverless-prune-plugin

# Copy host SSH keys to development container so that we 
# can pull private python packages from GitHub
COPY ./var/.ssh /root/.ssh 

# Install project-specific pip packages
# This lets us run the project locally inside the container
COPY requirements.txt /app
RUN pip3 install -r requirements.txt
