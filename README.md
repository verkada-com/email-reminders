# mops-serverless-service-template
Template for creating a Serverless AWS micro-service for the Verkada MOPs team. 

Workflow Features:
* Local environment setup via Docker
* Develop locally without having to deploy to test. [See docs on how to use.](https://www.notion.so/verkada-ops/Locally-developing-AWS-Lambdas-d0432f48f583476cbf0cad8db0edd5b2)
* Supports the VSCode debugger! [See docs on how to use.](https://www.notion.so/verkada-ops/Locally-developing-AWS-Lambdas-d0432f48f583476cbf0cad8db0edd5b2#5dbe22082aa24810ac78fb9497b29978)
* Supports running traditional lambdas and container-based lambdas
* Log Ingestion and Infrastructure Monitoring w/ DataDog
* Uses Serverless Framework for service configuration, packaging, and deployment
* Enable pip installing [packages from internal GitHub repos](https://www.notion.so/verkada-ops/Internal-library-Python-packages-62f9e3219ca045c3b5f23e60199e1f35)

## Usage
* Copy the template and update `serverless.yml` with config settings for your service, rename files, etc. appropriately
* Build local environment by running `./build.sh`
* To deploy run `sls deploy` optionally deploy as stage `sls deploy --stage dev`

## Notes
* Traditional Lambda = Max 250mb package unzipped  
* Container lambda = Max 10GB package unzipped

## Recommendations
* When in development of a new lambda, test locally by setting it up as a Traditional lambda. Local invocation of lambdas pointing to AWS ECR images is not supported.
* Once development is complete, convert it to a Container lambda to enable DataDog integration and other features automatically.
