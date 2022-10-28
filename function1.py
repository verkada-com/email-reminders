#!/usr/bin/env python
from base import Logger, SlackSDK, SecretManager, local_datadog_lambda_wrapper

LOG = Logger()


@local_datadog_lambda_wrapper()
@LOG.inject_lambda_context(log_event=True)
def lambda_handler(event, context):

    print("This is a lambda running from a container image")
    secrets = SecretManager(log=LOG)
    slack = SlackSDK(log=LOG, secret_manager=secrets)

    return {}
