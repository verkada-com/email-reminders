#!/usr/bin/env python
from base import (
    Logger,
    SlackSDK,
    SecretManager,
    local_datadog_lambda_wrapper,
    wait_for_debugger,
)

LOG = Logger()

# If running locally, pauses execution and waits
# for a debugger to attach at port 5678
wait_for_debugger()


@local_datadog_lambda_wrapper()
@LOG.inject_lambda_context(log_event=True)
def lambda_handler(event, context):

    print("The lambda function 3 is running the normal way")
    secrets = SecretManager(log=LOG)
    slack = SlackSDK(log=LOG, secret_manager=secrets)

    return {}
