#!/usr/bin/env python
from base import Logger, local_datadog_lambda_wrapper

# # BESPOKE LOCAL IMPORTS
from lib.api.google.google_bigquery_api import GoogleBigQuerySDK

LOG = Logger()


@local_datadog_lambda_wrapper()
@LOG.inject_lambda_context(log_event=True)
def lambda_handler(event, context):

    print("The lambda function 2 is running")

    bigquery = GoogleBigQuerySDK(LOG)

    return {}
