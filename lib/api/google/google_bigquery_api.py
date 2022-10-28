#!/usr/bin/env python

# Third-party imports
from google.cloud import bigquery


class GoogleBigQuerySDK:
    def __init__(self, log):

        self.LOG = log

        self.LOG.info("Initializing Google BigQuery API")

        self.client = bigquery.Client()

        self.LOG.info("Successfully initialized Google BigQuery API")

    def perform_query(self, query_str):

        self.LOG.info("Running query to BigQuery {}".format(query_str))

        query_job = self.client.query(query_str)
        query_res = query_job.result()

        self.LOG.info("Finished running query in BigQuery")

        return query_res

    # Bulk insert rows into a BQ table via a buffer stream
    # @param table_id [String] The id of the table to insert into
    # @param buffer [bytes] The row data to be inserted into the table
    # @param job_config [LoadJobConfig] Configuration options for BigQuery load jobs
    # @return [Int] Total number of rows in the table
    def load_from_csv_stream(self, table_id, buffer, job_config):

        res = self.client.load_table_from_file(
            buffer, table_id, job_config=job_config
        ).result()
        num_rows = self.client.get_table(table_id).num_rows

        self.LOG.info(
            "Finished loading data into table '{}' in BigQuery. Table now has a total of {} rows".format(
                table_id, num_rows
            )
        )

        return num_rows
