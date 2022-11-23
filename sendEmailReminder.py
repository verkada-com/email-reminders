#!/usr/bin/env python
from base import (
    Logger,
    SlackSDK,
    SecretManager,
    local_datadog_lambda_wrapper,
    wait_for_debugger,
)

# If running locally, pauses execution and waits
# for a debugger to attach at port 5678
wait_for_debugger()

from lib.api.postgres.postgres_mgr import PostgresManager
from lib.api.google.google_gmail_api import GoogleGmailSDK
from datetime import datetime, timedelta
from time import sleep

LOG = Logger()

secrets = SecretManager(log=LOG)
slack = SlackSDK(log=LOG, secret_manager=secrets)
postgres = PostgresManager(log=LOG, secret_mgr=secrets)

@local_datadog_lambda_wrapper()
@LOG.inject_lambda_context(log_event=True)
def lambda_handler(event, context):

    print("The lambda function 3 is running the normal way")
    
    utcnow = datetime.utcnow()
    sql = f"""
        select *
        from scheduled_email_sends
        where
            time_to_send > TIMESTAMP '{utcnow - timedelta(hours=1)}' and 
            time_to_send <= TIMESTAMP '{utcnow}'
    """
    emails_to_send = postgres.query(sql)

    for email_data in emails_to_send:
        try:
            created_date = email_data[1]
            contact_email = email_data[2]
            contact_first_name = email_data[3]
            contact_last_name = email_data[4]
            template_id = email_data[5]
            webinar_sfdc_id = email_data[6]
            time_to_send = email_data[7]
            sender_email = email_data[8]
            webinar_name = email_data[9]
            zoom_join_url = email_data[10]
            sender_email_full = email_data[11]

            gmail = GoogleGmailSDK(log=LOG, user=sender_email)

            if int(template_id) == 1:
                with open("email_templates/template1.html", "r") as arne:
                    body = arne.read().format(
                        contact_first_name,
                        webinar_name
                    )
                email_obj = gmail.create_email(
                    sender=sender_email_full,
                    to=contact_email,
                    subject=f"{contact_first_name}, thank you in advance!",
                    message_text=body,
                    html='html'
                )
            elif int(template_id) == 2:
                with open("email_templates/template2.html", "r") as arne:
                    body = arne.read().format(
                        contact_first_name,
                        webinar_name,
                        zoom_join_url
                    )
                email_obj = gmail.create_email(
                    sender=sender_email_full,
                    to=contact_email,
                    subject=f"We look forward to seeing you tomorrow, {contact_first_name}",
                    message_text=body,
                    html='html'
                )
            else:
                LOG.warning(f"Got email data with invalid template id: {template_id}, email data: {email_data}")
                continue
                
            gmail.send_email(sender_email, email_obj)
            LOG.info(f"Sent email to {contact_email} with template id {template_id}")

            sleep(1)
        except Exception as e:
            LOG.exception(
                f"""
                Error occurred when sending reminder email to {sender_email}
                Email Data: {email_data}
                Error: {e}
                """
            )
    return {}
