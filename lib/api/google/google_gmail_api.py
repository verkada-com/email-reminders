#!/usr/bin/env python

from __future__ import print_function
import os
import re
import base64
import pickle
import os.path
import email
import mimetypes
from time import sleep
from apiclient import errors
from email.mime.audio import MIMEAudio
from email.mime.base import MIMEBase
from email.mime.image import MIMEImage
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from googleapiclient.discovery import build
from google_auth_oauthlib.flow import InstalledAppFlow
from google.auth.transport.requests import Request
from google.oauth2 import service_account

GMAIL_SCOPES = [
    "https://mail.google.com/",
    "https://www.googleapis.com/auth/gmail.settings.sharing",
]

VERKADA_MARKETING_DOMAIN_SERVICE_PATH = "./var/creds/google/verkada-mops.json"


class GoogleGmailSDK:
    def __init__(self, log, user, is_service_account=False):

        self.LOG = log

        self.LOG.info("Initializing Google Gmail API")

        self.scope = [
            "https://www.googleapis.com/auth/gmail.send",
            "https://www.googleapis.com/auth/gmail.readonly",
            "https://www.googleapis.com/auth/gmail.modify,",
            "https://www.googleapis.com/auth/gmail.settings.sharing",
        ]

        """Shows basic usage of the Sheets API.
    Prints values from a sample spreadsheet.
    """
        creds = None
        self.account = user

        if self.account == "mike.cubberly.1@verkada.com":
            self.cred_path = "./var/creds/google/mdr_inbox_credentials.json"
            self.token_path = "./var/creds/google/mike_cubberly_1_token.pickle"
        elif self.account == "david.betty.1@verkada.com":
            self.cred_path = "./var/creds/google/mdr_inbox_credentials.json"
            self.token_path = "./var/creds/google/david_betty_1_token.pickle"
        elif self.account == "dom.freschet.1@verkada.com":
            self.cred_path = "./var/creds/google/mdr_inbox_credentials.json"
            self.token_path = "./var/creds/google/dom_freschet_1_token.pickle"

        elif not is_service_account:
            self.LOG.error("No valid credentials for user {}".format(user))

        if is_service_account:
            creds = service_account.Credentials.from_service_account_file(
                VERKADA_MARKETING_DOMAIN_SERVICE_PATH, scopes=GMAIL_SCOPES
            ).with_subject(self.account)
        else:
            # The file token.pickle stores the user's access and refresh tokens, and is
            # created automatically when the authorization flow completes for the first
            # time.
            if os.path.exists(self.token_path):
                with open(self.token_path, "rb") as token:
                    creds = pickle.load(token)
            # If there are no (valid) credentials available, let the user log in.
            if not creds or not creds.valid:
                if creds and creds.expired and creds.refresh_token:
                    creds.refresh(Request())
                else:
                    flow = InstalledAppFlow.from_client_secrets_file(
                        self.cred_path, self.scope
                    )
                    flow.authorization_url(access_type="offline")
                    creds = flow.run_local_server(port=0)
                    # with open(self.token_path, 'wb') as token:
                    #  pickle.dump(creds, token)

        self.service = build("gmail", "v1", credentials=creds, cache_discovery=False)

        self.LOG.info("Successfully initialized Google Gmail API")

    def get_labeled_emails(self, label):

        self.LOG.info(
            "Getting emails with '{}' label for {}".format(label, self.account)
        )

        final_email_list = []
        label_str = "label:{}".format(label)

        res = (
            self.service.users()
            .messages()
            .list(userId=self.account, q=label_str)
            .execute()
        )

        if "messages" in res.keys():
            for message in res["messages"]:
                final_email_list.append(message)

        else:
            self.LOG.info(
                "There are no messages labled {} for {}".format(label, self.account)
            )
            return False

        while "nextPageToken" in res.keys():

            self.LOG.info("Need to query the next page for list of email messages")

            token = res["nextPageToken"]
            res = (
                self.service.users()
                .messages()
                .list(userId=self.account, q=label_str, pageToken=token)
                .execute()
            )

            for message in res["messages"]:
                final_email_list.append(message)

        self.LOG.info(
            "Got a list of {} emails with label {} for {}".format(
                len(final_email_list), label, self.account
            )
        )

        return final_email_list

    # Get a list of all messages in the accounts inbox
    def get_emails_in_inbox(self):

        self.LOG.info("Getting inbox emails for {}".format(self.account))

        final_email_list = []
        search_str = "in:inbox newer_than:7d !(subject: XDW)"
        res = (
            self.service.users()
            .messages()
            .list(userId=self.account, q=search_str)
            .execute()
        )

        if "messages" in res.keys():
            for message in res["messages"]:
                final_email_list.append(message)
        else:
            self.LOG.info("There are no messages in Inbox for {}".format(self.account))

        while "nextPageToken" in res.keys():

            self.LOG.info("Need to query the next page for list of email messages")

            token = res["nextPageToken"]
            res = (
                self.service.users()
                .messages()
                .list(userId=self.account, q=search_str, pageToken=token)
                .execute()
            )

            if "messages" in res.keys():
                for message in res["messages"]:
                    final_email_list.append(message)

        self.LOG.info(
            "Got {} emails from inbox: {}".format(len(final_email_list), self.account)
        )

        return final_email_list

    def get_emails_after_date(self, after_date, unread_only=False):
        self.LOG.info(
            "Getting emails received after {} for {}".format(after_date, self.account)
        )

        # https://developers.google.com/gmail/api/guides/filtering
        # Warning: All dates used in the search query are interpreted as midnight on that date in the PST timezone. To specify accurate dates for other timezones pass the value in seconds instead:
        search_str = "after:{}".format(after_date)

        if unread_only:
            search_str = "is:unread after:{}".format(after_date)

        final_email_list = []
        res = (
            self.service.users()
            .messages()
            .list(userId=self.account, q=search_str)
            .execute()
        )

        if "messages" in res.keys():
            for message in res["messages"]:
                final_email_list.append(message)
        else:
            self.LOG.info("There are no messages in Inbox for {}".format(self.account))

        while "nextPageToken" in res.keys():

            self.LOG.info("Need to query the next page for list of email messages")

            token = res["nextPageToken"]
            res = (
                self.service.users()
                .messages()
                .list(userId=self.account, q=search_str, pageToken=token)
                .execute()
            )

            if "messages" in res.keys():
                for message in res["messages"]:
                    final_email_list.append(message)

        self.LOG.info(
            "Got {} emails from inbox: {}".format(len(final_email_list), self.account)
        )

        return final_email_list

    def get_threads_after_date(self, after_date, unread_only=False):
        self.LOG.info(
            "Getting emails received after {} for {}".format(after_date, self.account)
        )

        # https://developers.google.com/gmail/api/guides/filtering
        # Warning: All dates used in the search query are interpreted as midnight on that date in the PST timezone. To specify accurate dates for other timezones pass the value in seconds instead:
        search_str = "after:{}".format(after_date)

        if unread_only:
            search_str = "is:unread after:{}".format(after_date)

        final_thread_list = []
        res = (
            self.service.users()
            .threads()
            .list(userId=self.account, q=search_str)
            .execute()
        )

        if "threads" in res.keys():
            for thread in res["threads"]:
                final_thread_list.append(thread)
        else:
            self.LOG.info("There are no threads in Inbox for {}".format(self.account))

        while "nextPageToken" in res.keys():

            self.LOG.info("Need to query the next page for list of email messages")

            token = res["nextPageToken"]
            res = (
                self.service.users()
                .threads()
                .list(userId=self.account, q=search_str, pageToken=token)
                .execute()
            )

            if "threads" in res.keys():
                for thread in res["threads"]:
                    final_thread_list.append(thread)

        self.LOG.info(
            "Got {} threads from inbox: {}".format(len(final_thread_list), self.account)
        )

        return final_thread_list

    def get_spam_emails(self):

        self.LOG.info("Getting spam messages for {}".format(self.account))

        final_email_list = []

        # Get Spam
        search_str = "in:spam AND newer_than:10d"

        res = (
            self.service.users()
            .messages()
            .list(userId=self.account, q=search_str)
            .execute()
        )

        if "messages" in res.keys():
            for message in res["messages"]:
                final_email_list.append(message)
        else:
            self.LOG.info(
                "There are no spam messages in Spam for {}".format(self.account)
            )

        while "nextPageToken" in res.keys():

            self.LOG.info("Need to query the next page for list of email messages")

            token = res["nextPageToken"]
            res = (
                self.service.users()
                .messages()
                .list(userId=self.account, q=search_str, pageToken=token)
                .execute()
            )

            for message in res["messages"]:
                final_email_list.append(message)

        self.LOG.info(
            "Got a list of {} undeliverable emails for {}".format(
                len(final_email_list), self.account
            )
        )

        return final_email_list

    def get_undeliverable_emails(self):

        self.LOG.info("Getting undeliverable messages for {}".format(self.account))

        final_email_list = []
        # Get Inbox undeliverables
        search_str = "undeliverable newer_than:1d"

        res = (
            self.service.users()
            .messages()
            .list(userId=self.account, q=search_str)
            .execute()
        )

        if "messages" in res.keys():
            for message in res["messages"]:
                final_email_list.append(message)
        else:
            self.LOG.info(
                "There are no undeliverable messages in Inbox for {}".format(
                    self.account
                )
            )

        while "nextPageToken" in res.keys():

            self.LOG.info("Need to query the next page for list of email messages")

            token = res["nextPageToken"]
            res = (
                self.service.users()
                .messages()
                .list(userId=self.account, q=search_str, pageToken=token)
                .execute()
            )

            for message in res["messages"]:
                final_email_list.append(message)

        # Get Spam undeliverables
        search_str = "in:spam AND undeliverable, AND newer_than:1d"

        res = (
            self.service.users()
            .messages()
            .list(userId=self.account, q=search_str)
            .execute()
        )

        if "messages" in res.keys():
            for message in res["messages"]:
                final_email_list.append(message)
        else:
            self.LOG.info(
                "There are no undeliverable messages in Spam for {}".format(
                    self.account
                )
            )

        while "nextPageToken" in res.keys():

            self.LOG.info("Need to query the next page for list of email messages")

            token = res["nextPageToken"]
            res = (
                self.service.users()
                .messages()
                .list(userId=self.account, q=search_str, pageToken=token)
                .execute()
            )

            for message in res["messages"]:
                final_email_list.append(message)

        if len(final_email_list) == 0:
            self.LOG.warning(
                "There are no undeliverable messages in Inbox AND Spam for {}".format(
                    self.account
                )
            )
            return False

        self.LOG.info(
            "Got a list of {} undeliverable emails for {}".format(
                len(final_email_list), self.account
            )
        )

        return final_email_list

    def get_raw_email_message(self, email_address, email_id):
        self.LOG.info(
            "Getting email content for {} and message ID: {}".format(
                email_address, email_id
            )
        )

        res = (
            self.service.users()
            .messages()
            .get(id=email_id, userId=email_address, format="raw")
            .execute()
        )

        self.LOG.info(
            "Successfully got message content for message ID: {}".format(email_id)
        )

        message = base64.urlsafe_b64decode(res["raw"].encode("UTF-8"))
        msg_bytes = email.message_from_bytes(message)

        return msg_bytes

    def get_email_message(self, email_address, email_id):

        self.LOG.info(
            "Getting email content for {} and message ID: {}".format(
                email_address, email_id
            )
        )

        res = (
            self.service.users()
            .messages()
            .get(id=email_id, userId=email_address)
            .execute()
        )

        self.LOG.info(
            "Successfully got message content for message ID: {}".format(email_id)
        )

        return res

    def send_email(self, user_id, message):

        self.LOG.info("Sending email from {}".format(user_id))

        message = (
            self.service.users().messages().send(userId=user_id, body=message).execute()
        )

        self.LOG.info("Message Id: {}".format(message["id"]))

        return message

    def create_email(self, sender, to, subject, message_text):

        self.LOG.info(
            "Creating email '{}' to send to {}, from {}".format(subject, to, sender)
        )

        message = MIMEText(message_text)
        message["to"] = to
        message["from"] = sender
        message["subject"] = subject
        message["url"] = "test"

        self.LOG.info("Successfully created email")

        return {"raw": base64.urlsafe_b64encode(message.as_string().encode()).decode()}

    def forward_email(self, to, from_user_id, decoded_email_body):

        self.LOG.info("Forwarding email to send to {}".format(to))

        content_type = decoded_email_body.get_content_maintype()

        if content_type == "multipart":
            # there will usually be 2 parts: the first will be the body as a raw string,
            # the second will be the body as html
            parts = decoded_email_body.get_payload()

            # return the encoded text
            send_string = parts[0].get_payload()

            # force utf-8 encoding on the string
            send_string = send_string.encode("utf-8").decode("utf-8")

        message = MIMEText(send_string)
        message["to"] = to
        message["cc"] = None

        self.LOG.info(f"New message is: {message.as_string()}")

        email_body = {
            "raw": base64.urlsafe_b64encode(message.as_string().encode()).decode()
        }

        msg = (
            self.service.users()
            .messages()
            .send(userId=from_user_id, body=email_body)
            .execute()
        )

        return msg

    def change_autoforward_settings(self, userId, forwardingEmail):

        body = {
            "emailAddress": forwardingEmail,
            "enabled": True,
            "disposition": "archive",
        }
        result = (
            self.service.users()
            .settings()
            .updateAutoForwarding(userId=userId, body=body)
            .execute()
        )

    def forward_email_test(self, to, from_user_id, decoded_email_body):
        decoded_email_body = str(decoded_email_body)
        # decoded = base64.urlsafe_b64decode(str(decoded_email_body))

        # encoded_test = "RGVsaXZlcmVkLVRvOiBkb20uZnJlc2NoZXQuMUB2ZXJrYWRhLmNvbQpSZWNlaXZlZDogYnkgMjAwMjphMTc6OTA2OjUxOWE6MDowOjA6MCB3aXRoIFNNVFAgaWQgeTI2Y3NwMjEwMTE3M2VqazsKICAgICAgICBGcmksIDE5IE5vdiAyMDIxIDEzOjUyOjE4IC0wODAwIChQU1QpClgtUmVjZWl2ZWQ6IGJ5IDIwMDI6YTA1OjY4MDg6MTIwMjo6IHdpdGggU01UUCBpZCBhMm1yMzk2ODk3b2lsLjguMTYzNzM1ODczODQ3NDsKICAgICAgICBGcmksIDE5IE5vdiAyMDIxIDEzOjUyOjE4IC0wODAwIChQU1QpCkFSQy1TZWFsOiBpPTI7IGE9cnNhLXNoYTI1NjsgdD0xNjM3MzU4NzM4OyBjdj1wYXNzOwogICAgICAgIGQ9Z29vZ2xlLmNvbTsgcz1hcmMtMjAxNjA4MTY7CiAgICAgICAgYj1ZMzRoVU5oTnhHVlpiU0VFVkdxL1pvT24zUDkxUC9SM1hUTUtsbjhBRFludUU2R1pFUUhYM1NxN3ZvSjRrNXFjWkEKICAgICAgICAgak8xV2hDb1JCazFPR05qLzZqOW85R0MvV2dPWndrL1Q5akRjdUxxdjZ0U1Q0eHVkeXJEQUpIOG55TTFMek14Zk14YzMKICAgICAgICAgWEgvVVZPM0VVNGIrcFNxaVdMR2R0dnZPeWRhcElwUE96K29wZW5yTkNKWEFFdzdZQ0Nzd1p1RDJKM2ZoODhZOHBsRWsKICAgICAgICAga1VxbVMzTzhFcFN2TDg5dzc5K3hybkdTcTVCbXB5d0IyckRNVXpUSEFtNzR5alYxazE2UzRKckhzN25TMmx6OU9naFIKICAgICAgICAgM2x0dllpOG5JUkt5K2lSOG5JZlJSUkEzWHVhWmhiVE8reXBhKzQ3L2VGRWd1VXBSUitZYTZrcm1sTUdCSVRJQUdzdnUKICAgICAgICAgTXl6QT09CkFSQy1NZXNzYWdlLVNpZ25hdHVyZTogaT0yOyBhPXJzYS1zaGEyNTY7IGM9cmVsYXhlZC9yZWxheGVkOyBkPWdvb2dsZS5jb207IHM9YXJjLTIwMTYwODE2OwogICAgICAgIGg9dG86c3ViamVjdDptZXNzYWdlLWlkOmRhdGU6ZnJvbTpyZXBseS10bzppbi1yZXBseS10bzpyZWZlcmVuY2VzCiAgICAgICAgIDptaW1lLXZlcnNpb246ZGtpbS1zaWduYXR1cmU6ZGVsaXZlcmVkLXRvOwogICAgICAgIGJoPWM3NEZ2T1NSc1F6a1lwUEtKNXB1NFgwcXhuN0FWRFlSUzh1a2QveVpJcEE9OwogICAgICAgIGI9Z2dBdmlyVFBmTWpYekZBK1ZBWUd5bUFlTjh1V1BkRXBJNGVyRzZnWHdUTHNPK3dPY0VheXBDM3hqT09nSWFGUCtLCiAgICAgICAgIFo3WnFwSWtzYjFvbTVhR0tPcjNrUjNHbUMwYkVxR3lSWG9icFl3dkZSR3RXY1pQZzU3eFI2alJjYkFiQ0ZGV09JWGxkCiAgICAgICAgIFNkWnlQcjBTb01PWG9KSUJlZnRtMlRFa3FvdzBIazVDZWN2YWpWR3l6N3VRNnp5WDcvbkdZWFBQeVNUc3FzNDNwQ2pmCiAgICAgICAgIG50ZXBZTFgwcjN1WTB0dGUwTndJU05ZbXRDZzYxcU1ZTDVjeXJhLy8rb0MrMzlXRldGNmVXWjRRN3IwM0hPREhFMCtrCiAgICAgICAgIDhvRjZuTVdha3gzcnh3QnZ6WTlXYzlnMzJHUFJBN0xmbFpzOFduSFlGc3NYNU5lWDVRYzZTclVkSlI2V3JWbWwvd283CiAgICAgICAgIDdESmc9PQpBUkMtQXV0aGVudGljYXRpb24tUmVzdWx0czogaT0yOyBteC5nb29nbGUuY29tOwogICAgICAgZGtpbT1wYXNzIGhlYWRlci5pPUBnbWFpbC5jb20gaGVhZGVyLnM9MjAyMTAxMTIgaGVhZGVyLmI9R3krekRHTDQ7CiAgICAgICBhcmM9cGFzcyAoaT0xIHNwZj1wYXNzIHNwZmRvbWFpbj1nbWFpbC5jb20gZGtpbT1wYXNzIGRrZG9tYWluPWdtYWlsLmNvbSBkbWFyYz1wYXNzIGZyb21kb21haW49Z21haWwuY29tKTsKICAgICAgIHNwZj1wYXNzIChnb29nbGUuY29tOiBkb21haW4gb2YgZGZyZXNjaGV0K2NhZl89ZG9tLmZyZXNjaGV0LjE9dmVya2FkYS5jb21AdmVya2FkYS5jb20gZGVzaWduYXRlcyAyMDkuODUuMjIwLjQxIGFzIHBlcm1pdHRlZCBzZW5kZXIpIHNtdHAubWFpbGZyb209ImRmcmVzY2hldCtjYWZfPWRvbS5mcmVzY2hldC4xPXZlcmthZGEuY29tQHZlcmthZGEuY29tIjsKICAgICAgIGRtYXJjPXBhc3MgKHA9Tk9ORSBzcD1RVUFSQU5USU5FIGRpcz1OT05FKSBoZWFkZXIuZnJvbT1nbWFpbC5jb20KUmV0dXJuLVBhdGg6IDxkZnJlc2NoZXQrY2FmXz1kb20uZnJlc2NoZXQuMT12ZXJrYWRhLmNvbUB2ZXJrYWRhLmNvbT4KUmVjZWl2ZWQ6IGZyb20gbWFpbC1zb3ItZjQxLmdvb2dsZS5jb20gKG1haWwtc29yLWY0MS5nb29nbGUuY29tLiBbMjA5Ljg1LjIyMC40MV0pCiAgICAgICAgYnkgbXguZ29vZ2xlLmNvbSB3aXRoIFNNVFBTIGlkIGYxMnNvcjM1MzgzMW9pdy4xMDEuMjAyMS4xMS4xOS4xMy41Mi4xOAogICAgICAgIGZvciA8ZG9tLmZyZXNjaGV0LjFAdmVya2FkYS5jb20-CiAgICAgICAgKEdvb2dsZSBUcmFuc3BvcnQgU2VjdXJpdHkpOwogICAgICAgIEZyaSwgMTkgTm92IDIwMjEgMTM6NTI6MTggLTA4MDAgKFBTVCkKUmVjZWl2ZWQtU1BGOiBwYXNzIChnb29nbGUuY29tOiBkb21haW4gb2YgZGZyZXNjaGV0K2NhZl89ZG9tLmZyZXNjaGV0LjE9dmVya2FkYS5jb21AdmVya2FkYS5jb20gZGVzaWduYXRlcyAyMDkuODUuMjIwLjQxIGFzIHBlcm1pdHRlZCBzZW5kZXIpIGNsaWVudC1pcD0yMDkuODUuMjIwLjQxOwpBdXRoZW50aWNhdGlvbi1SZXN1bHRzOiBteC5nb29nbGUuY29tOwogICAgICAgZGtpbT1wYXNzIGhlYWRlci5pPUBnbWFpbC5jb20gaGVhZGVyLnM9MjAyMTAxMTIgaGVhZGVyLmI9R3krekRHTDQ7CiAgICAgICBhcmM9cGFzcyAoaT0xIHNwZj1wYXNzIHNwZmRvbWFpbj1nbWFpbC5jb20gZGtpbT1wYXNzIGRrZG9tYWluPWdtYWlsLmNvbSBkbWFyYz1wYXNzIGZyb21kb21haW49Z21haWwuY29tKTsKICAgICAgIHNwZj1wYXNzIChnb29nbGUuY29tOiBkb21haW4gb2YgZGZyZXNjaGV0K2NhZl89ZG9tLmZyZXNjaGV0LjE9dmVya2FkYS5jb21AdmVya2FkYS5jb20gZGVzaWduYXRlcyAyMDkuODUuMjIwLjQxIGFzIHBlcm1pdHRlZCBzZW5kZXIpIHNtdHAubWFpbGZyb209ImRmcmVzY2hldCtjYWZfPWRvbS5mcmVzY2hldC4xPXZlcmthZGEuY29tQHZlcmthZGEuY29tIjsKICAgICAgIGRtYXJjPXBhc3MgKHA9Tk9ORSBzcD1RVUFSQU5USU5FIGRpcz1OT05FKSBoZWFkZXIuZnJvbT1nbWFpbC5jb20KWC1Hb29nbGUtREtJTS1TaWduYXR1cmU6IHY9MTsgYT1yc2Etc2hhMjU2OyBjPXJlbGF4ZWQvcmVsYXhlZDsKICAgICAgICBkPTFlMTAwLm5ldDsgcz0yMDIxMDExMjsKICAgICAgICBoPXgtZ20tbWVzc2FnZS1zdGF0ZTpkZWxpdmVyZWQtdG86ZGtpbS1zaWduYXR1cmU6bWltZS12ZXJzaW9uCiAgICAgICAgIDpyZWZlcmVuY2VzOmluLXJlcGx5LXRvOnJlcGx5LXRvOmZyb206ZGF0ZTptZXNzYWdlLWlkOnN1YmplY3Q6dG87CiAgICAgICAgYmg9Yzc0RnZPU1JzUXprWXBQS0o1cHU0WDBxeG43QVZEWVJTOHVrZC95WklwQT07CiAgICAgICAgYj1qaXZ1NFpWejZ2SGRhZWxVNEVxVXJlNWpsNjBHNHFVQlJBWCtTTzQvOVZaM0pYRnZmNjlXQkF3Z2N1VkVScS8xT2cKICAgICAgICAgZElIeGFyakdzV0pBUGdRWU1Eek1ycW0rajhzZlNaSU1hRDc2M2V4OXRiQTlJckttOHRiNm9pajlIOVladys5eU9rUVEKICAgICAgICAgWmhRMVhyY01OTkx4ZFovMG1BZlNvU0tDUHQ3d3Y2dGdsMHdKbE94K2JFNWZVamRaS3lxWW5ISHVVSmhHNXNyaWkzbmIKICAgICAgICAgMWtZR3RXWmU4OE4vUzR1cEdxVldHSGdZUVFRTlpkTWY2WHpEempQazlNKy9IUGxNSDFrblN0TVZoUjI1TkdRRTBvNHIKICAgICAgICAgbmJSYVlqalZCVk9KQkNHQmJNTDFTb3Rnd3RuVDQzb0drZXY5a3MwWnlmcFVrNkxvdVUzdS9uRmVXNGdRL3hXWHlheloKICAgICAgICAgQWdNdz09ClgtR20tTWVzc2FnZS1TdGF0ZTogQU9BTTUzMTdSbUMrUnovNUkzc2t6bzJIVThpeGptVFltNWpReU5WTGJ5ZElkYlQvNVB3WG1MNkMKCTBoQTNuWFBQcFlvWjdZYXAwYzB0Y0RWb2hvdGU5S2ljNEhGRis0YkFrZStuRmpxeDVTUHNObG52MGVjPQpYLVJlY2VpdmVkOiBieSAyMDAyOmFjYToxYTA1Ojogd2l0aCBTTVRQIGlkIGE1bXIyOTU2MzM2b2lhLjE0Ni4xNjM3MzU4NzM4MjMwOwogICAgICAgIEZyaSwgMTkgTm92IDIwMjEgMTM6NTI6MTggLTA4MDAgKFBTVCkKWC1Gb3J3YXJkZWQtVG86IGRvbS5mcmVzY2hldC4xQHZlcmthZGEuY29tClgtRm9yd2FyZGVkLUZvcjogZGZyZXNjaGV0QHZlcmthZGEuY29tIGRvbS5mcmVzY2hldC4xQHZlcmthZGEuY29tCkRlbGl2ZXJlZC1UbzogZGZyZXNjaGV0QHZlcmthZGEuY29tClJlY2VpdmVkOiBieSAyMDAyOmE5ZDo3MTFjOjA6MDowOjA6MCB3aXRoIFNNVFAgaWQgbjI4Y3NwMjYwNDU5Mm90ajsKICAgICAgICBGcmksIDE5IE5vdiAyMDIxIDEzOjUyOjE2IC0wODAwIChQU1QpClgtUmVjZWl2ZWQ6IGJ5IDIwMDI6YTY3OmNkOGI6OiB3aXRoIFNNVFAgaWQgcjExbXI5OTg2NTU5OXZzbC4yNy4xNjM3MzU4NzM2ODEyOwogICAgICAgIEZyaSwgMTkgTm92IDIwMjEgMTM6NTI6MTYgLTA4MDAgKFBTVCkKQVJDLVNlYWw6IGk9MTsgYT1yc2Etc2hhMjU2OyB0PTE2MzczNTg3MzY7IGN2PW5vbmU7CiAgICAgICAgZD1nb29nbGUuY29tOyBzPWFyYy0yMDE2MDgxNjsKICAgICAgICBiPVlCTHM0Tmg0Uzh2NDhRNjBlejRpcHI2YWFjUnozM2E4azJqYXZuTWFFRzBSdXZyUlhOSm9rWVM2R1BjUDhCV2tNcQogICAgICAgICBXbSs0dmdsSzJYdlBzRFNKR0pFUFcwSWFPUC9FWDZSTUVEbEhIRFRub3VGV3haMWkrbCt5d0UxUk1kV0lGQnloUDZzTwogICAgICAgICBWSVU0RGx1VTdWeCtGWjlUaHRJcUQ5QkpOSThIOEtLRWdsdDJZNzRNcDNxS3I5RzRkSTA1M3dtYlNBZ0RlbzAwNTU0VwogICAgICAgICBQc0F0UW8zS0JmYjJmNFZSNU1ZQ0VuRkY1NXBFNTZ1WWc4TElJWXZrZ29vTHVQK0txMUdPZGMvZk5iU0ZVdmVpRUp0cQogICAgICAgICBtZ2ZGRTlLNG9TbjA4b2FZaWlENXBlYmVta3QrWjdPaEl3OThVbWNsb2dwUFNpWnU3ZzI3dnlNQWdDUEdqbVUrdERUWAogICAgICAgICB4a0hBPT0KQVJDLU1lc3NhZ2UtU2lnbmF0dXJlOiBpPTE7IGE9cnNhLXNoYTI1NjsgYz1yZWxheGVkL3JlbGF4ZWQ7IGQ9Z29vZ2xlLmNvbTsgcz1hcmMtMjAxNjA4MTY7CiAgICAgICAgaD10bzpzdWJqZWN0Om1lc3NhZ2UtaWQ6ZGF0ZTpmcm9tOnJlcGx5LXRvOmluLXJlcGx5LXRvOnJlZmVyZW5jZXMKICAgICAgICAgOm1pbWUtdmVyc2lvbjpka2ltLXNpZ25hdHVyZTsKICAgICAgICBiaD1jNzRGdk9TUnNRemtZcFBLSjVwdTRYMHF4bjdBVkRZUlM4dWtkL3laSXBBPTsKICAgICAgICBiPWlmNmYwcmtRcmhsbVc3WjZzOEFMa0o0OSsrTzZGZXYvbFlncFFoemY1UWpCeTJjUVN6NlJXS3o3bXJSMTY2dEppQwogICAgICAgICBibURRVEx0VTV6Mmx4Vmo1a3Bmb0xkY2VJNzNvNnRsaDAyc1BJNUFhMFQxN200M0s4bFBwMzFLaHorMmdvQXMrd2RHRgogICAgICAgICBGRHZwbU1USXhVbHFkQzllM2tlb0F3bW54cUxpWTFsS3lWa0IwbDd3ZWp3NUtzSk5qV1N2bEJweW1tZlgzSHpENE85TQogICAgICAgICB0ekY4djNPbk55MzRqalpVYjdjVlRvVTlydGZyYi9uY0wzM1JDNDlYTXFDb05sbXpNUmthVzR0VXhYQWVSVi9pY3cyOQogICAgICAgICB4RjBQV3JkV1hZMDBack9XanYrbFlmdGRpQTZBdm1aRWNkbnJuZTVNUmtCMkhoT0E2TXZ1Y0c1Q0U1Z0tGSGo3NUZTRAogICAgICAgICBhZ0ZRPT0KQVJDLUF1dGhlbnRpY2F0aW9uLVJlc3VsdHM6IGk9MTsgbXguZ29vZ2xlLmNvbTsKICAgICAgIGRraW09cGFzcyBoZWFkZXIuaT1AZ21haWwuY29tIGhlYWRlci5zPTIwMjEwMTEyIGhlYWRlci5iPUd5K3pER0w0OwogICAgICAgc3BmPXBhc3MgKGdvb2dsZS5jb206IGRvbWFpbiBvZiBkYXRhY2hyb21lQGdtYWlsLmNvbSBkZXNpZ25hdGVzIDIwOS44NS4yMjAuNDEgYXMgcGVybWl0dGVkIHNlbmRlcikgc210cC5tYWlsZnJvbT1kYXRhY2hyb21lQGdtYWlsLmNvbTsKICAgICAgIGRtYXJjPXBhc3MgKHA9Tk9ORSBzcD1RVUFSQU5USU5FIGRpcz1OT05FKSBoZWFkZXIuZnJvbT1nbWFpbC5jb20KUmV0dXJuLVBhdGg6IDxkYXRhY2hyb21lQGdtYWlsLmNvbT4KUmVjZWl2ZWQ6IGZyb20gbWFpbC1zb3ItZjQxLmdvb2dsZS5jb20gKG1haWwtc29yLWY0MS5nb29nbGUuY29tLiBbMjA5Ljg1LjIyMC40MV0pCiAgICAgICAgYnkgbXguZ29vZ2xlLmNvbSB3aXRoIFNNVFBTIGlkIDEyNHNvcjM5MjM5OXZzei41OS4yMDIxLjExLjE5LjEzLjUyLjE2CiAgICAgICAgZm9yIDxkZnJlc2NoZXRAdmVya2FkYS5jb20-CiAgICAgICAgKEdvb2dsZSBUcmFuc3BvcnQgU2VjdXJpdHkpOwogICAgICAgIEZyaSwgMTkgTm92IDIwMjEgMTM6NTI6MTYgLTA4MDAgKFBTVCkKUmVjZWl2ZWQtU1BGOiBwYXNzIChnb29nbGUuY29tOiBkb21haW4gb2YgZGF0YWNocm9tZUBnbWFpbC5jb20gZGVzaWduYXRlcyAyMDkuODUuMjIwLjQxIGFzIHBlcm1pdHRlZCBzZW5kZXIpIGNsaWVudC1pcD0yMDkuODUuMjIwLjQxOwpES0lNLVNpZ25hdHVyZTogdj0xOyBhPXJzYS1zaGEyNTY7IGM9cmVsYXhlZC9yZWxheGVkOwogICAgICAgIGQ9Z21haWwuY29tOyBzPTIwMjEwMTEyOwogICAgICAgIGg9bWltZS12ZXJzaW9uOnJlZmVyZW5jZXM6aW4tcmVwbHktdG86cmVwbHktdG86ZnJvbTpkYXRlOm1lc3NhZ2UtaWQKICAgICAgICAgOnN1YmplY3Q6dG87CiAgICAgICAgYmg9Yzc0RnZPU1JzUXprWXBQS0o1cHU0WDBxeG43QVZEWVJTOHVrZC95WklwQT07CiAgICAgICAgYj1HeSt6REdMNFNxOGpWNXFDN2ROUjViZ0N4MXBjVzdQQlBMYTNld3hBUkJvT0wzcEpVV2UvOHFkbXl1MCtFVGhqK0YKICAgICAgICAgUDVyUUtyMGRycUEvcWR2Mnp5QWNQN3E5NVNycDFPL2p0U2x6QzMzZ2xMWTNETEV0RVNDZUNaSGNCc0daMzNXdGdjeGwKICAgICAgICAgVGdXUDZzckwvb01RVVJCUDZlRFZ4b0lsdDJ4UlgzS3hRVWRZOTZZeThrdU1COTVIYnlnNDlHZFJpSTVLdE5WZHN6WmMKICAgICAgICAgekRSam5Ba2t5TjJCQkpqeEtFT1NoYTZnWkM3SUxkTTJXVHlnYStacEhIVkVYNFplVWtad0VMRE9QMVRRVW5KTHZGUncKICAgICAgICAgVjE2TFdFVHd4QjNpVXdGcWV6WmYrcGJDSHNGcitSY1NtejdXK0FlNGtvd1Rod1lDWjZMV3JLNVFWT05MVEFEV3RCYkEKICAgICAgICAgQ1FEUT09ClgtR29vZ2xlLVNtdHAtU291cmNlOiBBQmRoUEp3eU1Jd1hFcW81VDRuSktTd3ltSThtT2krZXdxQU1RUGREbUJJTVNGU083eG9CRVlQSmpIQnE4NTBEYjJoQW13RGZFQ2RMbnBMR01uTkN3VDF0bGhvPQpYLVJlY2VpdmVkOiBieSAyMDAyOmEwNTo2MTAyOmE0YTo6IHdpdGggU01UUCBpZCBpMTBtcjk3NTI3ODIwdnNzLjQ3LjE2MzczNTg3MzY0Mzc7CiBGcmksIDE5IE5vdiAyMDIxIDEzOjUyOjE2IC0wODAwIChQU1QpCk1JTUUtVmVyc2lvbjogMS4wClJlZmVyZW5jZXM6IDwxODA4OTI2NTYyLjM4NDM4MjYwMy4xNjM3MzQ3NDU2MDM1QGFibWt0bWFpbC1iYXRjaDFsLm1hcmtldG8ub3JnPgpJbi1SZXBseS1UbzogPDE4MDg5MjY1NjIuMzg0MzgyNjAzLjE2MzczNDc0NTYwMzVAYWJta3RtYWlsLWJhdGNoMWwubWFya2V0by5vcmc-ClJlcGx5LVRvOiBjbHVicGlzY2luZXN1cGVyZml0bmVzc0BkYXRhY2hyb21lLmNvbQpGcm9tOiBKZWFuIFRhbG9uIDxkYXRhY2hyb21lQGdtYWlsLmNvbT4KRGF0ZTogRnJpLCAxOSBOb3YgMjAyMSAxNjo1MjowNSAtMDUwMApNZXNzYWdlLUlEOiA8Q0FQVFZhLU52VHAtNUVIZzFNVEU5ekFTWF9Wb3RfZ1d3M1NWOVA4RnlFNy1NOCtyYkt3QG1haWwuZ21haWwuY29tPgpTdWJqZWN0OiBSZTogSmVhbiAtIGhvbGlkYXkgZ2lmdCBmb3IgQ2x1YiBQaXNjaW5lIFN1cGVyIEZpdG5lc3M_ClRvOiBkZnJlc2NoZXRAdmVya2FkYS5jb20KQ29udGVudC1UeXBlOiBtdWx0aXBhcnQvYWx0ZXJuYXRpdmU7IGJvdW5kYXJ5PSIwMDAwMDAwMDAwMDBkYWY2MzkwNWQxMmI0OTZmIgoKLS0wMDAwMDAwMDAwMDBkYWY2MzkwNWQxMmI0OTZmCkNvbnRlbnQtVHlwZTogdGV4dC9wbGFpbjsgY2hhcnNldD0iVVRGLTgiCgpIaSBEb20sCgpUaGFua3MgZm9yIHJlYWNoaW5nIG91dC4KCkFjdHVhbGx5IHlvdSBqdXN0IHJlbWluZGVkIG1lLCBJIGRpZCBub3QgcmVjZWl2ZSBteSBnaWZ0IGZyb20gdGhlIHByZXZpb3VzCnRpbWUgSSB3YXMgaW52aXRlZCB0byB5b3VyIHdlYmluYXIgYmFjayBhdCB0aGUgZW5kIG9mIFNlcHRlbWJlciwgc28gaWYgeW91CmNvdWxkIGxvb2sgaW50byB0aGlzLCBJIHdvdWxkIGdyZWF0bHkgYXBwcmVjaWF0ZSBpdC4KCkkgd2FzIGp1c3QgZ2V0dGluZyByZWFkeSB0byBwYWNrIGl0IGluIGZvciB0aGlzIHdlZWssIHNvIEknbGwgY2hlY2sgYmFjawpuZXh0IHdlZWsuCgpIYXZlIHlvdXJzZWxmIGEgZ3JlYXQgd2Vla2VuZCwKCkplYW4KCgpPbiBGcmksIE5vdiAxOSwgMjAyMSBhdCAxOjQ0IFBNIERvbSBGcmVzY2hldCA8ZGZyZXNjaGV0QHZlcmthZGEuY29tPiB3cm90ZToKCj4gSGV5IEplYW4sCj4KPiBIYXBweSBGcmlkYXkhIEhvcGUgeW91IGhhdmUgd29uZGVyZnVsIGhvbGlkYXkgcGxhbnMgZm9yIG5leHQgd2VlayBhbmQgdGhhdAo-IGV2ZXJ5b25lIGlzIHN0YXlpbmcgd2VsbCBhdCBDbHViIFBpc2NpbmUgU3VwZXIgRml0bmVzcy4gTXkgbmFtZSBpcyBEb20gYW5kCj4gSSBydW4gRGV2ZWxvcG1lbnQgYXQgVmVya2FkYS4KPgo-IFdhbnRlZCB0byB0b3VjaCBiYXNlIGFzIGl0IGxvb2tzIGxpa2Ugc29tZW9uZSBvbiBteSB0ZWFtIHRyaWVkIHRvIHJlYWNoCj4gb3V0IHRvIHlvdSBhIGNvdXBsZSB3ZWVrcyBiYWNrLCBKZWFuIC0tIG5vdCBzdXJlIGlmIHlvdSdkIHJlY2VpdmVkIG9uZSBvZgo-IG91ciBmYW1vdXMgVmVya2FkYSBZRVRJcyB5ZXQ_IElmIG5vdCwgd2hlcmUgY291bGQgSSBzaGlwIG9uZSBvdXQgYXMgYSB0b2tlbgo-IG9mIGdyYXRpdHVkZSBiZWZvcmUgdGhlIGhvbGlkYXlzPwo-Cj4gQW5kIGlmIHlvdSBoYXZlIGEgZmV3IG1pbnMgLS0gd291bGQgeW91IGJlIHdpbGxpbmcgdG8gdGFsayB0byBhIG1lbWJlciBvZgo-IG15IHRlYW0gYWJvdXQgd2h5IDcwMDArIGN1c3RvbWVycyBsb3ZlIFZlcmthZGEsIG9yIGNhbiB5b3UgcG9pbnQgbWUgdG8gdGhlCj4gcmlnaHQgcGVyc29uIGF0IENsdWIgUGlzY2luZSBTdXBlciBGaXRuZXNzPwo-IC0gT25lLWNhYmxlLCA8MTAtbWluIGluc3RhbGwgcHJvY2VzcyB3aXRoIGNhbWVyYXMvc2Vuc29ycyB0aGF0Cj4gc2VsZi11cGRhdGUuIE5vIERWUnMsIE5WUnMsIHNldHVwIHBhaW4sIGZpcm13YXJlIHVwZ3JhZGVzLCBvciBvdGhlcgo-IGZ1c3MvY29zdC4KPiAtIENvbmNpZXJnZSBtYW5hZ2VtZW50IC0tIGNoZWNrIGluIHZpc2l0b3JzIChkZWxpdmVyeSBkcml2ZXJzLAo-IGludGVydmlld2VlcywgY29udHJhY3RvcnMpIGluIG9uZSBwbGFjZSwgbm90aWZ5IGhvc3RzLCBldGMuCj4gLSAyNC03IHByb2Zlc3Npb25hbCBpbnRydXNpb24gbW9uaXRvcmluZwo-IC0gSW5kdXN0cnktbGVhZGluZyAxMC15ZWFyIHdhcnJhbnR5Cj4KPiBEb2VzIGl0IG1ha2Ugc2Vuc2UgdG8gY29ubmVjdCBmb3IgNSBtaW51dGVzIHRvZGF5IG9yIE1vbmRheSwgSmVhbj8KPgo-Cj4gRG9tIEZyZXNjaGV0Cj4gU2VuaW9yIE1hbmFnZXIsIERldmVsb3BtZW50Cj4gVmVya2FkYSwgNDA1IEUgNHRoIEF2ZSwgU2FuIE1hdGVvLCBDQSA5NDQwMSwgVVNBCj4KPiBPcHQgb3V0OiBodHRwczovL3ZlcmthZGEuY29tL2VtYWlsc2V0dGluZ3MKPgoKLS0wMDAwMDAwMDAwMDBkYWY2MzkwNWQxMmI0OTZmCkNvbnRlbnQtVHlwZTogdGV4dC9odG1sOyBjaGFyc2V0PSJVVEYtOCIKQ29udGVudC1UcmFuc2Zlci1FbmNvZGluZzogcXVvdGVkLXByaW50YWJsZQoKPGRpdiBkaXI9M0QibHRyIj48ZGl2PkhpIERvbSw8L2Rpdj48ZGl2Pjxicj48L2Rpdj48ZGl2PlRoYW5rcyBmb3IgcmVhY2hpbmcgPQpvdXQuPC9kaXY-PGRpdj48YnI-PC9kaXY-PGRpdj5BY3R1YWxseSB5b3UganVzdCByZW1pbmRlZCBtZSwgSSBkaWQgbm90IHJlY2U9Cml2ZSBteSBnaWZ0IGZyb20gdGhlIHByZXZpb3VzIHRpbWUgSSB3YXMgaW52aXRlZCB0byB5b3VyIHdlYmluYXIgYmFjayBhdCB0aD0KZSBlbmQgb2YgU2VwdGVtYmVyLCBzbyBpZiB5b3UgY291bGQgbG9vayBpbnRvIHRoaXMsIEkgd291bGQgZ3JlYXRseSBhcHByZWNpPQphdGUgaXQuPC9kaXY-PGRpdj48YnI-PC9kaXY-PGRpdj5JIHdhcyBqdXN0IGdldHRpbmcgcmVhZHkgdG8gcGFjayBpdCBpbiBmb3I9CiB0aGlzIHdlZWssIHNvIEkmIzM5O2xsIGNoZWNrIGJhY2sgbmV4dCB3ZWVrLjwvZGl2PjxkaXY-PGJyPjwvZGl2PjxkaXY-SGF2ZT0KIHlvdXJzZWxmIGEgZ3JlYXQgd2Vla2VuZCw8L2Rpdj48ZGl2Pjxicj48L2Rpdj48ZGl2PkplYW48L2Rpdj48ZGl2Pjxicj48L2RpPQp2PjwvZGl2Pjxicj48ZGl2IGNsYXNzPTNEImdtYWlsX3F1b3RlIj48ZGl2IGRpcj0zRCJsdHIiIGNsYXNzPTNEImdtYWlsX2F0dHI9CiI-T24gRnJpLCBOb3YgMTksIDIwMjEgYXQgMTo0NCBQTSBEb20gRnJlc2NoZXQgJmx0OzxhIGhyZWY9M0QibWFpbHRvOmRmcmVzYz0KaGV0QHZlcmthZGEuY29tIj5kZnJlc2NoZXRAdmVya2FkYS5jb208L2E-Jmd0OyB3cm90ZTo8YnI-PC9kaXY-PGJsb2NrcXVvdGUgPQpjbGFzcz0zRCJnbWFpbF9xdW90ZSIgc3R5bGU9M0QibWFyZ2luOjBweCAwcHggMHB4IDAuOGV4O2JvcmRlci1sZWZ0OjFweCBzb2w9CmlkIHJnYigyMDQsMjA0LDIwNCk7cGFkZGluZy1sZWZ0OjFleCI-SGV5IEplYW4sPGJyPgo8YnI-CkhhcHB5IEZyaWRheSEgSG9wZSB5b3UgaGF2ZSB3b25kZXJmdWwgaG9saWRheSBwbGFucyBmb3IgbmV4dCB3ZWVrIGFuZCB0aGF0ID0KZXZlcnlvbmUgaXMgc3RheWluZyB3ZWxsIGF0IENsdWIgUGlzY2luZSBTdXBlciBGaXRuZXNzLiBNeSBuYW1lIGlzIERvbSBhbmQgPQpJIHJ1biBEZXZlbG9wbWVudCBhdCBWZXJrYWRhLjxicj4KPGJyPgpXYW50ZWQgdG8gdG91Y2ggYmFzZSBhcyBpdCBsb29rcyBsaWtlIHNvbWVvbmUgb24gbXkgdGVhbSB0cmllZCB0byByZWFjaCBvdXQ9CiB0byB5b3UgYSBjb3VwbGUgd2Vla3MgYmFjaywgSmVhbiAtLSBub3Qgc3VyZSBpZiB5b3UmIzM5O2QgcmVjZWl2ZWQgb25lIG9mID0Kb3VyIGZhbW91cyBWZXJrYWRhIFlFVElzIHlldD8gSWYgbm90LCB3aGVyZSBjb3VsZCBJIHNoaXAgb25lIG91dCBhcyBhIHRva2VuPQogb2YgZ3JhdGl0dWRlIGJlZm9yZSB0aGUgaG9saWRheXM_PGJyPgo8YnI-CkFuZCBpZiB5b3UgaGF2ZSBhIGZldyBtaW5zIC0tIHdvdWxkIHlvdSBiZSB3aWxsaW5nIHRvIHRhbGsgdG8gYSBtZW1iZXIgb2YgbT0KeSB0ZWFtIGFib3V0IHdoeSA3MDAwKyBjdXN0b21lcnMgbG92ZSBWZXJrYWRhLCBvciBjYW4geW91IHBvaW50IG1lIHRvIHRoZSByPQppZ2h0IHBlcnNvbiBhdCBDbHViIFBpc2NpbmUgU3VwZXIgRml0bmVzcz88YnI-Ci0gT25lLWNhYmxlLCAmbHQ7MTAtbWluIGluc3RhbGwgcHJvY2VzcyB3aXRoIGNhbWVyYXMvc2Vuc29ycyB0aGF0IHNlbGYtdXBkYT0KdGUuIE5vIERWUnMsIE5WUnMsIHNldHVwIHBhaW4sIGZpcm13YXJlIHVwZ3JhZGVzLCBvciBvdGhlciBmdXNzL2Nvc3QuPGJyPgotIENvbmNpZXJnZSBtYW5hZ2VtZW50IC0tIGNoZWNrIGluIHZpc2l0b3JzIChkZWxpdmVyeSBkcml2ZXJzLCBpbnRlcnZpZXdlZXM9CiwgY29udHJhY3RvcnMpIGluIG9uZSBwbGFjZSwgbm90aWZ5IGhvc3RzLCBldGMuPGJyPgotIDI0LTcgcHJvZmVzc2lvbmFsIGludHJ1c2lvbiBtb25pdG9yaW5nPGJyPgotIEluZHVzdHJ5LWxlYWRpbmcgMTAteWVhciB3YXJyYW50eTxicj4KPGJyPgpEb2VzIGl0IG1ha2Ugc2Vuc2UgdG8gY29ubmVjdCBmb3IgNSBtaW51dGVzIHRvZGF5IG9yIE1vbmRheSwgSmVhbj88YnI-Cjxicj4KPGJyPgpEb20gRnJlc2NoZXQ8YnI-ClNlbmlvciBNYW5hZ2VyLCBEZXZlbG9wbWVudDxicj4KVmVya2FkYSwgNDA1IEUgNHRoIEF2ZSwgU2FuIE1hdGVvLCBDQSA5NDQwMSwgVVNBPGJyPgo8YnI-Ck9wdCBvdXQ6IDxhIGhyZWY9M0QiaHR0cHM6Ly92ZXJrYWRhLmNvbS9lbWFpbHNldHRpbmdzIiByZWw9M0Qibm9yZWZlcnJlciIgdD0KYXJnZXQ9M0QiX2JsYW5rIj5odHRwczovL3ZlcmthZGEuY29tL2VtYWlsc2V0dGluZ3M8L2E-PGJyPgo8L2Jsb2NrcXVvdGU-PC9kaXY-CgotLTAwMDAwMDAwMDAwMGRhZjYzOTA1ZDEyYjQ5NmYtLQo="

        decoded_email_body = (
            """Subject: Fwd: Hugo - holiday gift for Gunnison Fire Department?
From: JJ Hump <jason@verkada.com>
To: Brent Piephoff <brent@verkada.com>
Content-Type: multipart/alternative; boundary="0000000000004a393b05d12cad30"

--0000000000004a393b05d12cad30
Content-Type: text/plain; charset="UTF-8"

test

---------- Forwarded message ---------"""
            + decoded_email_body
        )

        self.LOG.info(f"message_bytes is  {decoded_email_body}")

        message = MIMEText(str(decoded_email_body))
        message["to"] = to
        message["from"] = "datachrome@gmail.com"
        message["cc"] = None

        # self.LOG.info(f"New message is: {message.as_string()}")

        email_body = {
            "raw": base64.urlsafe_b64encode(decoded_email_body.encode()).decode()
        }

        # raw = base64.urlsafe_b64encode(str(decoded).encode())
        # self.LOG.info(f"Raw is: {raw}")

        # email_body =  {'raw': base64.urlsafe_b64encode(str(decoded).encode()).decode()}

        # email_body =  {'raw': encoded_test}

        msg = (
            self.service.users()
            .messages()
            .send(userId=from_user_id, body=email_body)
            .execute()
        )

        # return msg

    def delete_message(self, user_id, email_id):

        self.LOG.info("Deleting email {} for {}".format(email_id, user_id))

        res = (
            self.service.users()
            .messages()
            .delete(id=email_id, userId=user_id)
            .execute()
        )

        print(res)

        self.LOG.info("Successfully deleted email {} for {}".format(email_id, user_id))

    def get_label_list(self, user_id):

        self.LOG.info("Getting list of labels for gmail account: {}".format(user_id))

        res = self.service.users().labels().list(userId=user_id).execute()

        return res["labels"]

    def identify_bad_deliverability_status(self, message):

        self.LOG.info("Identifying if this email message is a deliverability report")

        address_reported = False

        # Look through each header and try to find 'X-Failed-Recipients'
        for header in message["payload"]["headers"]:
            if header["name"] == "X-Failed-Recipients":
                report_found = True
                address_reported = header["value"]

        if address_reported:
            self.LOG.info(
                "Found undeliverable email address: {}".format(address_reported)
            )

            match = re.search(r"<(.*)>", address_reported)
            if match == None:
                return address_reported
            else:
                return match.group(1)

        # For Microsoft Office 365
        # If 'X-Failed-Recipients' is not found we need to look for 'Content-Type' header
        #   Within this header look for 'report-type=delivery-status'
        else:
            for header in message["payload"]["headers"]:
                if (
                    header["name"] == "Content-Type"
                    and "delivery-status" in header["value"]
                ):
                    for part_1 in message["payload"]["parts"]:
                        if "parts" in part_1:
                            for part_2 in part_1["parts"]:
                                for deep_header in part_2["headers"]:
                                    if deep_header["name"] == "To":
                                        address_reported = deep_header["value"]
                        # Some email jsons don't have a To: field<(.*)>. Last ditch effort is to look in the snippet
                        else:
                            match = re.search(r"&#39;(.*@.*)&#39;", message["snippet"])
                            if match:
                                self.LOG.info(
                                    "Found undeliverable email address from snippet: {}".format(
                                        match.group(1)
                                    )
                                )
                                return match.group(1)

        if address_reported:
            self.LOG.info(
                "Found undeliverable email address for Office 365 address: {}".format(
                    address_reported
                )
            )

            match = re.search(r"<(.*)>", address_reported)
            if match == None:
                return address_reported
            else:
                return match.group(1)

        else:
            self.LOG.warning("Did not find deliverability email for this message")
            return address_reported

    def remove_message_label(self, message_id, user_id, label_id):

        try:

            self.LOG.info(
                "Removing label {} for message {} under the account {}".format(
                    label_id, message_id, user_id
                )
            )

            request_body = {"removeLabelIds": [label_id]}

            res = (
                self.service.users()
                .messages()
                .modify(userId=user_id, id=message_id, body=request_body)
                .execute()
            )

            self.LOG.info(
                "Successfully removed label {} for message {} under the account {}".format(
                    label_id, message_id, label_id
                )
            )

            return True

        except errors.HttpError as error:

            self.LOG.info("An error occurred: {}".format(error))

            return True
