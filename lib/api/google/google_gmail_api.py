#!/usr/bin/env python

from __future__ import print_function
import os
import re
import base64
import pickle
import os.path
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
from datetime import datetime, timedelta

VSCO_CREDS_PATH = "./var/creds/google/bookmeetingservice.json"
GSYNC_CREDS_PATH = "./var/creds/google/gsync_service.json"

class GoogleGmailSDK():

  def __init__(self, log, user):

    self.LOG = log

    self.LOG.info("Initializing Google Gmail API")

    self.scope = ['https://www.googleapis.com/auth/gmail.send',
                  'https://www.googleapis.com/auth/gmail.readonly',
                  'https://www.googleapis.com/auth/gmail.modify']

    """Shows basic usage of the Sheets API.
    Prints values from a sample spreadsheet.
    """
    creds = None
    self.account = user

    if "@verkadasecurity.co" in user:
      creds = creds = service_account.Credentials.from_service_account_file(VSCO_CREDS_PATH, scopes=self.scope).with_subject(self.account)
    else:
      creds = creds = service_account.Credentials.from_service_account_file(GSYNC_CREDS_PATH, scopes=self.scope).with_subject(self.account)

    self.service = build('gmail', 'v1', credentials=creds, cache_discovery=False)

    self.LOG.info("Successfully initialized Google Gmail API")


  def get_labeled_emails(self, label):

    self.LOG.info("Getting emails with '{}' label for {}".format(label, self.account))

    final_email_list = []
    label_str = "label:{}".format(label)

    res = self.service.users().messages().list(userId=self.account, q=label_str).execute()

    if 'messages' in res.keys():
      for message in res['messages']:
        final_email_list.append(message)

    else:
      self.LOG.info("There are no messages labled {} for {}".format(label, self.account))
      return False

    while 'nextPageToken' in res.keys():

      self.LOG.info('Need to query the next page for list of email messages')

      token = res['nextPageToken']
      res = self.service.users().messages().list(userId=self.account, q=label_str, pageToken=token).execute()

      if 'messages' in res.keys():
        for message in res['messages']:
          final_email_list.append(message)

    self.LOG.info("Got a list of {} emails with label {} for {}".format(len(final_email_list), label, self.account))

    return(final_email_list)

  # Get a list of all messages in the accounts inbox
  def get_emails_in_inbox(self):

    self.LOG.info("Getting inbox emails for {}".format(self.account))

    final_email_list = []
    search_str = 'in:inbox'
    res = self.service.users().messages().list(userId=self.account, q=search_str).execute()

    if 'messages' in res.keys():
      for message in res['messages']:
        final_email_list.append(message)
    else:
      self.LOG.info("There are no messages in Inbox for {}".format(self.account))

    while 'nextPageToken' in res.keys():

      self.LOG.info('Need to query the next page for list of email messages')

      token = res['nextPageToken']
      res = self.service.users().messages().list(userId=self.account, q=search_str, pageToken=token).execute()

      for message in res['messages']:
        final_email_list.append(message)

    self.LOG.info("Got {} emails from inbox: {}".format(len(final_email_list), self.account))

    return final_email_list

  # Get a list of all messages received in last 24 hours in the accounts inbox
  def get_last_24_hour_emails(self):

    self.LOG.info("Getting emails from the last 24 hours for {}".format(self.account))

    final_email_list = []
    search_str = 'newer_than:1d'
    res = self.service.users().messages().list(userId=self.account, q=search_str).execute()

    if 'messages' in res.keys():
      for message in res['messages']:
        final_email_list.append(message)
    else:
      self.LOG.info("There are no messages in Inbox for {}".format(self.account))

    while 'nextPageToken' in res.keys():

      self.LOG.info('Need to query the next page for list of email messages')

      token = res['nextPageToken']
      res = self.service.users().messages().list(userId=self.account, q=search_str, pageToken=token).execute()

      for message in res['messages']:
        final_email_list.append(message)

    self.LOG.info("Got {} emails from inbox: {}".format(len(final_email_list), self.account))

    return final_email_list


  def get_undeliverable_emails(self):

    self.LOG.info("Getting undeliverable messages for {}".format(self.account))

    final_email_list = []
    # Get Inbox undeliverables
    search_str = 'undeliverable newer_than:1d'

    res = self.service.users().messages().list(userId=self.account, q=search_str).execute()

    if 'messages' in res.keys():
      for message in res['messages']:
        final_email_list.append(message)
    else:
      self.LOG.info("There are no undeliverable messages in Inbox for {}".format(self.account))

    while 'nextPageToken' in res.keys():

      self.LOG.info('Need to query the next page for list of email messages')

      token = res['nextPageToken']
      res = self.service.users().messages().list(userId=self.account, q=search_str, pageToken=token).execute()

      for message in res['messages']:
        final_email_list.append(message)

    # Get Spam undeliverables
    search_str = 'in:spam AND undeliverable, AND newer_than:1d'

    res = self.service.users().messages().list(userId=self.account, q=search_str).execute()

    if 'messages' in res.keys():
      for message in res['messages']:
        final_email_list.append(message)
    else:
      self.LOG.info("There are no undeliverable messages in Spam for {}".format(self.account))

    while 'nextPageToken' in res.keys():

      self.LOG.info('Need to query the next page for list of email messages')

      token = res['nextPageToken']
      res = self.service.users().messages().list(userId=self.account, q=search_str, pageToken=token).execute()

      for message in res['messages']:
        final_email_list.append(message)

    if len(final_email_list) == 0:
      self.LOG.warning("There are no undeliverable messages in Inbox AND Spam for {}".format(self.account))
      return False

    self.LOG.info("Got a list of {} undeliverable emails for {}".format(len(final_email_list), self.account))

    return(final_email_list)


  def get_email_message(self, email_address, email_id):

    self.LOG.info("Getting email content for {} and message ID: {}" \
                  .format(email_address, email_id))

    res = self.service.users().messages().get(id=email_id, userId=email_address).execute()

    self.LOG.info("Successfully got message content for message ID: {}".format(email_id))

    return res


  def send_email(self, user_id, message):

    self.LOG.info("Sending email from {}".format(user_id))

    message = self.service.users().messages().send(userId=user_id, body=message).execute()

    self.LOG.info("Message Id: {}".format(message['id']))

    return message


  def create_email(self, sender, to, subject, message_text, reply_to=None, url=None, cc=None, html=False):

    self.LOG.info("Creating email '{}' to send to {}, from {}".format(subject, to, sender))

    if html=='html':
      message = MIMEText(message_text,html)
    else:
      message = MIMEText(message_text)
    message['to'] = to
    message['from'] = sender
    message['subject'] = subject
    if url:
      message['url'] = url
    else:
      message['url'] = 'test'
    if cc:
      message['cc'] = cc
    if reply_to:
      message['reply-to'] = reply_to

    self.LOG.info("Successfully created email")

    return {'raw': base64.urlsafe_b64encode(message.as_string().encode()).decode()}

  
  def create_email_with_jpg(self, sender, to, subject, message_html, img_path, img_cid, url, cc=None):
    # THIS IS A TEST FUNCTION. NO GUARANTEE IT WORKS

    self.LOG.info("Creating email '{}' to send to {}, from {}, with image {}".format(subject, to, sender, img_path))

    # Load in image, as bytes
    img_data = open(img_path, 'rb').read()

    # Create related message container that will hold the HTML msg and the image
    html_part = MIMEMultipart(_subtype='related')

    # Create body with HTML. 
    body = MIMEText(message_html, _subtype = 'html')
    html_part.attach(body)

    # Create MIME container for the image
    img = MIMEImage(img_data, 'jpg')
    img.add_header('Content-Id', '<{}>'.format(img_cid)) # angle brackets are important
    img.add_header('Content-Disposition', 'inline', filename=img_cid)
    html_part.attach(img)

    # Add info to message
    html_part['to'] = to
    html_part['from'] = sender
    html_part['subject'] = subject
    html_part['url'] = url
    if cc:
      html_part['cc'] = cc

    self.LOG.info("Successfully created email with image")
    return {'raw': base64.urlsafe_b64encode(html_part.as_string().encode()).decode()}




  def delete_message(self, user_id, email_id):

    self.LOG.info("Deleting email {} for {}".format(email_id, user_id))

    res = self.service.users().messages().delete(id=email_id, userId=user_id).execute()

    print(res)

    self.LOG.info("Successfully deleted email {} for {}".format(email_id, user_id))


  def get_label_list(self, user_id):

    self.LOG.info("Getting list of labels for gmail account: {}".format(user_id))

    res = self.service.users().labels().list(userId=user_id).execute()

    return res['labels']


  def identify_bad_deliverability_status(self, message):

    self.LOG.info('Identifying if this email message is a deliverability report')

    address_reported = False

    # Look through each header and try to find 'X-Failed-Recipients'
    for header in message['payload']['headers']:
      if header['name'] == 'X-Failed-Recipients':
        report_found = True
        address_reported = header['value']

    if address_reported:
      self.LOG.info("Found undeliverable email address: {}".format(address_reported))

      match = re.search(r'<(.*)>', address_reported)
      if match == None:
        return address_reported
      else:
        return match.group(1)

    # For Microsoft Office 365
    # If 'X-Failed-Recipients' is not found we need to look for 'Content-Type' header
    #   Within this header look for 'report-type=delivery-status'
    else:
      for header in message['payload']['headers']:
        if header['name'] == 'Content-Type' and 'delivery-status' in header['value']:
          for part_1 in message['payload']['parts']:
            if 'parts' in part_1:
              for part_2 in part_1['parts']:
                for deep_header in part_2['headers']:
                  if deep_header['name'] == 'To':
                    address_reported = deep_header['value']
            # Some email jsons don't have a To: field<(.*)>. Last ditch effort is to look in the snippet
            else:
              match = re.search(r"&#39;(.*@.*)&#39;", message['snippet'])
              if match:
                self.LOG.info("Found undeliverable email address from snippet: {}".format(match.group(1)))
                return match.group(1)


    if address_reported:
      self.LOG.info("Found undeliverable email address for Office 365 address: {}" \
                    .format(address_reported))

      match = re.search(r'<(.*)>', address_reported)
      if match == None:
        return address_reported
      else:
        return match.group(1)

    else:
      self.LOG.warning('Did not find deliverability email for this message')
      return address_reported


  def remove_message_label(self, message_id, user_id, label_id):

    try:

      self.LOG.info("Removing label {} for message {} under the account {}" \
                    .format(label_id, message_id, user_id))

      request_body = { 'removeLabelIds': [label_id] }

      res = self.service.users().messages().modify(userId=user_id,
                                                   id=message_id,
                                                   body=request_body).execute()

      self.LOG.info("Successfully removed label {} for message {} under the account {}" \
                    .format(label_id, message_id, label_id))

      return True

    except errors.HttpError as error:

      self.LOG.error("An error occurred: {}".format(error))

      return True




  def remove_thread_label(self, thread_id, user_id, label_id):
    """
    Remove a given label from a given thread.
    E.G. Can be used to mark a thread as read.
    I'm not actually sure if this also removes the label from
    every email in the thread as well.
    """
    try:

      self.LOG.info("Removing label {} for thread {} under the account {}" \
                    .format(label_id, thread_id, user_id))

      request_body = { 'removeLabelIds': [label_id] }

      res = self.service.users().threads().modify(userId=user_id,
                                                   id=thread_id,
                                                   body=request_body).execute()

      self.LOG.info("Successfully removed label {} for thread {} under the account {}" \
                    .format(label_id, thread_id, label_id))

      return True

    except errors.HttpError as error:

      self.LOG.error("An error occurred while removing label from thread:\n{}".format(error))

      return False

  '''
  Special case of above functions.
  Mark email/thread as read
  '''
  def mark_email_as_read(self, message_id):
    self.remove_message_label(message_id, self.account, 'UNREAD')
  def mark_thread_as_read(self, thread_id):
    # Also marks emails within the thread as read
    self.remove_thread_label(thread_id, self.account, 'UNREAD')

  
  def add_message_label(self, message_id, user_id, label_id):
    '''
    Add label to an email
    '''
    try:
      self.LOG.info("Add label {} for message {} under the account {}" \
                    .format(label_id, message_id, user_id))

      request_body = { 'addLabelIds': [label_id] }

      res = self.service.users().messages().modify(userId=user_id,
                                                   id=message_id,
                                                   body=request_body).execute()

      self.LOG.info("Successfully added label {} for message {} under the account {}" \
                    .format(label_id, message_id, user_id))

      return True

    except errors.HttpError as error:

      self.LOG.error("An error occurred: {}".format(error))

      return True



  def get_last_24_hour_threads(self):
    """
    Fetch all threads from the last 24 hrs
    """
    
    self.LOG.info("Getting inbox threads from last 24 hrs for {}".format(self.account))

    final_thread_list = []
    search_str = 'newer_than:1d'

    # threads.list fetches all thread IDs (in last 24 hr)
    threads = self.service.users().threads().list(userId=self.account, q=search_str).execute().get('threads', [])
    if len(threads)==0:
      self.LOG.info("There are no threads from last 24 hr in Inbox for {}".format(self.account))
      return []

    for thread in threads:
      # threads.get grabs all messages in each thread
      tdata = self.service.users().threads().get(userId=self.account, id=thread['id']).execute()
      final_thread_list.append(tdata)

    self.LOG.info("Got {} threads from inbox: {}".format(len(final_thread_list), self.account))

    return final_thread_list

  def get_threads_via_query(self, q):
    """
    Fetch threads according to a given Gmail query.
    E.G. For threads from the last hour, use q='newer_than:1h'
    """

    self.LOG.info("Getting inbox threads for {} that satisfy the query: {}".format(self.account, q))
    final_thread_list = []

    # threads.list getches all thread IDs satisfying the query
    threads = self.service.users().threads().list(userId=self.account, q=q).execute().get('threads', [])
    if len(threads)==0:
      self.LOG.info("There are no threads satisfying query {} in Inbox for {}".format(q, self.account))
      return []

    for thread in threads:
      # threads.get grabs all messages in each thread
      tdata = self.service.users().threads().get(userId=self.account, id=thread['id']).execute()
      final_thread_list.append(tdata)

    self.LOG.info("Got {} threads from inbox: {}".format(len(final_thread_list), self.account))

    return final_thread_list


  def create_reply_email(self, sender, to, message_id, thread_id, subject, message_text, cc=None, bcc=None):
    """
    Create a reply email to respond within the same thread, NOT creating a separate thread.
    Need the thread ID as well as the message ID of the most recent email in that thread.
    This message ID is NOT message['id'] but rather header['value'] where header['name']=='Message-ID"
    and header is in message['headers']
    """
    self.LOG.info("Creating email '{}' to send to {}, from {}, within the same thread".format(subject, to, sender))

    message = MIMEText(message_text)
    message['to'] = to
    message['from'] = sender
    message['subject'] = subject
    message['In-Reply-To'] = message_id
    message['References'] = message_id
    if cc:
      message['cc'] = cc
    if bcc:
      message['bcc'] = bcc

    self.LOG.info("Successfully created reply email in thread")

    return {
      'raw': base64.urlsafe_b64encode(message.as_string().encode()).decode(),
      'threadId': thread_id
      } 



  def get_calendar_event_info(self, LOG, message):
      """
      Returns a dictionary with the fields we were able to extract from the invite.ics of a message.

      E.G. 
      method and partstat: "METHOD" and "PARTSTAT" (participation status) from the invite.ics file.
      i.e. ("REPLY"/"REQUEST", "ACCEPTED"/"TENTATIVELY ACCEPTED"/"DECLINED").

      E.G.
      UID: The unique identifier of the event (for GoogleCalendar)

      E.G. "X-RESPONSE-COMMENT" when they responded with a note. (mainly when METHOD is COUNTER)
          X-RESPONSE-COMMENT="Hey how are you":mailto

      Prospects using many different ESPs, as well as different languages, makes the invite.ics file
      the only reliable way to extract calendar event info from an email. 

      If no invite.ics found, return False, not an empty dictionary.
      If no invite.ics but subject seems to indicate a calendar email, raise a ValueError
      """ 

      # Get subject info we need
      subject = ''
      for header in message['payload']['headers']:
          if header['name'] != 'Subject': continue 
          subject = header['value']
          break

      correct_prefix_subject = False
      if len(subject) >= 9 and subject[:9] == 'Accepted:':
          correct_prefix_subject = True
      elif len(subject) >= 9 and subject[:9] == 'Declined':
          correct_prefix_subject = True
      elif len(subject) >= 21 and subject[:21] == 'Tentatively Accepted:':
          correct_prefix_subject = True

      subject_has_at = '@' in subject


      # Get invite.ics attachment, if it exists
      has_invite_ics = False
      att_data = []
      if message['payload'].get('filename') == 'invite.ics':
          LOG.error("Found invite.ics in top-level email message") # error because it should be in child-level
          has_invite_ics = True
          if 'data' in message['payload']['body']:
            file_data = base64.urlsafe_b64decode(message['payload']['body']['data'].encode('UTF-8'))
            att_data.append(file_data)
          else:
            att_id = message['payload']['body']['attachmentId']
            att = self.service.users().messages().attachments().get(
                userId=self.account,
                messageId=message['id'],
                id=att_id
            ).execute()
            file_data = base64.urlsafe_b64decode(att['data'].encode('UTF-8'))
            att_data.append(file_data)
      else:
          if 'parts' in message['payload']:
            for child in message['payload']['parts']:

              # Child-level file
              if child.get('filename') == 'invite.ics':
                  LOG.info("Found invite.ics in child-level email message")
                  has_invite_ics = True
                  if 'data' in child['body']:
                    file_data = base64.urlsafe_b64decode(child['body']['data'].encode('UTF-8'))
                    att_data.append(file_data)
                  else:
                    att_id = child['body']['attachmentId']
                    att = self.service.users().messages().attachments().get(
                        userId=self.account,
                        messageId=message['id'],
                        id=att_id
                    ).execute()
                    file_data = base64.urlsafe_b64decode(att['data'].encode('UTF-8'))
                    att_data.append(file_data)

              # Grandchild-level file
              for grandchild in child.get('parts', []):
                if grandchild.get('filename') == 'invite.ics':
                  LOG.info("Found invite.ics in grandchild-level email message")
                  has_invite_ics = True
                  if 'data' in grandchild['body']:
                    file_data = base64.urlsafe_b64decode(grandchild['body']['data'].encode('UTF-8'))
                    att_data.append(file_data)
                  else:
                    att_id = grandchild['body'].get('attachmentId')
                    att = self.service.users().messages().attachments().get(
                        userId=self.account,
                        messageId=message['id'],
                        id=att_id
                    ).execute()
                    file_data = base64.urlsafe_b64decode(att['data'].encode('UTF-8'))
                    att_data.append(file_data)




      # If email looks like calendar event, action
      if correct_prefix_subject and subject_has_at and (not has_invite_ics):
        err_msg = "Found email that satisfies all criteria for calendar invite reaction" \
                        " except having the invite.ics attachment. Check your function for where you detect" \
                        " this attachment in the email object, there might be a bug." \
                        " or it might be at a grandchild-level (or even deeper). Find email in logs."\
                        " We marked it as read but not as already_checked."
        LOG.error(err_msg + "\nHere is the email: {}".format(message))
        self.mark_email_as_read(message_id=message['id']) # Mark as read so this doesn't happen again
        raise ValueError(err_msg)

      elif not has_invite_ics:
        return False

      # There is an invite.ics file
      if (not correct_prefix_subject) or (not subject_has_at):
        LOG.info("Found email that has an invite.ics but whose subject doesn't match a calendar invite reaction." \
            " It might be from a prospect using a different ESP (not Google), or a different language." \
            "\nHere is the email".format(message))
      else:
        LOG.info("Found email that satisfies all 3 criteria for calendar invite reaction.")
      
      # Extract the invite.ics file's METHOD and PARTSTAT and UID fields and ORGANIZER fields
      if len(att_data)>1:
        for _elem in att_data[1:]:
          if _elem != att_data[0]:
            LOG.info("List of attachment data is:\n{}".format(att_data))
            raise ValueError("Found email with an invite.ics but the list of attachment data has length {}.\nMore info in logs".format(len(att_data)))
        att_data = [att_data[0]]
      if len(att_data)!=1:
        LOG.info("List of attachment data is:\n{}".format(att_data))
        raise ValueError("Found email with an invite.ics but the list of attachment data has length {}".format(len(att_data)))
      output = {}
      file_data = att_data[0]
      invite_ics = file_data.decode("UTF-8").replace(';','\r\n').split('\r\n')
      for i in range(len(invite_ics)):
        entry = invite_ics[i]

        # get method
        if len(entry)>=7 and entry[:7]=='METHOD:':
          if 'method' not in output:
            output['method'] = entry[7:]
          else:
            raise ValueError("Found two METHOD:s in invite.ics:\n```{}```".format(file_data))

        # get partstat
        elif len(entry)>=9 and entry[:9]=='PARTSTAT=':
          if 'partstat' not in output:
            output['partstat'] = entry[9:]
          else:
            output['partstat'] = 'UNKNOWN'

        # get UID
        elif len(entry)>=4 and entry[:4]=='UID:':
          if entry[-11:]!='@google.com':
            raise ValueError("Found UID that doesn't end in @google.com in invite.ics:"\
              "```{}```\n".format(file_data))
          if 'uid' not in output:
            output['uid'] = entry[4:-11]
          else:
            raise ValueError("Found two UID:s in invite.ics:\n```{}```".format(file_data))

        # get ORGANIZER
        elif len(entry)>=9 and entry[:9]=='ORGANIZER':
          if 'organizer' in output:
            raise ValueError("Found two ORGANIZERs in invite.ics:\n```{}```".format(file_data))
          if i<len(invite_ics)-1:
            if len(invite_ics[i+1])>=3 and invite_ics[i+1][:3]=='CN=':
              output['organizer'] = invite_ics[i+1][3:] #e.g. Verkada Concierge:mailto:concierge@verkadasecurity.co

        # get X-RESPONSE-COMMENT
        elif len(entry)>=19 and entry[:19]=='X-RESPONSE-COMMENT=':
          if 'x-response-comment' in output:
            raise ValueError("Found two X-ORGANIZER-COMMENTs in invite.ics:\n```{}```".format(file_data))
          temp = entry[19:]
          pos = temp.find(':mailto:')
          if pos != -1:
            temp = temp[:pos]
          output['x-response-comment'] = temp
            
      return output



  def thread_is_ordered_by_date(self, LOG, thread):
      '''
      Returns whether or not the messages in a thread are ordered in STRICTLY ascending
      order by date. This check is vital for our tool since we're only supposed
      to return to the most recent email in the thread.

      We used the 'internalDate' field, not the 'Date' header.
      '''

      internal_dates = []
      for msg in thread['messages']:
          internal_dates.append(int(msg['internalDate']))
          if len(internal_dates)>1 and internal_dates[-1] <= internal_dates[-2]:
              break
      else:
        return True
      
      # internal_date check failed. Allow for leeway of 10 seconds
      dates = []
      for msg in thread['messages']:
        for header in msg['payload']['headers']:
          if header['name']=='Date':
            date = header['value']
            break
        else:
          err_msg = "No Date header found in email:\n```{}```".format(msg)
          LOG.error(err_msg)
          raise ValueError(err_msg)
        date = datetime.strptime(date, '%a, %d %b %Y %H:%M:%S %z')
        dates.append(date)
        if len(dates)>1 and (dates[-1] + timedelta(seconds=10) <= dates[-2]):
          LOG.error("This thread not ordered by date, even with 10 second leeway")
          return False
      
      LOG.info("Thread not truly ordered by date, but all violations are less than 10 seconds")
      return True