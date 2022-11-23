#!/usr/bin/env python

import os
from datetime import datetime

# Slack IDs
SLACK_EMAIL_TEST_CHANNEL = 'CRS6B7MTP'
SLACK_AUTOMATION_CHANNEL = 'CPNGJ48JC'
SLACK_TEST_AUTOMATION_CHANNEL = 'CQ8UWJYLE'
SLACK_ZEESHAN_TEST_CHANNEL = 'C03K0AAEPE2'
SLACK_MDRTCM15_CHANNEL = 'C03CC82R3EY'
SLACK_WEBINAR_CHANNEL = 'GS99STHPC'
SLACK_BOOK_MEETING_CHANNEL = 'C039CLNCT9C'
SLACK_JASON_TESTING_CHANNEL = 'C01NRKWB2G3'
SLACK_SIGNALS_INCOMING_CHANNEL = 'C01C6GKDNKX'
SLACK_SYSTEMS_PULSE_CHANNEL = 'C01UQGU7D4M'
SLACK_LEAD_CONVERISON_CHANNEL = 'C024R09JC95'
SLACK_MDR_AUTOMATION_CHANNEL = 'C025K5VG8UW'
SLACK_MDR_SEQUENCE_ROTATOR_CHANNEL = 'C028UJE4YN9'
SLACK_USER_IDS = {'sean.moreno@verkada.com': 'UK7NMS7NU',
                  'christine.dzou@verkada.com': 'UBUL4HDU4',
                  'rob.marwanga@verkada.com': 'US05HDY2G',
                  'dean.wenstrand@verkada.com': 'UCRN51EP3',
                  'patrick.sung@verkada.com': 'UJBKSHNR4',
                  'joyce.zheng@verkada.com': 'UBS3SR9EG',
                  'mackenzie.lane@verkada.com': 'UJ5692CK0',
                  'renee.liu@verkada.com': 'U013NBXUP24',
                  'antoine.carnet@verkada.com': 'U01ETMSLTV1',
                  'brad.ayres@verkada.com': 'U01DEC91TFY',
                  'jeremy.clerc@verkada.com': 'U02GE5AHT7X'}
SLACK_CONCIERGE_CHANNEL = 'C03CHNTTA2H'
SLACK_BILLY_TEST_CHANNEL = 'C03PTGGADME'

SLACK_SEAN_ID = 'UK7NMS7NU'
SLACK_CHRISTINE_ID = 'UBUL4HDU4'
SLACK_PATRICK_ID = 'UJBKSHNR4'
SLACK_DEAN_ID = 'UCRN51EP3'
SLACK_IDAN_ID = 'UB0UB18AV'
SLACK_ALEX_ID = 'UUU3L4MPG'
SLACK_RENEE_ID = 'U013NBXUP24'
SLACK_JASON_ID = 'UK7NMS7NU'
SLACK_BRENT_ID = 'U01R72GV1RQ'
SLACK_HARRY_ID = 'U01D1JAQVUG'
SLACK_BILLY_ID = 'U02U75Z715L'
SLACK_JUANCARLOS_ID = 'U0382QUQEC9'
SLACK_ZEESHAN_ID = 'U03G29YLP1P'
SLACK_TEJAS_ID = 'U044SKDRL0L'

# Zoom API credentials
#ZOOM_API_KEY = os.environ['ZOOM_API_KEY']
#ZOOM_API_SECRET = os.environ['ZOOM_API_SECRET']
ZOOM_USER_IDS = {'rob.marwanga@verkada.com': 'qwG7d1y_RBCzWM-uxGLqSg',
                 'christine.dzou@verkada.com': 'NZobmcOeTaeGQhDYgkSdkA',
                 'joyce.zheng@verkada.com': 'HlcE0o4STmq1e9g-fJPnoA',
                 'mackenzie.lane@verkada.com': 'aHXQdCjkT-KlDSNYI9B-BA',
                 'fieldevents@verkada.com': '-FAIANGGQFyr5U6pRGKZMQ',
                 'matt.antos-lewis@verkada.com': 'UB1jIRGGR3apwDlXJfZe7g',
                 'antoine.carnet@verkada.com': 'aSgqHSt-TzqvCkvT8EO9cA',
                 'brad.ayres@verkada.com': '_bBdVy0RQHyUVX3kWIL_aw'}

ZOOM_ACCOUNT_MAPPING = {'christine.dzou@verkada.com': 'christine.dzou@verkada.com',
                        'sean.moreno@verkada.com': 'christine.dzou@verkada.com',
                        'idan@verkada.com': 'christine.dzou@verkada.com',
                        'dean.wenstrand@verkada.com': 'christine.dzou@verkada.com',
                        'jason.humphries@verkada.com': 'christine.dzou@verkada.com',
                        'paul.izhutov@verkada.com': 'christine.dzou@verkada.com',
                        'matt.antos-lewis@verkada.com': 'matt.antos-lewis@verkada.com',
                        'joyce.zheng@verkada.com': 'fieldevents@verkada.com',
                        'erica.morales@verkada.com': 'fieldevents@verkada.com',
                        'rob.marwanga@verkada.com': 'rob.marwanga@verkada.com',
                        'mackenzie.lane@verkada.com': 'rob.marwanga@verkada.com',
                        'jeff.chase@verkada.com': 'christine.dzou@verkada.com',
                        'antoine.carnet@verkada.com': 'antoine.carnet@verkada.com',
                        'brad.ayres@verkada.com': 'christine.dzou@verkada.com'}
