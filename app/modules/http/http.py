from scapy.all import *
import sys
import argparse
import os

import modules.config.risk_params_config as risk_config


results = []

REQUEST = 'HTTP Request'
RESPONSE = 'HTTP Response'
BASIC = 'Basic'
DIGEST = 'Digest'


def get_ip_version(pkt):
    if 'IPv6' in pkt:
        return 'IPv6'
    else:
        return 'IP'


def get_server(pkt):
    try:
        return pkt[RESPONSE].Server.decode('utf8')
    except (IndexError, UnicodeDecodeError, AttributeError) as e:
        return None


def get_useragent(pkt):
    try:
        return pkt[REQUEST].User_Agent.decode('utf8')
    except (IndexError, UnicodeDecodeError, AttributeError) as e:
        return "None"


def get_authorization(pkt):
    try:
        return pkt[REQUEST].Authorization.decode('utf8')
    except (IndexError, UnicodeDecodeError, AttributeError) as e:
        return "None"


def get_form(pkt):
    try:
        return pkt['Raw'].load.decode('utf-8')
    except (IndexError, UnicodeDecodeError, AttributeError) as e:
        return "None"

def process_pkt(pkt):
    risks = [risk_config.NO_RISK_PACKET]
    try:
        if REQUEST in pkt:
            row = {}
            row['srcMac'] = pkt['Ethernet'].src
            row['dstMac'] = pkt['Ethernet'].dst
            row['srcIP'] = pkt[get_ip_version(pkt=pkt)].src
            row['dstIP'] = pkt[get_ip_version(pkt=pkt)].dst
            row['authorization'] = get_authorization(pkt=pkt)    
            row['formdata'] = get_form(pkt=pkt)
            row['useragent'] = get_useragent(pkt=pkt)
            if (row['authorization'] != "None"):
                risks.append(risk_config.HTTP_DEFAULT_PASSWORD)
            if (row['formdata'] != "None"):
                risks.append(risk_config.HTTP_FORM_DATA)
            row['score'] = max(risks)
            row['risk'] = risk_config.getRiskLabel(max(risks))
            return row
    except (IndexError, UnicodeDecodeError, AttributeError) as e:
        return None
