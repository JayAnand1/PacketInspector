from scapy.all import *
import sys
import json
import argparse
import os
import csv

import modules.config.risk_params_config as risk_config


results = []

CLIENT_INIT = '146.156.146.168'
SUBNET = '192.168.1'

SYMMETRIC_PASSIVE = 1
SYMMETRIC_ACTIVE = 2
CLIENT_MODE = 3
SERVER_MODE = 4
BROADCAST_MODE = 5
RESERVED_MODE_1 = 6
RESERVED_MODE_2 = 7

NTP_EPOCH = 2208988800

UNSYNCHRONIZED = 3

HALF_DAY = 43200


def get_ip_version(pkt):
    if 'IPv6' in pkt:
        return 'IPv6'
    else:
        return 'IP'


def ntp_request(packet):
    return packet['IP'].src[:9] == SUBNET



def latest_version(packet):
    if packet['NTPHeader'].version == 4:
        return 1
    return 0



def reserved_mode(packet):
    if packet['NTPHeader'].mode == RESERVED_MODE_1 or packet['NTPHeader'].mode == RESERVED_MODE_2:
        return 1
    return 0


def symmetric_mode(packet):
    if packet['NTPHeader'].mode == SYMMETRIC_ACTIVE or packet['NTPHeader'].mode == SYMMETRIC_PASSIVE:
        return 1
    return 0


def incorrect_mode(packet):
    if packet['NTPHeader'].mode == 0 or packet['NTPHeader'].mode > 7:
        return 1
    return 0


def broadcast_mode(packet):
    if packet['NTPHeader'].mode == BROADCAST_MODE:
        return 1
    return 0

def get_version(packet):
    return packet['NTPHeader'].version


def get_mode(packet):
    return packet['NTPHeader'].mode


def process_pkt(pkt):
    risks = [risk_config.NO_RISK_PACKET]
    try:
        row = {}
        row['srcMac'] = pkt['Ethernet'].src
        row['dstMac'] = pkt['Ethernet'].dst
        row['srcIP'] = pkt[get_ip_version(pkt=pkt)].src
        row['dstIP'] = pkt[get_ip_version(pkt=pkt)].dst
        row['version'] = get_version(packet=pkt)
        row['mode'] = get_mode(packet=pkt) 
        row['latest_version'] = latest_version(packet=pkt)
        row['reserved'] = reserved_mode(packet=pkt)
        row['symmetric'] = symmetric_mode(packet=pkt)
        row['invalid'] = incorrect_mode(packet=pkt)
        row['broadcast'] = broadcast_mode(packet=pkt)
        if (row['latest_version'] != 1):
            risks.append(risk_config.NTP_NOT_LATEST_VERSION)
        if (row['reserved'] == 1):
            risks.append(risk_config.NTP_RESERVED)
        if (row['symmetric'] == 1):
            risks.append(risk_config.NTP_SYMMETRIC)
        if (row['invalid'] == 1):
            risks.append(risk_config.NTP_INVALID)                
        if (row['broadcast'] == 1):
            risks.append(risk_config.NTP_BROADCAST)  
        row['score'] = max(risks)      
        row['risk'] = risk_config.getRiskLabel(max(risks))      
        return row
    except (IndexError, UnicodeDecodeError, AttributeError) as e:
        return None
