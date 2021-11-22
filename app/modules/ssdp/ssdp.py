from scapy.all import *
import sys
import json   
import argparse
import os
import modules.config.risk_params_config as risk_config


results = []

NOTIFY = 'NOTIFY * HTTP/1.1'
MSEARCH = 'M-SEARCH * HTTP/1.1'
HTTP = 'HTTP/1.1 200 OK'

IPV6_MULTICAST = "ff02::c"
IPV4_MULTICAST = "239.255.255.250"

def get_ip_version(pkt):
    if 'IPv6' in pkt:
        return 'IPv6'
    else:
        return 'IP'

def get_ttl(pkt):
    ip_version = get_ip_version(pkt=pkt)
    if ip_version == 'IPv6':
        return pkt[get_ip_version(pkt=pkt)].hlim
    else:
        return pkt[get_ip_version(pkt=pkt)].ttl

def get_ssdp_headers(pkt):
    try:
        return pkt['Raw'].load.decode('utf8').splitlines()
    except (IndexError, UnicodeDecodeError, AttributeError) as e:
        return None
 
def get_ssdp_message_type(ssdp_headers):
    return ssdp_headers[0]

def get_ssdp_server(ssdp_headers):
    for header in ssdp_headers:
        if 'server' in header.lower():
            return header.split(':')[1]

def get_ssdp_user_agent(ssdp_headers):
    for header in ssdp_headers:
        if 'USER-AGENT' in header or 'USER' in header:
            return header.split(':')[1]

def get_ssdp_location(ssdp_headers):
    locations = []
    for header in ssdp_headers:
        if 'location' in header.lower():
            location = header.split(':', 1)[1].strip()
            locations.append(location)
    return locations

def get_ssdp_details(ssdp_headers):
    details = []
    for header in ssdp_headers:
        if 'USER-AGENT' in header or 'server' in header.lower():
            detail = header.split(':')[1].strip()
            if detail != 'urn' and detail != 'uuid':
                details.append(detail)
    return details

def process_pcap(filename):

    print('Opening {}...'.format(filename))

    for pkt in rdpcap(filename=filename):
        try:
            pkt.show()
            print(pkt['UDP'].sport)
            ssdp_headers = get_ssdp_headers(pkt=pkt)
            if ssdp_headers is None:
                continue
            msg_type = get_ssdp_message_type(ssdp_headers=ssdp_headers)
            row = {}
            row['srcMac'] = pkt['Ethernet'].src
            row['dstMac'] = pkt['Ethernet'].dst
            row['srcIP'] = pkt[get_ip_version(pkt=pkt)].src
            row['dstIP'] = pkt[get_ip_version(pkt=pkt)].dst
            row['ttl'] = get_ttl(pkt=pkt)
            if msg_type == NOTIFY:
                row['server'] = get_ssdp_server(ssdp_headers=ssdp_headers)
            elif msg_type == HTTP:
                row['server'] = get_ssdp_server(ssdp_headers=ssdp_headers)
            else:
                continue
            results.append(row)
        except (IndexError, UnicodeDecodeError, AttributeError) as e:
            continue 

def process_pkt(pkt):
    risks = [risk_config.NO_RISK_PACKET]
    try:
        ssdp_headers = get_ssdp_headers(pkt=pkt)
        if ssdp_headers is None:
            return None
        msg_type = get_ssdp_message_type(ssdp_headers=ssdp_headers)
        row = {}
        row['srcMac'] = pkt['Ethernet'].src
        row['dstMac'] = pkt['Ethernet'].dst
        row['srcIP'] = pkt[get_ip_version(pkt=pkt)].src
        row['dstIP'] = pkt[get_ip_version(pkt=pkt)].dst
        row['ttl'] = get_ttl(pkt=pkt)
        if msg_type == NOTIFY:
            row['server'] = get_ssdp_server(ssdp_headers=ssdp_headers)
        elif msg_type == HTTP:
            row['server'] = get_ssdp_server(ssdp_headers=ssdp_headers)
        else:
            return None
        if (row['dstIP'] == IPV6_MULTICAST or row['dstIP'] == IPV4_MULTICAST):
            if row['ttl'] > 1:
                risks.append(risk_config.SSDP_LEAVING_SUBNET)
        row['score'] = max(risks)
        row['risk'] = risk_config.getRiskLabel(max(risks))
        return row
    except (IndexError, UnicodeDecodeError, AttributeError) as e:
        return None 

