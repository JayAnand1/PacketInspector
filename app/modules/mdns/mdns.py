from scapy.all import *
import sys
import json   
import argparse
import os

import modules.config.risk_params_config as risk_config


results = []

TXT = 0x10
PTR = 0xc
A_REC = 0x1
AAAA_REC = 0x1c
RESPONSE = 1
QUERY = 0

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

def dns_response(dns_pkt):
    return dns_pkt.qr == RESPONSE

def dns_query(dns_pkt):
    return dns_pkt.qr == QUERY

def get_questions(dns_pkt):
    res = []
    for i in range(dns_pkt.qdcount):
        try: 
            if type(dns_pkt['DNSQR'][i].qname) == str:
                res.append(dns_pkt['DNSQR'][i].qname)
            elif type(dns_pkt['DNSQR'][i].qname) == bytes:
                res.append(dns_pkt['DNSQR'][i].qname.decode('utf8'))
            else:
                continue
        except (IndexError,UnicodeDecodeError, AttributeError) as e:
            print(e)

    return ",".join(list(set(res)))

def get_answers(dns_pkt):
    res = []
    for i in range(dns_pkt.ancount + dns_pkt.arcount):
        try: 
            if dns_pkt['DNSRR'][i].type == TXT or dns_pkt['DNSRR'][i].type == PTR or dns_pkt['DNSRR'][i].type == A_REC or dns_pkt['DNSRR'][i].type == AAAA_REC:
                res.append(dns_pkt['DNSRR'][i].rrname.decode('utf8'))
                if type(dns_pkt['DNSRR'][i].rdata) == str:
                    res.append(dns_pkt['DNSRR'][i].rdata)
                elif type(dns_pkt['DNSRR'][i].rdata) == bytes:
                    res.append(dns_pkt['DNSRR'][i].rdata.decode('utf8'))
                else:
                    for item in dns_pkt['DNSRR'][i].rdata:
                        detail = item.decode('utf8') if type(item) == bytes else item
                        if type(detail) != int and len(detail) > 1:   
                            res.append(detail)
        except (IndexError,UnicodeDecodeError, AttributeError) as e:
            print(e)
    
    return ",".join(list(set(res)))


def process_pcap(filename):

    print('Opening {}...'.format(filename))

    for pkt in rdpcap(filename=filename):
        try:
            dns_pkt = pkt['DNS']
            dns_pkt.show()
            row = {}
            row['srcMac'] = pkt['Ethernet'].src
            row['dstMac'] = pkt['Ethernet'].dst
            row['srcIP'] = pkt[get_ip_version(pkt=pkt)].src
            row['dstIP'] = pkt[get_ip_version(pkt=pkt)].dst
            row['answers'] = get_answers(dns_pkt)
            row['questions'] = get_questions(dns_pkt)
            results.append(row)
        except (IndexError, UnicodeDecodeError, AttributeError) as e:
            continue 

def process_pkt(pkt):
    risks = [risk_config.NO_RISK_PACKET]
    try:
        dns_pkt = pkt['DNS']
        row = {}
        row['srcMac'] = pkt['Ethernet'].src
        row['dstMac'] = pkt['Ethernet'].dst
        row['srcIP'] = pkt[get_ip_version(pkt=pkt)].src
        row['dstIP'] = pkt[get_ip_version(pkt=pkt)].dst
        row['ttl'] = get_ttl(pkt=pkt)
        row['answers'] = get_answers(dns_pkt)
        row['questions'] = get_questions(dns_pkt)
        if (row['dstIP'] == IPV6_MULTICAST or row['dstIP'] == IPV4_MULTICAST):
            if row['ttl'] > 1:
                risks.append(risk_config.MDNS_LEAVING_SUBNET)
        row['score'] = max(risks) 
        row['risk'] = risk_config.getRiskLabel(max(risks))      
        return row
    except (IndexError, UnicodeDecodeError, AttributeError) as e:
        return None
