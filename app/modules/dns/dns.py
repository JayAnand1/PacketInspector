from scapy.all import *
import sys
import json
import argparse
import os
import csv

import modules.config.risk_params_config as risk_config

results = []


def dnssec_enabled(dns_pkt):
    """
    Check for dnssec
    """
    if dns_pkt.ar is None:
        return 0
    if hex(dns_pkt.ar.z == 0x8000):
        return 1
    return 0


def get_ip_version(pkt):
    if 'IPv6' in pkt:
        return 'IPv6'
    else:
        return 'IP'


def dns_query(dns_pkt):
    """
    Check if DNS packet is query request
    """
    return dns_pkt.qr == 0


def dns_response(dns_pkt):
    """
    Check if DNS packet is query response
    """
    return dns_pkt.qr == 1


def q_type_any_flag(dns_pkt):
    """
    See if the q-type field in a query
    are set to * or ANY.
    """
    total = 0
    for i in range(dns_pkt.qdcount):
        try:
            if dns_pkt['DNSQR'][i].qtype == 255:
                total += 1
        except KeyError as e:
            continue
    return total


def q_class_any_flag(dns_pkt):
    """
    See if the q-class field in a query
    are set to * or ANY.
    """
    total = 0
    for i in range(dns_pkt.qdcount):
        try:
            if dns_pkt['DNSQR'][i].qclass == 255:
                total += 1
        except KeyError as e:
            continue
    return total


def RRSIG_received(dns_packet):
    """
    Check if hostname is dnssec secure
    """
    if dns_packet.ancount > 0 and 'DNS RRSIG Resource Record' in dns_packet.an:
        return True
    return False


def check_dnnsec_algorithm(dns_packet):
    """
    Check that packet uses RSA/SHA-1 (mandatory).
    All other algoritms are optional or not
    recommended.
    Check - https://tools.ietf.org/html/rfc4034#appendix-A.1
    """
    if dns_packet.ancount > 0 and dns_packet.an['DNS RRSIG Resource Record'].algorithm == 5:
        return 1
    return 0


def process_pcap(filename):
    print('Opening {}...'.format(filename))

    for pkt in rdpcap(filename=filename):
        try:
            dns_pkt = pkt['DNS']
            if dns_query(dns_pkt):
                row = {}
                row['srcMac'] = pkt['Ethernet'].src
                row['dstMac'] = pkt['Ethernet'].dst
                row['srcIP'] = pkt[get_ip_version(pkt=pkt)].src
                row['dstIP'] = pkt[get_ip_version(pkt=pkt)].dst
                row['dnssec'] = dnssec_enabled(dns_pkt)
                row['q_type'] = q_type_any_flag(dns_pkt)
                row['q_class'] = q_class_any_flag(dns_pkt)
                if (row['q_type'] > 0 or row['q_type'] > 0):
                    row['risk'] = risk_config.DNS_Q_RISK
                else:
                    row['risk'] = risk_config.NO_RISK_PACKET  
                results.append(row)
        except (IndexError, UnicodeDecodeError, AttributeError) as e:
            continue


def process_pkt(pkt):
    risks = [risk_config.NO_RISK_PACKET]
    try:
        dns_pkt = pkt['DNS']
        if dns_query(dns_pkt):
            row = {}
            row['srcMac'] = pkt['Ethernet'].src
            row['dstMac'] = pkt['Ethernet'].dst
            row['srcIP'] = pkt[get_ip_version(pkt=pkt)].src
            row['dstIP'] = pkt[get_ip_version(pkt=pkt)].dst
            row['dnssec'] = dnssec_enabled(dns_pkt)
            row['q_type'] = q_type_any_flag(dns_pkt)
            row['q_class'] = q_class_any_flag(dns_pkt)
            if (row['q_type'] > 0 or row['q_type'] > 0):
                risks.append(risk_config.DNS_Q_TYPE)
            row['score'] = max(risks)
            row['risk'] = risk_config.getRiskLabel(max(risks))
            return row
    except (IndexError, UnicodeDecodeError, AttributeError) as e:
        return None


def dns_print():
    print("DNS working")
