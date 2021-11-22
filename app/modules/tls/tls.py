from logging import NullHandler
from scapy.all import *
import sys
import json
import argparse
import os
import csv
from cryptography import x509
from cryptography.hazmat.backends import default_backend

import modules.config.risk_params_config as risk_config

import pathlib

results = []

CLIENT_HELLO = 0x1
SERVER_HELLO = 0x2

cipher_suites = {}


def get_ip_version(packet):
    if 'IPv6' in packet:
        return 'IPv6'
    else:
        return 'IP'



def get_ciphersuite_hex_vals(packet):
    pkt_bytes = raw(packet['Raw'].load)
    try:
        session_id_offset = 43
        session_id_length = pkt_bytes[session_id_offset]
        cipher_suites_length_bytes = pkt_bytes[(session_id_offset + session_id_length + 1): (
                2 + session_id_offset + session_id_length + 1)]

        cipher_suites_length = cipher_suites_length_bytes[0] << 8 | cipher_suites_length_bytes[1]
        start = 2 + session_id_offset + session_id_length + 1 + 1

        data = pkt_bytes[start: start + cipher_suites_length]
        cipher_vals = []
        for i in range(0, len(data), 2):
            hex_code = (data[i]) | data[i + 1] << 8
            cipher_vals.append(hex_code)
    except IndexError as e:
        print(e)
        return []
    return cipher_vals

def get_server_hello_cipher(packet):
    print(packet['IP'].src)
    pkt_bytes = raw(packet['Raw'].load)
    result = {}
    try:
        session_id_offset = 43
        session_id_length = pkt_bytes[session_id_offset]
        cipher_suite = pkt_bytes[(session_id_offset + session_id_length + 1): (
                2 + session_id_offset + session_id_length + 1)]
        hex_code = cipher_suite[0] << 8 | cipher_suite[1] 
        print(cipher_suite[0])
        print(cipher_suite[1])

        result['security'] = cipher_suites[hex_code]['security']
        result['name'] = cipher_suites[hex_code]['name']
        return result
    except (IndexError, KeyError) as e:
        print(e)
        print('failed')
        return None


def get_tls_version(packet):
    pkt_bytes = raw(packet['Raw'].load)
    version = (pkt_bytes[9] << 8) | pkt_bytes[10]
    if version == 0x0303:
        return 'v1.2'
    if version == 0x0302:
        return 'v1.1'
    if version == 0x0301:
        return 'v1.0'


def setup_cipher_suites():
    path = str(pathlib.Path(__file__).parent.resolve()) + "/ciphersuites.json"
    with open(path, 'r') as file:
        ciphersuites_json = file.read()

    ciphersuites = json.loads(ciphersuites_json)
    ciphersuites = ciphersuites['ciphersuites']

    for item in ciphersuites:
        cipher = {}

        name = list(item.keys())[0]
        details = item[name]

        byte_1 = int(details['hex_byte_1'], 16) << 8
        byte_2 = int(details['hex_byte_2'], 16)
        hex_code = byte_1 | byte_2

        cipher['name'] = name
        cipher['security'] = details['security']

        cipher_suites[hex_code] = cipher


def get_ciphersuites(packet):
    result = [[], [], [], []]
    ciphersuites = get_ciphersuite_hex_vals(packet)
    for cipher in ciphersuites:
        try:
            if cipher_suites[cipher]['security'] == "insecure":
                result[0].append(cipher_suites[cipher]['name'])
            if cipher_suites[cipher]['security'] == "weak":
                result[1].append(cipher_suites[cipher]['name'])
            if cipher_suites[cipher]['security'] == "secure":
                result[2].append(cipher_suites[cipher]['name'])
            if cipher_suites[cipher]['security'] == "recommended":
                result[3].append(cipher_suites[cipher]['name'])
        except KeyError as e:
            print(e)
            continue

    return result


def tls_handshake_type(packet):
    pkt_bytes = raw(packet['Raw'].load)
    return pkt_bytes[5]


def tls_handshake(packet):
    pkt_bytes = raw(packet['Raw'].load)
    return pkt_bytes[0] == 0x16


def get_negotiated_cipher(packet):
    try:
        pkt_bytes = raw(packet['Raw'].load)
        session_id_offset = 43
        session_id_length = pkt_bytes[session_id_offset]

        cipher_suite_bytes = pkt_bytes[(session_id_offset + session_id_length + 1): (
                2 + session_id_offset + session_id_length + 1)]
        cipher_suite = (cipher_suite_bytes[0] << 8) | cipher_suite_bytes[1]
    except IndexError as e:
        return None
    return cipher_suite


def calculate_client_hello_risk(row):
    good = row['secure_num'] + row['recommended_num']
    total = row['secure_num'] + row['recommended_num'] + row['weak_num'] + row['insecure_num']

    if not total > 0:
        return None

    percentage_good = good/total * 100

    if (percentage_good < 50):
        return risk_config.TLS_CLIENT_CIPHERS_INSECURE
    if (percentage_good >= 50 and percentage_good < 76):
        return risk_config.TLS_CLIENT_CIPHERS_OK
    if (percentage_good >=76 and percentage_good < 100):
        return risk_config.TLS_CLIENT_CIPHERS_GOOD
    if (percentage_good == 100):
        return risk_config.TLS_CLIENT_CIPHERS_SECURE

    return None

def calculate_server_hello_risk(ciphersuite):
    if ciphersuite['security'] == "insecure":
        return risk_config.TLS_SERVER_CIPHER_INSECURE
    if ciphersuite['security'] == "weak":
        return risk_config.TLS_SERVER_CIPHER_WEAK
    if ciphersuite['security'] == "secure":
        return risk_config.TLS_SERVER_CIPHER_STRONG        
    if ciphersuite['security'] == "recommended":
        return risk_config.TLS_SERVER_CIPHER_RECOMMENDED
    return None    


def process_pkt(pkt):
    setup_cipher_suites()
    
    try:
        if not tls_handshake(pkt):
            return None
        handshake = tls_handshake_type(pkt)
        if handshake == CLIENT_HELLO or handshake == SERVER_HELLO:
            row = {'srcMac': pkt['Ethernet'].src, 'dstMac': pkt['Ethernet'].dst,
                   'srcIP': pkt[get_ip_version(packet=pkt)].src, 'dstIP': pkt[get_ip_version(packet=pkt)].dst, 'handshake_type': ""}
            if handshake == CLIENT_HELLO:       
                ciphersuites = get_ciphersuites(packet=pkt)
                row['handshake_type'] = "CLIENT_HELLO"
                row['version'] = get_tls_version(packet=pkt)
                row['insecure'] = ",".join(ciphersuites[0])
                row['insecure_num'] = len(ciphersuites[0])
                row['weak'] = ",".join(ciphersuites[1])
                row['weak_num'] = len(ciphersuites[1])
                row['secure'] = ",".join(ciphersuites[2])
                row['secure_num'] = len(ciphersuites[2])
                row['recommended'] = ",".join(ciphersuites[3])
                row['recommended_num'] = len(ciphersuites[3])
                row['score'] = calculate_client_hello_risk(row)
                row['risk'] = risk_config.getRiskLabel(row['score'])
                if (row['score'] == None):
                    return None
                return row
            else:
                ciphersuite = get_server_hello_cipher(packet=pkt)
                row['handshake_type'] = "SERVER_HELLO"
                row['version'] = get_tls_version(packet=pkt)
                row['insecure'] = ""
                row['insecure_num'] = ""
                row['weak'] = ""
                row['weak_num'] = ""
                row['secure'] = ""
                row['secure_num'] = ""
                row['recommended'] = ""
                row['recommended_num'] = ""
                row[ciphersuite['security']] = ciphersuite['name']
                row[ciphersuite['security'] + '_num'] = 1
                row['score'] = calculate_server_hello_risk(ciphersuite)
                row['risk'] = risk_config.getRiskLabel(row['score'])
                if (row['score'] == None):
                    return None
                return row
    except (IndexError, UnicodeDecodeError, AttributeError, TypeError) as e:
        return None




























#Trying stuff out




# def process_pkt(pkt):
#     try:
#         payload = raw(pkt['Raw'].load)
#         handshakes = parse_handshakes(payload=payload)
#         if len(handshakes) == 0:
#             return None
#         row = {'srcMac': pkt['Ethernet'].src, 'dstMac': pkt['Ethernet'].dst,
#                    'srcIP': pkt[get_ip_version(packet=pkt)].src, 'dstIP': pkt[get_ip_version(packet=pkt)].dst, 'handshake_type': ""}    
#         for handshake in handshakes:
#             if is_client_hello(handshake):


#         if handshake == CLIENT_HELLO or handshake == SERVER_HELLO:    
#             if handshake == CLIENT_HELLO:       
#                 ciphersuites = get_ciphersuites(packet=pkt)
#                 row['handshake_type'] = "CLIENT_HELLO"
#                 row['version'] = get_tls_version(packet=pkt)
#                 row['insecure'] = ",".join(ciphersuites[0])
#                 row['insecure_num'] = len(ciphersuites[0])
#                 row['weak'] = ",".join(ciphersuites[1])
#                 row['weak_num'] = len(ciphersuites[1])
#                 row['secure'] = ",".join(ciphersuites[2])
#                 row['secure_num'] = len(ciphersuites[2])
#                 row['recommended'] = ",".join(ciphersuites[3])
#                 row['recommended_num'] = len(ciphersuites[3])
#                 row['score'] = calculate_client_hello_risk(row)
#                 row['risk'] = risk_config.getRiskLabel(row['score'])
#                 if (row['score'] == None):
#                     return None
#                 return row
#             else:
#                 ciphersuite = get_server_hello_cipher(packet=pkt)
#                 row['handshake_type'] = "SERVER_HELLO"
#                 row['version'] = get_tls_version(packet=pkt)
#                 row['insecure'] = ""
#                 row['insecure_num'] = ""
#                 row['weak'] = ""
#                 row['weak_num'] = ""
#                 row['secure'] = ""
#                 row['secure_num'] = ""
#                 row['recommended'] = ""
#                 row['recommended_num'] = ""
#                 row[ciphersuite['security']] = ciphersuite['name']
#                 row[ciphersuite['security'] + '_num'] = 1
#                 row['score'] = calculate_server_hello_risk(ciphersuite)
#                 row['risk'] = risk_config.getRiskLabel(row['score'])
#                 if (row['score'] == None):
#                     return None
#                 return row
#     except (IndexError, UnicodeDecodeError, AttributeError, TypeError) as e:
#         return None












# def is_handshake(payload):
#     return payload[0] == 0x16

# def is_client_hello(payload):
#     return payload[0] == 0x01

# def is_server_hello(payload):
#     return payload[0] == 0x02

# def is_certificate(payload):
#     return payload[0] == 0x0b

# def get_tls_handshake_version(payload):
#     return payload[4] << 8 | payload[5]

# def get_tls_handshake_version(payload):
#     return payload[4] << 8 | payload[5]

# def get_record_length(payload):
#     return payload[3] << 8 | payload[4]  

# def get_record_layers(payload):
#     start = 0
#     recLen = 0
#     end = 0
#     type = 0
#     recordLayers = []

#     while start < len(payload):
#         type = payload[start]
#         recLen = payload[start + 3] << 8 | payload[start + 4]
#         end = start + recLen + 5
#         if end >  len(payload):
#             end = len(payload)
#         if type == 0x16:
#             recordLayers.append(payload[start:end])
#         start = end

#     return recordLayers

# def get_handshake_protocols(payload):

#     if not is_handshake(payload):
#         return None
    
#     handshakeProtocols = []

#     start = 5
#     recordlength = get_record_length(payload)
#     type = 0

#     while start < recordlength and start < len(payload):
#         type = payload[start]
#         typeLen = payload[start + 1] << 16 | payload[start + 2] << 8 | payload[start + 3]
#         end = start + 4 + typeLen
#         if end > len(payload):
#             end = len(payload)
#         if type == 0x1 or type == 0x2 or type == 0x0b:
#             handshakeProtocols.append(payload[start:end])    
#         start = end

# def extract_certificate(bytes):
#     '''parse x509'''
#     cert = x509.load_pem_x509_certificate(bytes, default_backend())


# def get_certificates(payload):
#     certificates = []
#     certificateslength = payload[4] << 16 | payload[5] << 8 | payload[6]
#     start = 7

#     while start < certificateslength and start < len(payload):
#         certLen =  payload[start] << 16 | payload[start + 1] << 8 | payload[start + 2]
#         end = start + 3 + certLen
#         if end > len(payload):
#             end = len(payload)        
#         cert = extract_certificate(payload[start + 3: end])
#         if not cert is None:
#             certificates.append(cert)
#         start = end                
#     return certificates

# def parse_handshakes(payload):
#     recordLayers = get_record_layers(payload)
#     handshakes = []

#     for recordLayer in recordLayers:
#         res = get_handshake_protocols(recordLayer)
#         if not res is None:
#             handshakes.append(res)
    
#     return handshakes

# def setup_ciphersuites():
#     path = str(pathlib.Path(__file__).parent.resolve()) + "/ciphersuites.json"
#     with open(path, 'r') as file:
#         ciphersuites_json = file.read()

#     ciphersuites = json.loads(ciphersuites_json)
#     return ciphersuites['ciphersuites']

# def get_ciphersuites_length_offset(payload):
#     sessionIdOffset = 38
#     sessionIdLength = payload[sessionIdOffset]
#     return sessionIdOffset + sessionIdLength + 1

# def get_ciphersuites_length(payload):
#     ciphersuites_length_offset = get_ciphersuites_length_offset(payload)
#     return payload[ciphersuites_length_offset] << 8 | payload[ciphersuites_length_offset + 1]

# def get_ciphersuites_offset(payload):
#     return get_ciphersuites_length_offset(payload) + 2

# def extract_cipher_suites(payload):
#     cipherSuitesLength = get_ciphersuites_length(payload)
#     cipherSuitesOffset = get_ciphersuites_offset(payload)
#     end = cipherSuitesOffset + cipherSuitesLength
#     if end > len(payload):
#         end = len(payload)

#     return payload[cipherSuitesOffset : end]


# def get_cipher_suites_info(payload):
#     ciphersuites_payload = extract_cipher_suites(payload)

#     if ciphersuites_payload is None:
#         return None

#     ciphersuites = setup_ciphersuites()
#     selected_cipersuites = []

#     for i in range(0, len(ciphersuites_payload), 2):
#         hex_b1 = ciphersuites_payload[i]
#         hex_b2 = ciphersuites_payload[i+1]
#         for item in ciphersuites:
#             name = list(item.keys())[0]
#             details = item[name]
#             byte_1 = int(details['hex_byte_1'], 16) << 8
#             byte_2 = int(details['hex_byte_2'], 16)
#             if byte_1 == hex_b1 and byte_2 == hex_b2:
#                 selected_cipersuites.append(item)
#                 break

#     return selected_cipersuites

# def get_accepted_ciphersuite_info(payload):
#     ciphersuites = setup_ciphersuites()

#     sessionIdLength = payload[38]
#     start = sessionIdLength + 38 + 1

#     hex_b1 = payload[start]
#     hex_b2 = payload[start+1]

#     for item in ciphersuites:
#         name = list(item.keys())[0]
#         details = item[name]
#         byte_1 = int(details['hex_byte_1'], 16) << 8
#         byte_2 = int(details['hex_byte_2'], 16)
#         if byte_1 == hex_b1 and byte_2 == hex_b2:
#             return item
    
#     return None
