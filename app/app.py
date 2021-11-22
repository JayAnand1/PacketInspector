from scapy.all import *
import sys
import argparse
import os
import modules.http.http as http
import modules.mdns.mdns as mdns
import modules.tls.tls as tls
import modules.ssdp.ssdp as ssdp
import modules.ntp.ntp as ntp
import modules.dns.dns as dns

import xlsxwriter

from modules.config import risk_params_config as risk_params
from config.devices import devices

import pathlib

date = ""

current_path = str(pathlib.Path(__file__).parent.resolve())

output_folder = ""

results = {'dns': [], 'http': [], 'mdns': [], 'ntp': [], 'ssdp': [], 'tls': []}

device_results = {}


def get_protocol(pkt):
    try:
        if 'TCP' in pkt:
            if http.REQUEST in pkt:
                return 'HTTP'
            if pkt['TCP'].dport == 443 or pkt['TCP'].sport == 443:
                return 'TLS'
        elif 'UDP' in pkt:
            if pkt['UDP'].dport == 53:
                return 'DNS'
            if pkt['UDP'].dport == 5353 or pkt['UDP'].sport == 5353:
                return 'mDNS'
            if pkt['UDP'].dport == 123 or pkt['UDP'].sport == 123:
                return 'NTP'
            if pkt['UDP'].dport == 1900 or pkt['UDP'].sport == 1900:
                return 'SSDP'
    except (IndexError, UnicodeDecodeError, AttributeError) as e:
        print(e)
        return None


def add_result(res, protocol):
    if res is not None:
        results[protocol].append(res)

def add_result_to_device(res, protocol):
    if res is not None:
        if res['srcMac'] in device_results:
            device_results[res['srcMac']][protocol].append(res)
        if res['dstMac'] in device_results:
            device_results[res['dstMac']][protocol].append(res)

        

def write_excel_sheets(results, workbook):
    
    zero_risk = workbook.add_format({'bg_color': '#c2ffb8',
                               'font_color': '#006100'})
    low_risk = workbook.add_format({'bg_color': '#f6ffb8',
                               'font_color': '#5c6100'})
    medium_risk = workbook.add_format({'bg_color': '#ffddb8',
                               'font_color': '#613a00'})
    high_risk = workbook.add_format({'bg_color': '#ffb8b8',
                               'font_color': '#610000'})


    for protocol, entries in results.items():
        if len(entries) == 0:
            continue
        
        worksheet = workbook.add_worksheet(name=protocol)

        fieldnames = list(entries[0].keys())
        worksheet.write_row(0, 0, fieldnames)

        first_row = 0
        first_col = len(fieldnames) - 1
        last_row = len(entries)
        last_col = len(fieldnames) - 1

        i = 1
        for entry in entries:
            worksheet.write_row(i, 0, list(entry.values()))
            i += 1

        worksheet.conditional_format(first_row, first_col,last_row, last_col, 
                                        {'type': 'text',
                                         'criteria': 'containing',
                                         'value': 'ZERO',
                                         'format': zero_risk})
        worksheet.conditional_format(first_row, first_col,last_row, last_col, 
                                        {'type': 'text',
                                         'criteria': 'containing',
                                         'value': 'LOW',
                                         'format': low_risk})
        worksheet.conditional_format(first_row, first_col,last_row, last_col, 
                                        {'type': 'text',
                                         'criteria': 'containing',
                                         'value': 'MEDIUM',
                                         'format': medium_risk})
        worksheet.conditional_format(first_row, first_col,last_row, last_col, 
                                        {'type': 'text',
                                         'criteria': 'containing',
                                         'value': 'HIGH',
                                         'format': high_risk})

def write_protocol_assessment():
    workbook = xlsxwriter.Workbook(output_folder + '/' + 'Full Traffic Trace-' + date + '.xlsx')
    write_excel_sheets(results, workbook)
    workbook.close()

def get_risk_breakdown(entries):
    res = [0,0,0,0]
    for row in entries:
        if 'ZERO' == row['risk']:
            res[0] += 1
        if 'LOW' == row['risk']:
            res[1] += 1
        if 'MEDIUM' == row['risk']:
            res[2] += 1    
        if 'HIGH' == row['risk']:
            res[3] += 1

    return res

def write_summary_statistics(entry, workbook):
    worksheet = workbook.add_worksheet(name="summary")
    protos = list(entry.keys())
    amount = [len(v) for v in entry.values()]
    worksheet.write_row(0, 0, protos)
    worksheet.write_row(1, 0, amount)
    i = 4
    heading = ['ZERO','LOW','MEDIUM','HIGH']
    worksheet.write_row(i, 1, heading)
    for protocol, entries in entry.items():
        i+=1
        breakdown = get_risk_breakdown(entries)
        breakdown.insert(0, protocol)
        worksheet.write_row(i, 0, breakdown)
    

def write_device_assessments():
    for mac, entry in device_results.items():
        d = devices[mac]
        d = str(d)
        sum = 0
        for proto, pkts in entry.items():
            sum = sum + len(pkts)
        
        if sum == 0:
            continue
        
        workbook = xlsxwriter.Workbook(output_folder + '/' +  d + '-' + date + '.xlsx')
        write_summary_statistics(entry, workbook)
        write_excel_sheets(entry, workbook)
        workbook.close()


def prepare_device_assessment_data_structure():
    for mac, name in devices.items():
        entry = {
            'dns' : [],
            'http' : [],
            'mdns' : [],
            'ntp' : [],
            'ssdp' : [],
            'tls' : []
        }
        device_results[mac] = entry

def get_flag(pkt):
    return pkt['TCP'].flags

def is_ack_flag(flag):
    return flag == 'A'

def is_push_flag(flag):
    return 'P' in flag

def assembled_tcp_frags(pkts):
    new_pkt = pkts[0]
    for pkt in pkts[1:]:
        new_pkt['Raw'].load += pkt['Raw'].load
    return new_pkt     

def main(filename):
    tls_buffer = []
    http_buffer = []
    
    load_layer('http')
    prepare_device_assessment_data_structure()
    
    for pkt in rdpcap(filename=filename):
        protocol = get_protocol(pkt=pkt)
        if protocol == 'DNS':
            res = dns.process_pkt(pkt=pkt)
            add_result(res=res, protocol='dns')
            add_result_to_device(res=res, protocol='dns')
        if protocol == 'HTTP':
            flag = get_flag(pkt)
            if is_ack_flag(flag) and 'Raw' in pkt:
                http_buffer.append(pkt)
                continue
            if is_push_flag(flag) and 'Raw' in pkt:
                http_buffer.append(pkt)
                new_pkt = assembled_tcp_frags(http_buffer)
                http_buffer.clear()
                res = http.process_pkt(pkt=new_pkt)
                add_result(res=res, protocol='http')
                add_result_to_device(res=res, protocol='http')
        if protocol == 'mDNS':
            res = mdns.process_pkt(pkt=pkt)
            add_result(res=res, protocol='mdns')
            add_result_to_device(res=res, protocol='mdns')
        if protocol == 'NTP':
            res = ntp.process_pkt(pkt=pkt)
            add_result(res=res, protocol='ntp')
            add_result_to_device(res=res, protocol='ntp')
        if protocol == 'SSDP':
            res = ssdp.process_pkt(pkt=pkt)
            add_result(res=res, protocol='ssdp')
            add_result_to_device(res=res, protocol='ssdp')
        if protocol == 'TLS':
            # flag = get_flag(pkt)
            # if is_ack_flag(flag) and 'Raw' in pkt:
            #     tls_buffer.append(pkt)
            #     continue
            # if is_push_flag(flag) and 'Raw' in pkt:
            #     tls_buffer.append(pkt)
            #     new_pkt = assembled_tcp_frags(tls_buffer)
            #     tls_buffer.clear()            
            res = tls.process_pkt(pkt=pkt)
            add_result(res=res, protocol='tls')
            add_result_to_device(res=res, protocol='tls')

    write_protocol_assessment()
    write_device_assessments()

if __name__ == "__main__":

    parser = argparse.ArgumentParser(description='PCAP reader')
    parser.add_argument('--pcap', metavar='<pcap file name>',
                        help='pcap file to parse', required=True)

    args = parser.parse_args()
    filename = args.pcap

    if not os.path.isfile(filename):
        print('"{}" does not exist'.format(filename), file=sys.stderr)
        sys.exit(-1)

    folder = filename.split(os.sep)[-1].split('.')[0]
    date = folder
    
    path = os.path.join(current_path, 'output' + '/' + folder)
    os.mkdir(path)
    output_folder = path

    print("Starting...")

    main(filename)
    
    print("Finished...")

    print("Output in..." + output_folder)

