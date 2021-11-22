
risk = {
    'zero': 0,
    'low' : 1,
    'medium': 2,
    'high' : 3
}

def getRiskLabel(val):
    if val is None:
        return ""
    return list(risk.keys())[list(risk.values()).index(val)].upper()
    

HTTP_DEFAULT_PASSWORD = risk['high']
HTTP_FORM_DATA = risk['high']

DNS_Q_TYPE = risk['high']
DNS_NO_DNSSEC = risk['medium']

TLS_CLIENT_CIPHERS_INSECURE = risk['high']        #less than 50% secure/recommended
TLS_CLIENT_CIPHERS_OK = risk['medium']            #50-75% secure/recommended
TLS_CLIENT_CIPHERS_GOOD = risk['low']             #76-99% secure/recommended
TLS_CLIENT_CIPHERS_SECURE = risk['zero']          #100% secure/recommened 

TLS_SERVER_CIPHER_INSECURE = risk['high']
TLS_SERVER_CIPHER_WEAK = risk['high']
TLS_SERVER_CIPHER_STRONG = risk['zero']
TLS_SERVER_CIPHER_RECOMMENDED = risk['zero']

NTP_NOT_LATEST_VERSION = risk['high']
NTP_RESERVED = risk['high']
NTP_SYMMETRIC = risk['high']
NTP_BROADCAST = risk['high']
NTP_INVALID = risk['high']

SSDP_LEAVING_SUBNET = risk['high']
SSDP_RESP_TO_UNICAST = risk['high']

MDNS_LEAVING_SUBNET = risk['high']
MDNS_RESP_TO_UNICAST = risk['high']

NO_RISK_PACKET = risk['zero']