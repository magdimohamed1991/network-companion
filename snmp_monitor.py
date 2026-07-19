"""
snmp_monitor.py — Phase 4: Router-level bandwidth monitoring via SNMP.

Uses PySNMP to poll the router's WAN interface counters and record them in the DB.
"""

import time
import sys
from pathlib import Path

# Add parent dir to path for imports
sys.path.insert(0, str(Path(__file__).resolve().parent))

import config
import database

try:
    from pysnmp.hlapi import *
except ImportError:
    print("[!] PySNMP not installed. SNMP monitoring disabled.")
    sys.exit(0)

POLL_INTERVAL = 30

def get_snmp_counter(target, community, oid):
    errorIndication, errorStatus, errorIndex, varBinds = next(
        getCmd(SnmpEngine(),
               CommunityData(community),
               UdpTransportTarget((target, 161)),
               ContextData(),
               ObjectType(ObjectIdentity(oid)))
    )
    if errorIndication:
        raise Exception(errorIndication)
    elif errorStatus:
        raise Exception('%s at %s' % (errorStatus.prettyPrint(),
                                      errorIndex and varBinds[int(errorIndex) - 1][0] or '?'))
    else:
        for varBind in varBinds:
            return int(varBind[1])

def main():
    cfg = config.load()
    if not cfg.get("snmp_enabled"):
        print("[i] SNMP monitoring disabled in config.json.")
        return

    router_ip = cfg.get("router_ip")
    if not router_ip:
        from netutils import get_default_gateway
        router_ip = get_default_gateway()
    
    if not router_ip:
        print("[!] Could not determine router IP for SNMP.")
        return

    community = cfg.get("snmp_community", "public")
    if_index = cfg.get("snmp_wan_index", 1)
    
    # OIDs for ifInOctets and ifOutOctets
    OID_IN = f'1.3.6.1.2.1.2.2.1.10.{if_index}'
    OID_OUT = f'1.3.6.1.2.1.2.2.1.16.{if_index}'

    print(f"[i] Starting SNMP monitoring for {router_ip} (WAN index {if_index})...")
    
    last_in = None
    last_out = None

    while True:
        try:
            curr_in = get_snmp_counter(router_ip, community, OID_IN)
            curr_out = get_snmp_counter(router_ip, community, OID_OUT)
            
            if last_in is not None and last_out is not None:
                # Handle 32-bit counter wrap
                delta_in = (curr_in - last_in) if curr_in >= last_in else (0xFFFFFFFF - last_in + curr_in)
                delta_out = (curr_out - last_out) if curr_out >= last_out else (0xFFFFFFFF - last_out + curr_out)
                
                database.record_router_bandwidth_sample(delta_out, delta_in)
            
            last_in = curr_in
            last_out = curr_out
            
        except Exception as e:
            print(f"[!] SNMP poll failed: {e}")
            last_in = None
            last_out = None
            
        time.sleep(POLL_INTERVAL)

if __name__ == "__main__":
    main()
