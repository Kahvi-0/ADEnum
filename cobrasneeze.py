#!/usr/bin/env python3

import argparse
import binascii
import sys
import time
from datetime import datetime
import re
from collections import defaultdict
from scapy.all import sniff, rdpcap, Raw, TCP, UDP, DNS
from scapy.layers.inet import IP
import threading

# Common AD-related ports -> protocol friendly name
AD_PORTS = {
    137: "NBNS",
    138: "NetBIOS-DS",
    138: "BROWSER",
    139: "SMB-over-NetBIOS",
    445: "SMB",
    88:  "Kerberos",
    389: "LDAP",
    636: "LDAPS",
    3268: "GlobalCatalog LDAP",
    3269: "GlobalCatalog LDAPS",
    53: "DNS",
    5355: "LLMNR",
}

def find_keywords_in_bytes(payload_bytes: bytes, keywords: list):
    """Return list of matched keywords and the snippet around first match."""
    matches = []
    lower = payload_bytes.lower()
    for kw in keywords:
        kb = kw.lower().encode()
        idx = lower.find(kb)
        if idx != -1:
            start = max(0, idx - 40)
            end = min(len(payload_bytes), idx + len(kb) + 40)
            snippet = payload_bytes[start:end]
            matches.append((kw, snippet))
    return matches

def hexdump_snippet(b: bytes, length=120):
    snippet = b[:length]
    return binascii.hexlify(snippet).decode()

def handle_dns_like(pkt, keywords):
    # Try to parse DNS (works for LLMNR too since same format)
    try:
        dns = DNS(pkt[UDP].payload)
    except Exception:
        # fallback: raw payload search
        payload = bytes(pkt[UDP].payload)
        return find_keywords_in_bytes(payload, keywords), None

    matches = []
    # look into question/answer names
    try:
        if dns.qdcount > 0 and dns.qd:
            # dns.qd can be list or a single DNSQR
            qrs = dns.qd if isinstance(dns.qd, list) else [dns.qd]
            for qr in qrs:
                qname = bytes(qr.qname or b"")
                matches += [(kw, qname) for kw in keywords if kw.lower().encode() in qname.lower()]
        # answers
        if dns.ancount > 0 and dns.an:
            ans = dns.an if isinstance(dns.an, list) else [dns.an]
            for a in ans:
                rdata = bytes(a.rdata or b"")
                matches += [(kw, rdata) for kw in keywords if kw.lower().encode() in (rdata or b"").lower()]
    except Exception:
        pass

    # If no structured matches, try raw
    if not matches:
        payload = bytes(pkt[UDP].payload)
        matches = find_keywords_in_bytes(payload, keywords)

    return matches, dns

def handle_smb(pkt, keywords):
    payload = None
    if pkt.haslayer(Raw):
        payload = pkt[Raw].load
    else:
        return [], None

    # If impacket is available we attempt minimal decode (best-effort)
    if HAVE_IMPA:
        try:
            # Try SMB1 decode
            try:
                smb_pkt = smb.SMBPacket(payload)
                # SMBPacket may provide structure; pull command and data if possible
                cmd = getattr(smb_pkt, 'Command', None)
                # convert raw and search keywords
                matches = find_keywords_in_bytes(payload, keywords)
                return matches, smb_pkt
            except Exception:
                # Try SMB2/3 parsing fallback - impacket has SMB2/SMB3 helpers but they are more involved
                matches = find_keywords_in_bytes(payload, keywords)
                return matches, None
        except Exception:
            # fallback to raw search
            return find_keywords_in_bytes(payload, keywords), None
    else:
        return find_keywords_in_bytes(payload, keywords), None

def handle_kerberos(pkt, keywords):
    # Kerberos is ASN.1; Impacket can decode but requires robust logic.
    payload = bytes(pkt[Raw].load) if pkt.haslayer(Raw) else b''
    if HAVE_IMPA:
        try:
            # Try to find AP-REQ or KRB-TGS or tickets by looking for ASN.1 tag sequences
            # We'll still do keyword search on raw bytes as primary
            matches = find_keywords_in_bytes(payload, keywords)
            # Optional: attempt to decode and extract names - complex, skip for now unless needed
            return matches, None
        except Exception:
            return find_keywords_in_bytes(payload, keywords), None
    else:
        return find_keywords_in_bytes(payload, keywords), None

def handle_ldap(pkt, keywords):
    # LDAP over TCP/UDP is ASN.1 BER; parsing is complex. We'll search raw and look for readable ASCII.
    payload = bytes(pkt[Raw].load) if pkt.haslayer(Raw) else b''
    return find_keywords_in_bytes(payload, keywords), None
    
def dispatch_packet(pkt, keywords):
    proto = None
    sport = dport = None
    try:
        if pkt.haslayer(TCP):
            sport = pkt[TCP].sport
            dport = pkt[TCP].dport
            # check both ends
            proto = AD_PORTS.get(sport) or AD_PORTS.get(dport)
        elif pkt.haslayer(UDP):
            sport = pkt[UDP].sport
            dport = pkt[UDP].dport
            proto = AD_PORTS.get(sport) or AD_PORTS.get(dport)
    except Exception:
        pass

    # Default: if no AD-related port, we still optionally search
    if not proto:
        # optional: limit generic scanning to only when raw present to reduce noise
        if pkt.haslayer(Raw):
            matches = find_keywords_in_bytes(bytes(pkt[Raw].load), keywords)
            if matches:
                print_packet_match(pkt, "RAW", matches)
        return

    # Call protocol-specific handler
    matches = []
    parsed = None
    try:
        if proto in ("DNS", "LLMNR", "NBNS", "BROWSER", "MDNS"):
            matches, parsed = handle_dns_like(pkt, keywords)
        elif proto and proto.startswith("SMB"):
            matches, parsed = handle_smb(pkt, keywords)
        elif proto == "Kerberos":
            matches, parsed = handle_kerberos(pkt, keywords)
        elif proto and "LDAP" in proto:
            matches, parsed = handle_ldap(pkt, keywords)
        else:
            matches = find_keywords_in_bytes(bytes(pkt[Raw].load) if pkt.haslayer(Raw) else b'', keywords)
    except Exception as e:
        # ensure a bug in handler doesn't kill sniffer
        print(f"[!] Handler error for proto {proto}: {e}")
        matches = find_keywords_in_bytes(bytes(pkt[Raw].load) if pkt.haslayer(Raw) else b'', keywords)

    if matches:
        print_packet_match(pkt, proto, matches, parsed)

def print_packet_match(pkt, proto, matches, parsed=None):
    ip_layer = pkt[IP] if pkt.haslayer(IP) else None
    src = f"{ip_layer.src}:{pkt.sport}" if ip_layer else "?"
    dst = f"{ip_layer.dst}:{pkt.dport}" if ip_layer else "?"
    for kw, snippet in matches:
        # snippet may be bytes or scapy object (e.g., DNS); print intelligibly
        if isinstance(snippet, bytes):
            try:
                matches = PRINTABLE_RE.findall(snippet)
                src = pkt[0][1].src
                src = PORT_RE.sub("", src)
                printable = snippet.decode(errors='replace')
            except Exception:
                printable = hexdump_snippet(snippet, 200)
            for match in matches:
                print(f"DEBUG - {proto} - {src} - {match.decode(errors='ignore')}")
                match_str = match.decode(errors='ignore').strip()
                match_str_lower = match_str.lower()
                observations[match_str_lower].add(src)
        else:
            # for parsed objects (DNS etc) attempt nicer printing
            print("REPORT THIS")
            print(f"[MATCH] keyword='{kw}' parsed:\n{snippet}\n")
    # show raw payload size and sample
    if pkt.haslayer(Raw):
        raw = bytes(pkt[Raw].load)
        print(f"Raw payload {len(raw)} bytes, hexdump(0..120): {hexdump_snippet(raw,120)}")

def live_sniff(interface, keywords, bpf=None):
    print(f"Starting live capture on {interface}. Press Ctrl-C to stop.")
    sniff(iface=interface, prn=lambda p: dispatch_packet(p, keywords), store=False, filter=bpf)

def pcap_scan(filename, keywords):
    print(f"Reading pcap {filename} ...")
    packets = rdpcap(filename)
    print(f"Loaded {len(packets)} packets; scanning for keywords...")
    for pkt in packets:
        dispatch_packet(pkt, keywords)

def main():
    parser = argparse.ArgumentParser(description="AD-protocol-aware sniffer (Scapy + optional Impacket).")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('--iface', help='Interface to sniff (live). Requires root.')
    group.add_argument('--pcap', help='PCAP file to scan.')
    parser.add_argument('--keywords', help='Comma-separated keywords to search (case-insensitive).')
    parser.add_argument('--bpf', help='Optional BPF filter to reduce capture noise (e.g., "tcp or udp")')
    args = parser.parse_args()

    keywords = [r'\MAILSLOT\BROWSE']
    if args.keywords:
    	new_keywords = [k.strip() for k in args.keywords.split(',')]
    	keywords.extend(new_keywords)
    	print(keywords)
        
    if args.iface:
        live_sniff(args.iface, keywords, bpf=args.bpf)

    else:
        pcap_scan(args.pcap, keywords)

PRINTABLE_RE = re.compile(rb"[ -~]{3,}")
PORT_RE = re.compile(r":\d+$") 
observations = defaultdict(set)

def summary_printer():
    while True:
        time.sleep(3)
        print("\x1b[2J\033[H")
        print("\n--- Summary ---")
        for keyword, sources in observations.items():
            if "\\mailslot\\browse" in keyword.lower():
               continue
            print(f"{keyword}")
            for ip in sources:
                print(f"  Observed from: {ip}")
        print("----------------")

threading.Thread(target=summary_printer, daemon=True).start()

if __name__ == "__main__":
    main()
