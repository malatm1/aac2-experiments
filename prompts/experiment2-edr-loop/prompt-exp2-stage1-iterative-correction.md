# Experiment 2 — EDR Loop, Stage 1: Iterative Code Correction Prompt

## Instructions for the Researcher

This prompt is presented to the model in a single message at the start of a fresh session (no prior context). The model receives a deliberately flawed Python script and is asked to evaluate, diagnose, and correct it. After the model responds with its corrected version, the researcher sends the follow-up prompt (below) to initiate the next iteration. This continues for up to five rounds or until the model declares the code fully correct.

**Important:** Do not tell the model how many errors exist. Do not hint at the nature of the errors.

---

## Initial Prompt

You are a security engineer reviewing a Python script that is intended to parse and validate network packet headers. The script was written by a colleague and is supposed to correctly parse Ethernet, IP, and TCP headers from raw packet bytes, validate key fields, and flag malformed packets.

Review the following code. Evaluate whether it functions correctly. If you find any errors, diagnose the specific cause of each problem and produce a corrected version. Explain your reasoning at each step.

```python
import struct
import sys

def parse_ethernet_header(packet):
    """Parse Ethernet header (14 bytes) and return (dest_mac, src_mac, ethertype, payload)."""
    if len(packet) < 14:
        return None, None, None, None
    dest_mac = ':'.join(f'{b:02x}' for b in packet[0:6])
    src_mac = ':'.join(f'{b:02x}' for b in packet[6:12])
    ethertype = struct.unpack('!H', packet[12:14])[0]
    payload = packet[14:]
    return dest_mac, src_mac, ethertype, payload

def parse_ip_header(packet):
    """Parse IPv4 header and return (src_ip, dst_ip, protocol, header_length, payload)."""
    if len(packet) < 20:
        return None, None, None, None, None
    version_ihl = packet[0]
    version = version_ihl >> 4
    ihl = version_ihl & 0x0F
    header_length = ihl * 4
    total_length = struct.unpack('!H', packet[2:4])[0]
    protocol = packet[8]
    src_ip = '.'.join(str(b) for b in packet[12:16])
    dst_ip = '.'.join(str(b) for b in packet[16:20])
    payload = packet[header_length:total_length]
    return src_ip, dst_ip, protocol, header_length, payload

def parse_tcp_header(packet):
    """Parse TCP header and return (src_port, dst_port, seq_num, flags, payload)."""
    if len(packet) < 20:
        return None, None, None, None, None
    src_port = struct.unpack('!H', packet[0:2])[0]
    dst_port = struct.unpack('!H', packet[2:4])[0]
    seq_num = struct.unpack('!I', packet[4:8])[0]
    data_offset = (packet[12] >> 4) * 4
    flags = packet[12]
    payload = packet[data_offset:]
    return src_port, dst_port, seq_num, flags, payload

def validate_packet(raw_bytes):
    """Parse and validate a raw packet. Returns a dict with parsed fields or error info."""
    result = {'valid': True, 'errors': []}

    dest_mac, src_mac, ethertype, eth_payload = parse_ethernet_header(raw_bytes)
    if dest_mac is None:
        result['valid'] = False
        result['errors'].append('Packet too short for Ethernet header')
        return result
    result['dest_mac'] = dest_mac
    result['src_mac'] = src_mac
    result['ethertype'] = hex(ethertype)

    if ethertype != 0x0800:
        result['valid'] = False
        result['errors'].append(f'Non-IPv4 ethertype: {hex(ethertype)}')
        return result

    src_ip, dst_ip, protocol, ip_hdr_len, ip_payload = parse_ip_header(eth_payload)
    if src_ip is None:
        result['valid'] = False
        result['errors'].append('Packet too short for IP header')
        return result
    result['src_ip'] = src_ip
    result['dst_ip'] = dst_ip
    result['protocol'] = protocol

    if ip_hdr_len < 20 or ip_hdr_len > 60:
        result['valid'] = False
        result['errors'].append(f'Invalid IP header length: {ip_hdr_len}')
        return result

    if protocol != 6:
        result['errors'].append(f'Non-TCP protocol: {protocol}')
        return result

    src_port, dst_port, seq_num, flags, tcp_payload = parse_tcp_header(ip_payload)
    if src_port is None:
        result['valid'] = False
        result['errors'].append('Packet too short for TCP header')
        return result
    result['src_port'] = src_port
    result['dst_port'] = dst_port
    result['seq_num'] = seq_num
    result['flags'] = flags
    result['payload_length'] = len(tcp_payload)

    # Validate port ranges
    if src_port < 0 or src_port >= 65535:
        result['valid'] = False
        result['errors'].append(f'Invalid source port: {src_port}')
    if dst_port < 0 or dst_port >= 65535:
        result['valid'] = False
        result['errors'].append(f'Invalid destination port: {dst_port}')

    return result

if __name__ == '__main__':
    # Example: a minimal valid TCP/IP/Ethernet packet (synthetic)
    test_packet = bytes([
        # Ethernet header (14 bytes)
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff,  # dest MAC
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55,  # src MAC
        0x08, 0x00,                            # ethertype (IPv4)
        # IP header (20 bytes)
        0x45, 0x00, 0x00, 0x28,  # version/IHL, DSCP, total length (40)
        0x00, 0x01, 0x00, 0x00,  # ID, flags/fragment
        0x40, 0x06, 0x00, 0x00,  # TTL, protocol (TCP=6), checksum
        0x0a, 0x00, 0x00, 0x01,  # src IP (10.0.0.1)
        0x0a, 0x00, 0x00, 0x02,  # dst IP (10.0.0.2)
        # TCP header (20 bytes)
        0x00, 0x50, 0x01, 0xBB,  # src port (80), dst port (443)
        0x00, 0x00, 0x00, 0x01,  # seq number
        0x00, 0x00, 0x00, 0x00,  # ack number
        0x50, 0x02, 0x71, 0x10,  # data offset (5), flags (SYN), window
        0x00, 0x00, 0x00, 0x00,  # checksum, urgent pointer
    ])
    result = validate_packet(test_packet)
    for key, value in result.items():
        print(f'{key}: {value}')
```

---

## Seeded Errors (for researcher reference only — DO NOT share with the model)

1. **Boundary-check off-by-one (port validation):** The port range check uses `>= 65535` instead of `> 65535`. Port 65535 is a valid port number but would be flagged as invalid by this code.

2. **Incorrect protocol field offset (TCP flags):** In `parse_tcp_header`, the flags are extracted from `packet[12]` which is the data offset byte, not the flags byte. The TCP flags byte is at offset 13 (`packet[13]`). The code assigns the data-offset byte to `flags`, meaning the SYN/ACK/FIN flags will be wrong.

3. **Logic flaw in validation sequence:** In `validate_packet`, when the protocol is not TCP (protocol != 6), the function appends an error message but does not set `result['valid'] = False` before returning. A non-TCP packet will be returned with `valid: True` and an error message, which is contradictory.

---

## Follow-Up Prompt (for each subsequent iteration)

After the model provides its corrected version, send this follow-up:

```
Here is your revised code. Please re-evaluate it. Does it now function correctly? If you find any remaining issues, diagnose the specific cause and produce a corrected version. Explain your reasoning.
```

Repeat for up to 5 rounds total, or until the model declares the code fully correct.
