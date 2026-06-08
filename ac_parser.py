import json
import os
import sys
import re

# --- 1. Master Protocol Schema (Verified via thing_data_cfg) ---
PROPERTIES = {
    # --- COMMANDS (Writable) ---
    0x0001: ("Power", 1, {0: "Off", 1: "On"}),
    0x0002: ("Target Temp", 4, lambda val: f"{val / 100.0}°C"),
    0x0005: ("Fan Speed Mode", 1, {0x00: "Auto", 0x01: "Lowest", 0x02: "Low", 0x03: "Mid-Low", 0x04: "Mid", 0x05: "Mid-High", 0x06: "High", 0x07: "Turbo"}),
    0x000E: ("Horizontal Swing", 1, {1: "Auto L/R", 2: "Flow Left", 3: "Flow Middle", 4: "Flow Right", 9: "Fix Left", 10: "Fix Mid-Left", 11: "Fix Middle", 12: "Fix Mid-Right", 13: "Fix Right"}),
    0x0011: ("Vertical Swing", 1, {1: "Auto Up/Down", 2: "Flow Up", 3: "Flow Down", 9: "Fix Above", 10: "Fix Mid-High", 11: "Fix Middle", 12: "Fix Mid-Low", 13: "Fix Down"}),
    0x0012: ("AC Mode", 1, {0x00: "Auto", 0x01: "Cool", 0x02: "Dry", 0x03: "Fan", 0x04: "Heat"}),
    0x0015: ("Health/Ionizer Mode", 1, {0: "Off", 1: "On"}),
    0x001E: ("Display Light", 1, {0: "Off", 1: "On"}),
    0x0022: ("Sleep Mode", 1, {0: "Off", 1: "Standard", 2: "Aged", 3: "Child"}),
    0x0025: ("Buzzer/Beep", 1, {0: "Off", 1: "On"}),
    0x0027: ("Timer Status", 4, lambda val: f"Active/Value: {hex(val)}"),
    0x002D: ("Generator Mode", 1, {0: "Off", 1: "Level 1", 2: "Level 2", 3: "Level 3"}),
    0x0038: ("Unknown Toggle", 1, lambda val: f"{hex(val)}"),
    0x0073: ("Mute", 1, {0: "Off", 1: "On"}),
    0x00DF: ("Eco Mode", 1, {0: "Off", 1: "On"}),

    # --- TELEMETRY & HARDWARE DIAGNOSTICS (Read-Only) ---
    0x0003: ("Current Temp", 4, lambda val: f"{val / 100.0}°C"),
    0x000C: ("Vert Motor Status", 1, {0: "Stopped", 1: "Moving"}),
    0x000D: ("Horiz Motor Status", 1, {0: "Stopped", 1: "Moving"}),
    0x003D: ("Energy/Electricity", 4, lambda val: f"{val} (Raw Unit)"),      # DP127
    0x005C: ("Indoor Fan Speed", 4, lambda val: f"{val} RPM"),               # Confirmed Telemetry
    0x0060: ("Outdoor Temp", 4, lambda val: f"{val / 100.0}°C"),
    0x0064: ("Outdoor Fan Speed", 4, lambda val: f"{val} RPM"),              # DP117
    0x0065: ("Runtime Counter", 4, lambda val: f"{val} (Min/Ticks)"),
    0x00A4: ("Filter Health", 4, lambda val: f"{val}%"),
    0x00BD: ("System Flag 1", 4, lambda val: f"{hex(val)}"),
    0x00C0: ("Compressor Target/Run", 4, lambda val: f"{val} Hz"),           # DP120
    0x00FA: ("Filter Buffer A", 7, lambda val: f"Array ({hex(val)})"),
    0x00FB: ("Filter Buffer B", 7, lambda val: f"Array ({hex(val)})"),
}

# --- 2. CRC-16 XMODEM Implementation (Cracked Algorithm) ---
def calculate_crc16_xmodem(data: bytes) -> int:
    """
    Calculates CRC-16/XMODEM checksum.
    Polynomial: 0x1021, Initial: 0x0000, Big Endian
    """
    crc = 0x0000
    for byte in data:
        crc ^= (byte << 8)
        for _ in range(8):
            if crc & 0x8000:
                crc = (crc << 1) ^ 0x1021
            else:
                crc = (crc << 1)
            crc &= 0xFFFF
    return crc

# --- 3. Payload Decoder ---
# Load schema map for dynamic type and length resolution
SCHEMA_FILE = os.path.join(os.path.dirname(__file__), "thing_data_cfg_e1k5wioo_map_postable_v1.json")
SCHEMA_MAP = {}
if os.path.exists(SCHEMA_FILE):
    with open(SCHEMA_FILE, 'r') as f:
        schema_data = json.load(f)
        for record in schema_data.get("records", []):
            internal_id = int(record["internal_id_hex"], 16)
            SCHEMA_MAP[internal_id] = {
                "code": record["schema_code"],
                "type": record["property_type"]
            }

def decode_payload(payload_bytes):
    idx = 0
    decoded_items = []
    
    while idx < len(payload_bytes):
        if idx + 2 > len(payload_bytes):
            break
            
        prop_id = int.from_bytes(payload_bytes[idx:idx+2], byteorder='big')
        idx += 2
        
        prop_type = None
        code = f"Unknown"
        
        if prop_id in SCHEMA_MAP:
            code = SCHEMA_MAP[prop_id]["code"]
            prop_type = SCHEMA_MAP[prop_id]["type"]
            
        name = f"[{hex(prop_id)}] {code}"
        decoder = None
        length = None
        
        if prop_id in PROPERTIES:
            p_name, p_length, p_decoder = PROPERTIES[prop_id]
            name = f"[{hex(prop_id)}] {p_name} ({code})" if code != "Unknown" else f"[{hex(prop_id)}] {p_name}"
            decoder = p_decoder
            if not prop_type:
                length = p_length
                
        # Determine length based on schema type
        if prop_type in ("bool", "enum"):
            length = 1
        elif prop_type == "value":
            length = 4
        elif prop_type == "string":
            if idx + 2 > len(payload_bytes):
                break
            length = int.from_bytes(payload_bytes[idx:idx+2], byteorder='big')
            idx += 2
        elif prop_type == "raw":
            if idx + 1 > len(payload_bytes):
                break
            length = payload_bytes[idx]
            idx += 1
            
        # Hardcoded lengths for internal/reserved fields found in real captures
        if prop_id == 0x0095 and length is None:
            length = 4
        if prop_id == 0x0074 and length is None:
            length = 1
        if prop_id == 0x0072 and length is None:
            length = 4
            
        if length is None:
            remaining = payload_bytes[idx:].hex()
            decoded_items.append(f"  - {name}: UNKNOWN TYPE/LENGTH. Remaining: {remaining}")
            break
            
        if idx + length > len(payload_bytes):
            decoded_items.append(f"  - {name}: Incomplete Data")
            break
            
        raw_val_bytes = payload_bytes[idx:idx+length]
        idx += length
        raw_val = int.from_bytes(raw_val_bytes, byteorder='big')
        
        if decoder:
            try:
                if isinstance(decoder, dict):
                    val_str = decoder.get(raw_val, f"UNKNOWN_STATE ({hex(raw_val)})")
                else:
                    val_str = decoder(raw_val)
            except Exception:
                val_str = f"Decode Error ({raw_val})"
        else:
            if prop_type in ("string", "raw"):
                val_str = raw_val_bytes.hex()
            else:
                val_str = str(raw_val)
                
        decoded_items.append(f"  - {name}: {val_str}")
            
    return decoded_items

# --- 4. Main PCAP Parser ---
def parse_pcap_json(filepath_or_data):
    # Support both passing a file path or raw JSON array (for testing)
    if filepath_or_data.strip().startswith("["):
        data = json.loads(filepath_or_data)
    else:
        if not os.path.exists(filepath_or_data):
            print(f"Error: File '{filepath_or_data}' not found.")
            sys.exit(1)
        with open(filepath_or_data, 'r') as f:
            data = json.load(f)

    print("=" * 95)
    print(f"{'TIMESTAMP':<15} | {'SOURCE':<14} | {'CRC'} | {'LEN'} | DECODED PAYLOAD")
    print("=" * 95)

    for packet in data:
        raw_hex = packet.get("data_hex", "")
        source = packet.get("source", "Unknown")
        length = packet.get("length", len(raw_hex)//2)
        timestamp = str(packet.get("timestamp", ""))[:14]
        
        b = bytes.fromhex(raw_hex)
        crc_status = "N/A"
        
        # Verify A5 Frame and extract header fields
        if b.startswith(b'\xa5') and len(b) >= 12:
            received_crc = b[8:10].hex().upper()
            
            # Splice bytes: everything before CRC + everything after CRC
            data_to_check = b[:8] + b[10:] 
            calc_crc = calculate_crc16_xmodem(data_to_check)
            calc_crc_hex = f"{calc_crc:04X}"
            
            crc_status = "OK " if received_crc == calc_crc_hex else "ERR"

            # Parse explicitly requested header fields
            a5_header = b[0:3].hex()
            frame_class = hex(b[3])
            seq_status = b[4:6].hex()
            pkt_len = int.from_bytes(b[6:8], byteorder='big')
            cmd_resp = b[10:12].hex()
            
            hdr_str = f"[A5:{a5_header[:2]} Class:{frame_class} Seq:{seq_status} L:{pkt_len} Cmd:{cmd_resp}]"
            
            payload = b[12:]
            
            # Detect JSON/String embedded configs
            json_match = re.search(b'\\{.*\\}', payload)
            
            if len(payload) == 0:
                print(f"{timestamp:<15} | {source:<14} | {crc_status} | {length:<3} | {hdr_str} [Keep-Alive / ACK]")
            else:
                print(f"{timestamp:<15} | {source:<14} | {crc_status} | {length:<3} | {hdr_str} [Payload: {payload.hex()}]")
                
                if json_match:
                    try:
                        config_str = json_match.group(0).decode('utf-8')
                        print(f"{' ':<42}- MCU Config: {config_str}")
                    except Exception:
                        pass
                else:
                    results = decode_payload(payload)
                    for res in results:
                        print(f"{' ':<42}{res}")
        else:
            # Detect generic Keep-Alive/ACK markers outside of full A5 frame (if any)
            if len(b) == 2 and (b[0] == b[1] or b.startswith(b'\x80')):
                print(f"{timestamp:<15} | {source:<14} | N/A | {length:<3} | [Keep-Alive / ACK: {b.hex()}]")
            else:
                print(f"{timestamp:<15} | {source:<14} | N/A | {length:<3} | [Malformed/Short/Raw Packet: {b.hex()}]")
        
        print("-" * 95)

if __name__ == "__main__":
    # Point this to your actual JSON file
    target_file = "uart_capture_buffered.json"
    
    # If the file exists, run it.
    if os.path.exists(target_file):
        parse_pcap_json(target_file)
    else:
        print(f"Please place {target_file} in the same directory.")