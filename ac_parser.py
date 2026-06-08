import json
import os
import sys
import re

# --- 1. Master Protocol Schema (Verified via thing_data_cfg) ---
PROPERTIES = {
    # --- COMMANDS (Writable) ---
    0x0001: ("Power", 1, {0: "Off", 1: "On"}),
    0x0002: ("Target Temp", 4, lambda val: f"{val / 100.0}°C"),
    0x0005: ("Fan Speed Mode", 2, {0x0000: "Auto", 0x0100: "Lowest", 0x0200: "Low", 0x0300: "Mid-Low", 0x0400: "Mid", 0x0500: "Mid-High", 0x0600: "High", 0x0700: "Turbo"}),
    0x000E: ("Horizontal Swing", 1, {1: "Auto L/R", 2: "Flow Left", 3: "Flow Middle", 4: "Flow Right", 9: "Fix Left", 10: "Fix Mid-Left", 11: "Fix Middle", 12: "Fix Mid-Right", 13: "Fix Right"}),
    0x0011: ("Vertical Swing", 1, {1: "Auto Up/Down", 2: "Flow Up", 3: "Flow Down", 9: "Fix Above", 10: "Fix Mid-High", 11: "Fix Middle", 12: "Fix Mid-Low", 13: "Fix Down"}),
    0x0012: ("AC Mode", 2, {0x0000: "Auto", 0x0100: "Cool", 0x0200: "Dry", 0x0300: "Fan", 0x0400: "Heat"}),
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
    0x0060: ("Compressor Internal Freq", 4, lambda val: f"{val} Hz"),
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
def decode_payload(payload_bytes):
    idx = 0
    decoded_items = []
    
    while idx < len(payload_bytes):
        if idx + 2 > len(payload_bytes):
            break
            
        prop_id = int.from_bytes(payload_bytes[idx:idx+2], byteorder='big')
        idx += 2
        
        if prop_id in PROPERTIES:
            name, length, decoder = PROPERTIES[prop_id]
            if idx + length > len(payload_bytes):
                decoded_items.append(f"  - [{hex(prop_id)}] {name}: Incomplete Data")
                break
                
            raw_val = int.from_bytes(payload_bytes[idx:idx+length], byteorder='big')
            idx += length
            
            if isinstance(decoder, dict):
                val_str = decoder.get(raw_val, f"UNKNOWN_STATE ({hex(raw_val)})")
            else:
                val_str = decoder(raw_val)
                
            decoded_items.append(f"  - {name}: {val_str}")
        else:
            remaining = payload_bytes[idx:].hex()
            decoded_items.append(f"  - [?] UNKNOWN DP ({hex(prop_id)}). Remaining: {remaining}")
            break
            
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
        
        # Verify A5 Frame and extract CRC (Bytes 8 & 9)
        if b.startswith(b'\xa5') and len(b) >= 10:
            received_crc = b[8:10].hex().upper()
            
            # Splice bytes: everything before CRC + everything after CRC
            data_to_check = b[:8] + b[10:] 
            calc_crc = calculate_crc16_xmodem(data_to_check)
            calc_crc_hex = f"{calc_crc:04X}"
            
            crc_status = "OK " if received_crc == calc_crc_hex else "ERR"

        # Separate Header (0-9) from Payload (10+)
        if len(b) > 10:
            payload = b[10:]
            
            # Detect JSON/String embedded configs
            json_match = re.search(b'\{.*\}', payload)
            
            # Detect generic Keep-Alive/ACK markers (usually 2 duplicated bytes at start)
            if len(payload) == 2 and (payload[0] == payload[1] or payload.startswith(b'\x80')):
                print(f"{timestamp:<15} | {source:<14} | {crc_status} | {length:<3} | [Keep-Alive / ACK: {payload.hex()}]")
                print("-" * 95)
                continue
                
            print(f"{timestamp:<15} | {source:<14} | {crc_status} | {length:<3} | [Raw Payload: {payload.hex()}]")
            
            if json_match:
                try:
                    config_str = json_match.group(0).decode('utf-8')
                    print(f"{' ':<42}- MCU Config: {config_str}")
                except Exception:
                    pass
            else:
                # Strip 2-byte marker if it looks like a standard DP payload marker (e.g., 0A0A, 0C0C, 0B0B)
                if len(payload) > 2 and payload[0] == payload[1]:
                    dp_payload = payload[2:]
                else:
                    dp_payload = payload
                
                results = decode_payload(dp_payload)
                for res in results:
                    print(f"{' ':<42}{res}")
        else:
            print(f"{timestamp:<15} | {source:<14} | {crc_status} | {length:<3} | [Malformed/Short Packet]")
        
        print("-" * 95)

if __name__ == "__main__":
    # Point this to your actual JSON file
    target_file = "uart_capture_buffered.json"
    
    # If the file exists, run it.
    if os.path.exists(target_file):
        parse_pcap_json(target_file)
    else:
        print(f"Please place {target_file} in the same directory.")