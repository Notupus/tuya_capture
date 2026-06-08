# A Brute-Force CRC-16 Cracker for TCL/Tuya MCU Protocols
import binascii

def crc16_generic(data, poly, init, xor_out, ref_in, ref_out):
    crc = init
    for byte in data:
        if ref_in:
            byte = int('{:08b}'.format(byte)[::-1], 2)
        crc ^= (byte << 8)
        for _ in range(8):
            if crc & 0x8000:
                crc = (crc << 1) ^ poly
            else:
                crc = (crc << 1)
            crc &= 0xFFFF
    if ref_out:
        crc = int('{:016b}'.format(crc)[::-1], 2)
    return crc ^ xor_out

# The Top 8 Most Common Industrial CRC-16 Algorithms
ALGORITHMS = {
    "CRC-16/MODBUS":      (0x8005, 0xFFFF, 0x0000, True, True),
    "CRC-16/ARC":         (0x8005, 0x0000, 0x0000, True, True),
    "CRC-16/MAXIM":       (0x8005, 0x0000, 0xFFFF, True, True),
    "CRC-16/CCITT-FALSE": (0x1021, 0xFFFF, 0x0000, False, False),
    "CRC-16/XMODEM":      (0x1021, 0x0000, 0x0000, False, False),
    "CRC-16/KERMIT":      (0x1021, 0x0000, 0x0000, True, True),
    "CRC-16/MCRF4XX":     (0x1021, 0xFFFF, 0x0000, True, True),
    "CRC-16/GENIBUS":     (0x1021, 0xFFFF, 0xFFFF, False, False)
}

# A confirmed valid packet from your very first capture
# a5 01 01 21 5b 00 00 0f [95 f8] 0a 0a 00 01 01
raw_packet = bytes.fromhex("a50101215b00000f95f80a0a000101")
expected_crc_be = "95F8" # Big Endian
expected_crc_le = "F895" # Little Endian (Swapped)

print(f"Target CRC to find: {expected_crc_be} (or {expected_crc_le})")
print("-" * 60)

# The different ways the manufacturer might have sliced the bytes
data_variations = {
    "Skipped CRC Bytes": raw_packet[:8] + raw_packet[10:],
    "Skipped Start Byte & CRC": raw_packet[1:8] + raw_packet[10:],
    "CRC Bytes Replaced with 00 00": raw_packet[:8] + b'\x00\x00' + raw_packet[10:],
    "Only the Header": raw_packet[:8],
    "Only the Payload": raw_packet[10:]
}

found = False
for algo_name, params in ALGORITHMS.items():
    poly, init, xor_out, ref_in, ref_out = params
    
    for slice_name, data in data_variations.items():
        calc_crc = crc16_generic(data, poly, init, xor_out, ref_in, ref_out)
        calc_hex = f"{calc_crc:04X}"
        
        if calc_hex == expected_crc_be:
            print(f"✅ CRACKED! Algorithm: {algo_name}")
            print(f"   Data Splicing: {slice_name}")
            print(f"   Byte Order: Big Endian")
            found = True
        elif calc_hex == expected_crc_le:
            print(f"✅ CRACKED! Algorithm: {algo_name}")
            print(f"   Data Splicing: {slice_name}")
            print(f"   Byte Order: Little Endian (Swapped)")
            found = True

if not found:
    print("❌ Standard CRC-16 algorithms did not match. The manufacturer might be using a proprietary checksum (e.g., standard byte addition).")