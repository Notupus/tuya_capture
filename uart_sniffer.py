import serial
import time
import json
import threading
from queue import Queue
import sys

# --- Configuration ---
BAUD_RATE = 115200
PORT_1 = '/dev/ttyACM0'
PORT_2 = '/dev/ttyACM1'
OUTPUT_FILE = 'uart_capture_buffered.json'

data_queue = Queue()

def read_serial_port(port_name, label, baud_rate):
    try:
        ser = serial.Serial(
            port=port_name, 
            baudrate=baud_rate, 
            bytesize=serial.EIGHTBITS,
            parity=serial.PARITY_NONE, 
            stopbits=serial.STOPBITS_ONE,
            timeout=0.1 
        )
        print(f"[*] Listening on {port_name} ({label}) at {baud_rate} 8N1...")

        buffer = bytearray()

        while True:
            chunk = ser.read(1024)
            
            if chunk:
                buffer.extend(chunk)

                # --- Strict Synchronization & Silent Discard ---
                # We need at least 2 bytes to find the "A5 01" frame start
                while len(buffer) >= 2:
                    start_idx = -1
                    
                    # Search the buffer for the Tuya/GFW start signature
                    for i in range(len(buffer) - 1):
                        if buffer[i] == 0xA5 and buffer[i+1] == 0x01:
                            start_idx = i
                            break
                    
                    if start_idx != -1:
                        # Silently discard any bootloader garbage before the valid start byte
                        if start_idx > 0:
                            buffer = buffer[start_idx:]
                        
                        # At this point, buffer[0] is guaranteed to be A5 and buffer[1] is 01
                        # We need at least 8 bytes to safely read the length byte (index 7)
                        if len(buffer) >= 8:
                            expected_length = buffer[7]
                            
                            # Sanity check: packet length must be realistic
                            if expected_length < 8 or expected_length > 255:
                                # False positive, pop the A5 so we can continue searching
                                buffer.pop(0)
                                continue
                            
                            # Check if the full packet has arrived in the buffer
                            if len(buffer) >= expected_length:
                                packet_bytes = buffer[:expected_length]
                                
                                # Advance the buffer past this complete packet
                                buffer = buffer[expected_length:]
                                
                                packet = {
                                    "timestamp": time.time(),
                                    "source": label,
                                    "length": expected_length,
                                    "data_hex": packet_bytes.hex()
                                }
                                data_queue.put(packet)
                            else:
                                # Valid header, but full packet hasn't arrived yet. Wait for next serial chunk.
                                break 
                        else:
                            # Valid header, but length byte hasn't arrived yet. Wait.
                            break
                    else:
                        # No "A5 01" signature found in the current buffer.
                        # Discard the garbage, but keep the very last byte just in case 
                        # it's an 'A5' and the '01' arrives in the next serial chunk.
                        if len(buffer) > 1:
                            buffer = buffer[-1:]
                        break
                
    except serial.SerialException as e:
        print(f"\n[!] Error opening {port_name}: {e}")
        sys.exit(1)

def writer_thread(output_filename):
    print(f"[*] Saving capture to {output_filename}...")
    print("-" * 70)
    print(f"{'TIMESTAMP':<15} | {'SOURCE':<18} | {'LEN':<4} | {'DATA (HEX)'}")
    print("-" * 70)
    
    with open(output_filename, 'w') as f:
        f.write("[\n") 
        first_entry = True
        
        while True:
            packet = data_queue.get()
            
            ts_str = f"{packet['timestamp']:.3f}"
            print(f"[{ts_str:<13}] | {packet['source']:<18} | {packet['length']:<4} | {packet['data_hex']}")

            if not first_entry:
                f.write(",\n")
            
            f.write(json.dumps(packet, indent=4))
            first_entry = False
            f.flush() 
            data_queue.task_done()

if __name__ == "__main__":
    print("--- Protocol-Aware UART Sniffer ---")
    writer = threading.Thread(target=writer_thread, args=(OUTPUT_FILE,), daemon=True)
    writer.start()

    t1 = threading.Thread(target=read_serial_port, args=(PORT_1, "AC (ACM0)", BAUD_RATE), daemon=True)
    t2 = threading.Thread(target=read_serial_port, args=(PORT_2, "Dongle (ACM1)", BAUD_RATE), daemon=True)

    t1.start()
    t2.start()

    try:
        while True:
            time.sleep(0.5)
    except KeyboardInterrupt:
        print("\n\n[!] Stopping capture...")
        with open(OUTPUT_FILE, 'a') as f:
            f.write("\n]\n")
        print(f"[*] Capture cleanly saved to {OUTPUT_FILE}. Exiting.")
        sys.exit(0)