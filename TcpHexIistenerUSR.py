import socket
import datetime
import os
import sys
import binascii

from TcpCrcUtilitiesUSR import check_packet_crc
from TcpDecodersUSR import decode_c1_payload, decode_c0_payload, decode_c0_bms_info_payload, decode_a2_payload

# TCP port to listen on
# --- DEFAULT PORT CONSTANT ---
# This port will be used if no argument is provided.
DEFAULT_PORT = 8898

# Check number of arguments
# sys.argv is a list of arguments, where:
# sys.argv[0] = script name ('TcpHexIistenerUSR.py')

if len(sys.argv) == 1:
    # Case 1: No argument provided (run as: python3 script.py)
    PORT = DEFAULT_PORT
    print(f"Port argument missing. Using default port: {PORT}")

elif len(sys.argv) == 2:
    # Case 2: Argument provided (run as: python3 script.py 12345)
    try:
        # Read and convert the first argument to an integer
        PORT = int(sys.argv[1])

        # Optional check for valid port range (8891 - 8898)
        if not (8890 < PORT < 8899):
            print(f"Error: Port {PORT} must be in the range 8891 - 8898.")
            os._exit(1)

    except ValueError:
        # Error handling if the argument is not a number
        print(f"Error: '{sys.argv[1]}' is not a valid port number (integer required).")
        os._exit(1)

else:
    # Case 3: Too many arguments
    print("Usage: python3 TcpHexIistenerUSR.py [<port_number>]")
    os._exit(1)

# --- CONFIGURATION ---
# IP address to listen on (localhost) "0.0.0.0"
# Start-of-packet prefix
START_SIGN = b'\xAA\x55'
# Expected ID (19 bytes)
# C0, A2, D0
EXPECTED_ID_S_HEX = '31343133413037424C444F5047303039303031' # == 1413A07SLDOPG009001
# C1
EXPECTED_ID_B_HEX = '31343133413037424C444F5047303039303031' # == 1413A07BLDOPG009001
# !!! WE USE LENGTH ONLY !!!
ID_LENGTH = 19
# Minimum packet length (START_SIGN + TYPE + ID + 2 bytes CRC)
MIN_PACKET_LENGTH = len(START_SIGN) + 1 + ID_LENGTH + 2

# --- LOGGING SETUP ---
LOG_DIR = f'./logs_{PORT}'
ALL_LOG_FILE = os.path.join(LOG_DIR, 'all.log')

# Dictionary to store the last Payload for each typeFrame
last_payloads = {}

# --- ГЛОБАЛЬНА ЗМІННА ДЛЯ СИСТЕМНИХ ПОВІДОМЛЕНЬ ---
# Зберігає Created log directory, Waiting for connection
SYSTEM_MESSAGES_PREFIX = ""
# --- КІНЕЦЬ ГЛОБАЛЬНОЇ ЗМІННОЇ ---


def setup_logging():
    """Creates the log directory if it doesn't exist."""
    if not os.path.exists(LOG_DIR):
        os.makedirs(LOG_DIR)
        # Вивід на консоль тепер відбувається у main()

# --- НОВА ФУНКЦІЯ: Збирає початкові повідомлення у змінну ---
def prepare_system_messages(listen_host, port):
    """
    Prepares the initial system messages string (directory creation and waiting).
    Returns messages for console output.
    """
    global SYSTEM_MESSAGES_PREFIX

    # 1. Створюємо рядок про директорію (якщо вона створюється)
    dir_msg = ""
    if not os.path.exists(LOG_DIR):
        # Якщо директорія створюється, додаємо відповідний рядок
        dir_msg = f"Created log directory: {LOG_DIR}\n"

    # 2. Додаємо повідомлення про очікування
    wait_msg = f"*** Waiting for connection on {listen_host}:{port} ***\n"

    SYSTEM_MESSAGES_PREFIX = dir_msg + wait_msg

    # Повертаємо рядки для виводу на консоль
    return dir_msg.strip(), wait_msg.strip()
# --- КІНЕЦЬ НОВОЇ ФУНКЦІЇ ---


def get_current_time_ms():
    """Returns the current time in [yyyy-mm-dd HH:MM:SS.mmm] format."""
    now = datetime.datetime.now()
    return now.strftime("[%Y-%m-%d %H:%M:%S.") + f"{now.microsecond // 1000:03d}]"

def write_to_all_log(log_entry):
    """Writes an entry to the all.log file."""
    with open(ALL_LOG_FILE, 'a', encoding='utf-8') as f:
        f.write(log_entry + '\n')

def write_to_type_log(type_frame_hex, payload_hex, payload_bytes, crc_status_message=None):
    """
    Writes the Payload to the type_{typeFrame}.log file.
    Writes SYSTEM_MESSAGES_PREFIX only on the first entry for C1/C0.
    """
    # CORRECTED RULE: Explicit exception for A2 and D0.
    if type_frame_hex == "A2" or type_frame_hex == "D0":
        return

    # (If Payload is empty, do not log.)
    if len(payload_bytes) == 0:
        return

    file_path = os.path.join(LOG_DIR, f'type_{type_frame_hex}.log')

    # If payload is the same — do not write
    if type_frame_hex in last_payloads and last_payloads[type_frame_hex] == payload_hex:
        return

    # Prepare RAW string
    log_line = f"{get_current_time_ms()} {payload_hex}"

    decoded = None
    if type_frame_hex == "C1":
        decoded = decode_c1_payload(payload_bytes)
    elif type_frame_hex == "C0":
        decoded = decode_c0_payload(payload_bytes)


    if decoded:
        log_line += "\n" + decoded

    # ADD CRC INFORMATION
    if crc_status_message:
        log_line += "\n" + crc_status_message + "\n"

    # --- НОВИЙ БЛОК: Додавання префіксу при першому записі ---
    content_to_write = ""
    # Якщо це перший запис для цього типу (C1 або C0)
    if type_frame_hex in ["C1", "C0"] and type_frame_hex not in last_payloads:
        # Додаємо глобальний префікс (який вже містить повідомлення про підключення)
        if SYSTEM_MESSAGES_PREFIX:
            # Використовуємо rstrip() для видалення кінцевого '\n' перед додаванням нового логу
            content_to_write += SYSTEM_MESSAGES_PREFIX.rstrip() + "\n\n"

    content_to_write += log_line + "\n"
    # --- КІНЕЦЬ НОВОГО БЛОКУ ---

    # Write to file
    with open(file_path, 'a', encoding='utf-8') as f:
        f.write(content_to_write)

    # Update last payload
    last_payloads[type_frame_hex] = payload_hex

def parse_and_process_data(buffer):
    """
    Parses the buffer for complete packets (\xAA\x55 ... \xAA\x55)
    and processes them.
    """
    packets = []
    current_index = 0
    end_index = 0  # <--- FIX: Initialize end_index

    # 1. Search and extract packets
    while True:
        start_index = buffer.find(START_SIGN, current_index)
        if start_index == -1:
            break

        end_index = buffer.find(START_SIGN, start_index + len(START_SIGN))

        if end_index == -1:
            # This is the last (possibly incomplete) packet in the buffer
            if len(buffer) - start_index >= MIN_PACKET_LENGTH:
                packet_data = buffer[start_index:]
                packets.append(packet_data)
                current_index = len(buffer)
            break
        else:
            # A complete packet was found
            packet_data = buffer[start_index:end_index]
            if len(packet_data) >= MIN_PACKET_LENGTH:
                packets.append(packet_data)
            current_index = end_index

    # 2. Process extracted packets
    for packet in packets:
        try:
            # Check for START_SIGN (byte 0, 1)
            if packet[:2] != START_SIGN:
                print("ERROR: Invalid start signature!")
                continue

            # byte [2] - typeFrame (Hex)
            type_frame_byte = packet[2:3]
            type_frame_hex = binascii.hexlify(type_frame_byte).decode('utf-8').upper()

            # byte[3, 21] - ID (19 bytes)
            id_bytes = packet[3:3 + ID_LENGTH]
            id_display = id_bytes.decode('ascii') # <<< CHANGE: Decode ID for display

            # byte[22, ...] - Payload
            # Separate CRC (2 bytes) from the end
            payload_with_crc_bytes = packet[3 + ID_LENGTH:]

            # Check that the packet contains CRC (2 bytes)
            if len(payload_with_crc_bytes) < 2:
                print(f"WARNING: Packet of type {type_frame_hex} is too short for CRC.")
                continue

            payload_bytes = payload_with_crc_bytes[:-2]
            crc_bytes = payload_with_crc_bytes[-2:]

            payload_hex = binascii.hexlify(payload_bytes).decode('utf-8').upper()
            crc_hex = binascii.hexlify(crc_bytes).decode('utf-8').upper() # <--- CRC purely for informational purposes

            # --- CRC CHECK (UNIFIED) ---
            crc_message = check_packet_crc(packet, type_frame_hex)

            # --- DISPLAY INFORMATION ---
            timestamp = get_current_time_ms()
            full_packet_hex = binascii.hexlify(packet).decode('utf-8').upper()

            # To screen (Рядок 1)
            output = f"{timestamp} {full_packet_hex}"
            print(output)



            # Display details and CRC information

            # REQUIREMENT: If Payload is empty, display 'Payload: null - CRC: {crc_hex}'
            if len(payload_bytes) == 0:
                payload_display_details = f"null - CRC: {crc_hex}"
            elif type_frame_hex == "A2":
                # Decode A2 only for screen output
                version_info = decode_a2_payload(payload_bytes)
                payload_display_details = f"{payload_hex} {version_info.strip().replace('\n', ' ')}"
            else:
                payload_display_details = payload_hex

            # <<< CHANGE: Use id_display for ID >>>
            details = f"  TYPE: {type_frame_hex} ID: {id_display} Payload: {payload_display_details}"

            # Add from C0 short info

            # Display full CRC status
            crc_line = f"  {crc_message}"

            print(details)
            print(crc_line)
            if  type_frame_hex == "C0":
                info_bms_message = decode_c0_bms_info_payload(payload_bytes)
                print(info_bms_message)

            # To file
            all_log_entry = output + '\n' + details + '\n' + crc_line
            write_to_all_log(all_log_entry)

            # Write only Payload WITHOUT CRC to type_log
            write_to_type_log(type_frame_hex, payload_hex, payload_bytes, crc_line)

        except Exception as e:
            print(f"ERROR processing packet: {e}")
            print(f"Packet (HEX): {binascii.hexlify(packet).decode('utf-8').upper()}")

    # 3. Return the remainder of the buffer
    if not packets:
        return buffer
    else:
        # Return the part of the buffer after the last found packet
        if end_index == -1:
            return buffer[start_index:] if 'start_index' in locals() else b''
        else:
            return buffer[current_index:]

def main():
    """Main function to run the TCP server."""
    listen_host = '0.0.0.0'

    # 1. Створення директорії логів
    setup_logging()

    # 2. Збір початкових повідомлень та вивід на консоль
    dir_msg, wait_msg = prepare_system_messages(listen_host, PORT)
    if dir_msg:
        print(dir_msg)
    print(wait_msg)

    # Примітка: На цьому етапі SYSTEM_MESSAGES_PREFIX містить
    # 'Created log directory...' та '*** Waiting for connection...'

    try:
        # Create TCP socket
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            # Allows reusing the address/port
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.bind((listen_host, PORT))
            s.listen(1) # Listen for only one client

            # Accept connection
            conn, addr = s.accept()
            with conn:
                connect_msg = f"Connected to {addr}"
                print(connect_msg)
                print()

                # --- ОНОВЛЕННЯ GLOBAL ЗМІННОЇ ТА ALL.LOG ---
                global SYSTEM_MESSAGES_PREFIX
                # Додаємо повідомлення про підключення до глобальної змінної
                SYSTEM_MESSAGES_PREFIX += connect_msg + "\n"

                # Записуємо ВСІ початкові системні повідомлення в all.log ОДНИМ БЛОКОМ
                write_to_all_log(SYSTEM_MESSAGES_PREFIX.rstrip()+ "\n")
                # --- КІНЕЦЬ ОНОВЛЕННЯ ---

                # Buffer for incomplete data
                data_buffer = b''

                while True:
                    data = conn.recv(4096)
                    if not data:
                        print("Connection closed by client.")
                        break

                    data_buffer += data

                    # Parse and process data, returns the remainder of the buffer
                    data_buffer = parse_and_process_data(data_buffer)

    except ConnectionRefusedError:
        print(f"ERROR: Connection refused. Ensure the client is actually trying to connect to {PORT}.")
    except Exception as e:
        print(f"Critical error: {e}")
    finally:
        print("*** Listening finished ***")

if __name__ == "__main__":
    main()