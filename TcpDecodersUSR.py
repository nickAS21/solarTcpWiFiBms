import binascii

# ======================================================================
#   ERROR DECODING MAPS (Based on AoBo/Custom Protocol)
# ======================================================================

# Maximum cycle count to 80% SOH level, declared by the manufacturer (GS Energy GBL2.45K3 (SYL Battery) = 6000 - 40000 cycles
BMS_LIFEPO4_CYCLES_TO_80_SOH = 6000

# The percentage (SOH) at which the battery is considered end-of-life
SOH_TERMINAL_PERCENT = 80

# The total SOH percentage range lost before reaching EOL (100% - 80% = 20%)
SOH_DEGRADATION_RANGE = 100 - SOH_TERMINAL_PERCENT  # 20

# Calculation of SOH loss per single cycle (using a linear model)
SOH_LOSS_PER_CYCLE = SOH_DEGRADATION_RANGE / BMS_LIFEPO4_CYCLES_TO_80_SOH

# Byte 1 (MSB, bits 23-16) - Critical/General Flags
# Keys are the bitmask values
BYTE1_ERROR_MAP = {
    0x20: "CRITICAL_FAULT",
    0x10: "WARNING: STATE AFTER CRITICAL...",
    # Add other general flags here if known...
}

# Byte 2 (Middle, bits 15-8) - Specific Error Flags
# Keys are the bitmask values
BYTE2_ERROR_MAP = {
    0x08: "CRITICALLY_LOW_CHARGE (<18%)",
    0x04: "CELL_UNBALANCE",
    0x02: "UNDER_VOLTAGE_CELL",
    0x01: "OVER_VOLTAGE_CELL",
    # Add other specific flags here if known...
}

# --- BALANCE STATUS CONSTANTS (in mV) ---
class BalanceThresholds:
    """Defines the maximum delta_mV for each status level."""
    EXCELLENT_MAX = 10
    GOOD_MAX = 20
    WARN_MAX = 50
    CRITICAL_MAX = 80
    # > 80 mV is considered Dangerous/Emergency Shutdown

# ======================================================================
#   UTILITY FUNCTIONS (Defined FIRST)
# ======================================================================

def decode_error_flags(error_code_int: int) -> list:
    """
    Decodes the 3-byte error code (e.g., 0x200700) using predefined maps.
    """
    messages = []
    byte1 = (error_code_int >> 16) & 0xFF
    byte2 = (error_code_int >> 8) & 0xFF

    for bit_mask, description in BYTE1_ERROR_MAP.items():
        if byte1 & bit_mask:
            messages.append(f"{description} (0x{bit_mask:02X})")

    for bit_mask, description in BYTE2_ERROR_MAP.items():
        if byte2 & bit_mask:
            messages.append(f"{description} (0x{bit_mask:02X})")

    if not messages and error_code_int != 0:
        messages.append(f"UNKNOWN_ERROR_CODE (0x{error_code_int:06X})")

    return messages


def get_balance_status(delta_mV: int) -> str:
    """
    Determines the cell balance status based on the voltage difference (V_max - V_min).
    """
    if delta_mV < 0:
        return "ERROR - Invalid delta_mV (must be non-negative)"

    if delta_mV <= BalanceThresholds.EXCELLENT_MAX:
        return "Excellent"
    elif delta_mV <= BalanceThresholds.GOOD_MAX:
        return "Good"
    elif delta_mV <= BalanceThresholds.WARN_MAX:
        return "Warning"
    elif delta_mV <= BalanceThresholds.CRITICAL_MAX:
        return "Critical"
    else:
        return "Dangerous, Emergency Shutdown"


def decode_bms_status(status_int: int) -> list:
    """
    Decodes the 2-byte BMS status integer into human-readable flags.
    """
    bit_status_map = {
        1: "Charging",
        2: "Discharging",
        3: "Static",
    }
    result = []
    for bit_index, name in bit_status_map.items():
        mask = 1 << (bit_index - 1)
        if status_int & mask:
            result.append(name)

    return result if result else ["None"]


def format_error_code_output(cells_error_code: bytes, number: int) -> str:
    """
    Форматує рядок для виведення коду помилки та його деталей (рядок X).
    """
    error_value = int.from_bytes(cells_error_code, byteorder='big', signed=False)
    cells_error_code_hex = binascii.hexlify(cells_error_code).decode().upper()

    if error_value == 0:
        details = "Byte_Valid"
    else:
        decoded_errors = decode_error_flags(error_value)

        details_list = [f"Error_Code_HEX: {cells_error_code_hex}"]
        details_list.append(f"Decoded_Errors: {', '.join(decoded_errors)}")

        details = f"Byte_Invalid (Details: {'; '.join(details_list)})"

    return f"{number} | Error_Code:      | {details}"


def decode_a2_payload(payload_bytes):
    # payload_bytes: WITHOUT "AA55", WITHOUT ID_IDENT (len 19), WITHOUT CRC (len 2)
    # Expected 2 bytes (0C 10)
    if len(payload_bytes) != 2:
        return "\n--- Error A2: Incorrect data length ---"

    # 0C10
    major_version = payload_bytes[-2]
    minor_version = payload_bytes[-1]

    # ФОРМАТ: Ver: XXYY
    return f"\nVer: V{major_version:02}{minor_version:02}\n"


# ======================================================================
#   Decoder for TYPE C1 (BMS CELL VOLTAGES)
# ======================================================================

def decode_c1_payload(payload_bytes):
    # payload_bytes: WITHOUT "AA55", WITHOUT ID_IDENT (len 19), WITHOUT CRC (len 2)

    try:
        if len(payload_bytes) < 2:
            return "\n--- ERROR C1: payload bad len ---\n"

        cells_all_len = payload_bytes[0]
        cells_cnt = payload_bytes[1]
        cells_len = cells_cnt * 2
        if cells_all_len != 40:
            return (
                "\n--- ERROR in STRUCTURE C1 ---\n"
                f"byte[0] = {cells_all_len}, but it is expected 40\n"
            )

        # -------------------------------------------------------------
        # DATA SPLIT
        # -------------------------------------------------------------

        cells_start_data = 2
        cells_data_all = payload_bytes[: cells_all_len]
        cells_data = cells_data_all[cells_start_data: cells_start_data + cells_len]
        cells_data_hex = binascii.hexlify(cells_data).decode().upper()

        cells_info_start = cells_start_data + cells_len
        cells_last = cells_data_all[cells_info_start:]
        cells_error_code_start = 3
        cells_info = cells_last[: cells_error_code_start]
        cells_soc_start = 2
        cells_soc = cells_info[cells_soc_start]
        # Life Cycles [0, 2]
        cells_life_cycles_count = cells_info[:cells_soc_start]
        cells_life_cycles_count_int = int.from_bytes(cells_life_cycles_count, "big")
        cells_soh = round(100 - (cells_life_cycles_count_int * SOH_LOSS_PER_CYCLE))
        cells_info_hex = binascii.hexlify(cells_info).decode().upper()

        # 3 байти коду помилки для C1
        cells_error_code = cells_last[cells_error_code_start:]
        cells_error_code_hex = binascii.hexlify(cells_error_code).decode().upper()

        payload_last = payload_bytes[cells_all_len:]
        payload_last_hex = binascii.hexlify(payload_last).decode().upper()
        major_version = payload_last[-2]
        minor_version = payload_last[-1]

        # -------------------------------------------------------------
        # FORM OUTPUT
        # -------------------------------------------------------------
        output = []
        output.append("--- DETAILS DECODE C1 ---")

        # ---------------- 1.1 - 1.2 (HEX/Lengths) ----------------
        output.append(
            f"1.1) payload: cells_all_len={cells_all_len} cells_cnt={cells_cnt}"
            f" cells_len: {cells_len}   cells_last_len: {len(cells_last)}"
        )

        output.append(
            f"1.2) payload: cells_data_hex: {cells_data_hex}"
            f" cells_info: {cells_info_hex}"
            f" cells_info_error_code: {cells_error_code_hex}"
            f" payload_last_hex: {payload_last_hex}"
        )

        # ---------------- 1.3 MIN/MAX/DELTA (Calculations) ----------------
        voltages_mV = []
        for i in range(cells_cnt):
            vb = cells_data[i*2 : i*2 + 2]
            mv = int.from_bytes(vb, "big")
            voltages_mV.append(mv)

        min_mV = min(voltages_mV)
        max_mV = max(voltages_mV)
        delta_mV = max_mV - min_mV
        balance = get_balance_status(delta_mV)

        # ---------------- SUM / MIN/MAX / DELTA + MIN/MAX CELL INDEX ----------------
        sum_mV = sum(voltages_mV)
        sum_V = sum_mV / 1000.0

        idx_min = voltages_mV.index(min_mV) + 1   # 1-based index
        idx_max = voltages_mV.index(max_mV) + 1

        # --- New Table Formatting ---

        output.append("1.3) Cells Info Table:")

        output.append("#  | Name             | Value")
        output.append("---|------------------|------------")
        output.append(f"1  | Ver:             | V{major_version:02}{minor_version:02}")
        output.append(f"2  | Life Cycles:     | {cells_life_cycles_count_int}")
        output.append(f"3  | SOC:             | {cells_soc} %")
        output.append(f"4  | SOH:             | {cells_soh:.0f} %")
        output.append(f"5  | SUM_V:           | {sum_V:.2f} V")
        output.append(f"6  | Cell{idx_min:02d}_MIN:      | {min_mV/1000:.3f} V")
        output.append(f"7  | Cell{idx_max:02d}_MAX:      | {max_mV/1000:.3f} V")
        output.append(f"8  | DELTA:           | {delta_mV/1000:.3f} V")
        output.append(f"9  | Balance:         | {balance}")

        # 4. Error Code (3 байти) - Рядок 8
        error_output = format_error_code_output(cells_error_code, 10)
        output.append(error_output)

        output.append(" ")

        # ---------------- 1.4 Таблиця (Cells Table) ----------------
        output.append("1.4) Cells Table:")
        output.append("#\tHEX     mV      V")

        for i in range(cells_cnt):
            vb = cells_data[i*2 : i*2 + 2]
            mv = int.from_bytes(vb, "big")
            vv = mv / 1000
            hex_v = binascii.hexlify(vb).decode().upper()
            output.append(f"{i+1:02}\t{hex_v}\t{mv}\t{vv:.3f} V")

        return "\n" + "\n".join(output) + "\n"

    except Exception as e:
        return f"\n--- CRITICAL ERROR C1 ---\n{e}\n"


# ======================================================================
#   DECODER FOR TYPE C0 (BMS General Status)
# ======================================================================

def decode_c0_payload(payload_bytes):
    # payload_bytes: WITHOUT "AA55", WITHOUT ID_IDENT (len 19), WITHOUT CRC (len 2)

    data_bytes = payload_bytes

    try:

        voltage_V_min = int.from_bytes(data_bytes[0:2], byteorder="big", signed=False) / 100      # Uint16
        voltage_V_cur = int.from_bytes(data_bytes[2:4], byteorder="big", signed=False) / 100      # Uint16
        current_A_cur = int.from_bytes(data_bytes[4:6], "big", signed=True) / 10

        soc = data_bytes[6]

        # Info and error data: від data_bytes[7:] до кінця
        info_error_data_bytes = data_bytes[7:]
        info_error_data_hex = binascii.hexlify(info_error_data_bytes).decode().upper()

        # Розділення: 10 байтів info_raw + 4 байти error_raw
        info_raw  = info_error_data_bytes[:10]
        info_raw_hex  = binascii.hexlify(info_raw).decode().upper()
        error_raw  = info_error_data_bytes[10:] # 4 байти коду помилки
        error_raw_hex  = binascii.hexlify(error_raw).decode().upper()

        # Розділення 10 байтів info_raw:
        state_bms_raw  = info_raw[0:2] # 2 байти стану BMS
        # ВИПРАВЛЕННЯ: Конвертуємо bytes у int для decode_bms_status
        state_bms_int = int.from_bytes(state_bms_raw, byteorder="big", signed=False)
        state_bms_raw_hex = binascii.hexlify(state_bms_raw).decode().upper()
        state_bms_dop1_raw  = info_raw[2:6] # 4 байти
        state_bms_dop1_raw_hex = binascii.hexlify(state_bms_dop1_raw).decode().upper()
        state_bms_dop2_raw  = info_raw[6:] # 4 байти
        state_bms_dop2_raw_hex = binascii.hexlify(state_bms_dop2_raw).decode().upper()

        output = [
            "--- DETAILS DECODE C0 (BMS General Status) ---",
            f"1  | Voltage Min (V)  | {voltage_V_min:.2f} V",
            f"2  | Voltage (V)      | {voltage_V_cur:.2f} V",
            f"3  | Current (A)      | {current_A_cur:.2f} A",
            f"4  | SOC (%)          | {soc} %",
            f"5  | All info Data    | {info_error_data_hex}",
            f"6  | info Data        | {info_raw_hex}",
            f"7  | BMS status       | 0x{state_bms_raw_hex} (2B)",
            f"8  | BMS status1      | 0x{state_bms_dop1_raw_hex} (4B)",
            f"9  | BMS status2      | 0x{state_bms_dop2_raw_hex} (4B)",
            f"10 | Error info Data  | {error_raw_hex} (4B)",
        ]

        # Додаємо Error_Code (4 байти) - Рядок 11
        error_output = format_error_code_output(error_raw, 11)
        output.append(error_output)

        # Декодуємо статус BMS (використовуємо state_bms_int)
        status_details = decode_bms_status(state_bms_int)
        if status_details:
            output.append("12 | BMS status value | " + ", ".join(status_details))

        output.append("------------------------------------------------")

        return "\n" + "\n".join(output) + "\n"

    except Exception as e:
        return (
            "\n--- CRITICAL DECODE ERROR C0 ---\n"
            f"{e}\n"
        )
# ======================================================================
#   DECODER FOR TYPE C0 (BMS Info Short Status)
# ======================================================================

def decode_c0_bms_info_payload(payload_bytes):
    # payload_bytes: WITHOUT "AA55", WITHOUT ID_IDENT (len 19), WITHOUT CRC (len 2)

    data_bytes = payload_bytes

    try:

        voltage_V_cur = int.from_bytes(data_bytes[2:4], byteorder="big", signed=False) / 100      # Uint16
        current_A_cur = int.from_bytes(data_bytes[4:6], "big", signed=True) / 10

        soc = data_bytes[6]

        # Info and error data: від data_bytes[7:] до кінця
        info_error_data_bytes = data_bytes[7:]
        info_error_data_hex = binascii.hexlify(info_error_data_bytes).decode().upper()

        # Розділення: 10 байтів info_raw + 4 байти error_raw
        info_raw  = info_error_data_bytes[:10]
        info_raw_hex  = binascii.hexlify(info_raw).decode().upper()
        error_raw  = info_error_data_bytes[10:13] # 3 байти коду помилки
        error_raw_hex  = binascii.hexlify(error_raw).decode().upper()

        # Розділення 10 байтів info_raw:
        state_bms_raw  = info_raw[0:2] # 2 байти стану BMS
        # ВИПРАВЛЕННЯ: Конвертуємо bytes у int для decode_bms_status
        state_bms_int = int.from_bytes(state_bms_raw, byteorder="big", signed=False)
        state_bms_raw_hex = binascii.hexlify(state_bms_raw).decode().upper()
        state_bms_dop1_raw  = info_raw[2:6] # 4 байти
        state_bms_dop1_raw_hex = binascii.hexlify(state_bms_dop1_raw).decode().upper()
        state_bms_dop2_raw  = info_raw[6:] # 4 байти
        state_bms_dop2_raw_hex = binascii.hexlify(state_bms_dop2_raw).decode().upper()

        output = [
            "--- DETAILS DECODE C0 (BMS General Status) ---",
            f"1 | Voltage (V)      | {voltage_V_cur:.2f} V",
            f"3 | Current (A)      | {current_A_cur:.2f} A",
            f"4 | SOC (%)          | {soc} %",
        ]

        # Додаємо Error_Code (4 байти) - Рядок 5
        error_output = format_error_code_output(error_raw, 5)
        output.append(error_output)

        # Декодуємо статус BMS (використовуємо state_bms_int)
        status_details = decode_bms_status(state_bms_int)
        if status_details:
            output.append("6 | BMS status value | " + ", ".join(status_details))

        output.append("------------------------------------------------")

        return "\n" + "\n".join(output) + "\n"

    except Exception as e:
        return (
            "\n--- CRITICAL DECODE ERROR C0 ---\n"
            f"{e}\n"
        )