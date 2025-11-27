import binascii

# ======================================================================
#   Decoder for TYPE C1 (BMS CELL VOLTAGES)
# ======================================================================

def decode_c1_payload(payload_bytes):
    # payload_bytes: WITHOUT "AA55", WITHOUT ID_IDENT (len 19), WITHOUT CRC (len 2)

    try:
        if len(payload_bytes) < 2:
            return "\n--- ERROR C1: payload bad len ---\n"

        cells_all_len = payload_bytes[0]     # byte[0] — len payload_cells (Expected 40)
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
        cells_temp_start = 2
        cells_temp_f = cells_info[cells_temp_start]
        cells_temp_f_dec = int(cells_temp_f)
        cells_temp_c = (cells_temp_f_dec - 32) * 5 / 9
        cells_info_hex = binascii.hexlify(cells_info).decode().upper()
        cells_error_code = cells_last[cells_error_code_start:]
        cells_error_code_hex = binascii.hexlify(cells_error_code).decode().upper()

        payload_last = payload_bytes[cells_all_len:]          # all last after payload_cells_len
        payload_last_hex = binascii.hexlify(payload_last).decode().upper()
        # 0C10/0C0C
        major_version = payload_last[-2]  # 0C -> 12 (Dec)
        minor_version = payload_last[-1]  # 10 -> 16 (Dec)

        # -------------------------------------------------------------
        # FORM OUTPUT
        # -------------------------------------------------------------
        output = []
        output.append("--- DETAILS DECODE C1 ---")

        # ---------------- 1.1 ----------------
        output.append(
            f"1.1) payload: cells_all_len={cells_all_len} cells_cnt={cells_cnt}"
            f" cells_len: {cells_len}   cells_last_len: {len(cells_last)}"
        )

        # ---------------- 1.2 ----------------
        output.append(
            f"1.2) payload: cells_data_hex: {cells_data_hex}"
            f" cells_info: {cells_info_hex}"
            f" cells_info_error_code: {cells_error_code_hex}"
            f" payload_last_hex: {payload_last_hex}"
        )

        # ---------------- 1.3 MIN/MAX/DELTA ----------------
        voltages_mV = []
        for i in range(cells_cnt):
            vb = cells_data[i*2 : i*2 + 2]
            mv = int.from_bytes(vb, "big")
            voltages_mV.append(mv)

        min_mV = min(voltages_mV)
        max_mV = max(voltages_mV)
        delta_mV = max_mV - min_mV

        # поріг
        delta_limit = 100
        balance = "Balance - OK" if delta_mV <= delta_limit else "Unbalance"

        # ---------------- SUM / MIN/MAX / DELTA + MIN/MAX CELL INDEX ----------------
        sum_mV = sum(voltages_mV)
        sum_V = sum_mV / 1000.0

        idx_min = voltages_mV.index(min_mV) + 1   # 1-based index
        idx_max = voltages_mV.index(max_mV) + 1

        # ФОРМАТ: Ver: XXYY
        output.append(
            f"1.3) Ver: V{major_version:02}{minor_version:02} SUM_V = {sum_V:.2f} V Temp = {cells_temp_c:.2f} °C "
            f"Cell{idx_min}_MIN={min_mV/1000:.3f} V "
            f"Cell{idx_max}_MAX={max_mV/1000:.3f} V "
            f"DELTA={delta_mV/1000:.3f} V "
            f"{balance}"
        )

        # ---------------- 1.4 ----------------
        error_value = int.from_bytes(cells_error_code, byteorder='big', signed=False)
        if error_value == 0:
            output.append(
                f"1.4) error_code: Error_Byte_Valid"
            )
        else:
            status_list = []
            status_list.append(f"Balance_Status: {balance}")
            status_list.append(f"Error_Flag_Set: {cells_error_code_hex}")
            output.append(
                f"1.4) error_code: Error_Byte_Invalid (Details: {status_list})"
            )

        # ---------------- 1.5 Таблиця ----------------
        output.append("1.5) Cells Table:")
        output.append("#\tHEX\tmV\tV")

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

    # Expected structure: voltage_V_min(2), voltage_V_cur(2), current_A_cur(2), SOC(1), Reserve(1) Status(1), remaining_data_bytes(N)

    try:

        voltage_V_min = int.from_bytes(data_bytes[0:2], byteorder="big", signed=False) / 100      # Uint16
        voltage_V_cur = int.from_bytes(data_bytes[2:4], byteorder="big", signed=False) / 100      # Uint16
        current_A_cur = int.from_bytes(data_bytes[4:6], "big", signed=True) / 10

        soc = data_bytes[6]

        status_raw  = data_bytes[8] # (9-й byte)

        # Remaining data: від data_bytes[8] до кінця
        remaining_data_bytes = data_bytes[8:]
        last_hex = binascii.hexlify(remaining_data_bytes).decode().upper()

        output = [
            "--- DETAILS DECODE C0 (BMS General Status) ---",
            f"1. Voltage Min (V)       : {voltage_V_min:.2f} V",
            f"2. Voltage (V)           : {voltage_V_cur:.2f} V",
            f"3. Current (A)           : {current_A_cur:.2f} A",
            f"4. SOC (%)               : {soc} %",
            f"5. Status Byte           : 0x{status_raw:02X}",
            f"6. Remaining Data (HEX)  : {last_hex}",
            "------------------------------------------------",
        ]

        status_details = []
        if status_raw & 0x01: status_details.append("Charging...")
        if status_raw & 0x02: status_details.append("Discharging...")
        if status_raw & 0x04: status_details.append("Static...")

        if status_details:
            output.append("Status meaning: " + ", ".join(status_details))

        return "\n" + "\n".join(output) + "\n"

    except Exception as e:
        return (
            "\n--- CRITICAL DECODE ERROR C0 ---\n"
            f"{e}\n"
        )

# ======================================================================
#   DECODER FOR TYPE A2 (BMS Configuration Data)
# ======================================================================

def decode_a2_payload(payload_bytes):
    # payload_bytes: WITHOUT "AA55", WITHOUT ID_IDENT (len 19), WITHOUT CRC (len 2)
    # Expected 2 bytes (0C 10)
    if len(payload_bytes) != 2:
        return "\n--- Error A2: Incorrect data length ---"

    # 0C10
    major_version = payload_bytes[-2]  # 0C -> 12 (Dec)
    minor_version = payload_bytes[-1]  # 10 -> 16 (Dec)

    # ФОРМАТ: Ver: XXYY
    return f"\nVer: V{major_version:02}{minor_version:02}\n"