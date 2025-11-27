# ======================================================================
#   FORMATTING TOOLS
# ======================================================================

def to_hex_16(value):
    """Converts an integer into a 4-digit HEX string."""
    return hex(value)[2:].upper().zfill(4)

# ======================================================================
#   CRC-16/MODBUS (0x8005, LSB-first) - FUNCTIONAL CALCULATION
#   Poly: 0x8005 (Reflected: 0xA001), Init: 0x0000, RefIn: True, RefOut: True, XorOut: 0x0000
# ======================================================================

def calculate_crc16_modbus(data: bytes) -> int:
    """
    Calculates the CRC-16/MODBUS (LSB-first) for the given bytes.
    Used for unified AoBo CRC checking.
    """
    crc = 0x0000
    poly_reflected = 0xA001 # 0x8005 reflected

    for byte in data:
        # XOR with the input byte (LSB-first: XOR the lower byte of CRC)
        crc ^= byte

        for _ in range(8):
            # Check LSB (bit 0)
            if (crc & 0x0001) != 0:
                # Right shift and XOR with the reflected polynomial
                crc = (crc >> 1) ^ poly_reflected
            else:
                # Simple right shift
                crc = crc >> 1

            crc &= 0xFFFF # Ensure CRC stays a 16-bit value

    return crc


def check_packet_crc(full_packet: bytes, type_frame_hex: str) -> str:
    """
    Checks the CRC-16/MODBUS according to unified AoBo rules.

    Rule: CRC is calculated FROM AA55 (the entire packet, excluding the last 2 CRC bytes).

    Args:
        full_packet: The complete received packet bytes.
        type_frame_hex: The packet type as a hex string (e.g., "C0").

    Returns:
        A string message containing the CRC check status.
    """
    if len(full_packet) < 4:
        return "CRC Status: BAD. Message: Packet is too short for CRC."

    expected_crc_bytes = full_packet[-2:]
    expected_crc_hex = to_hex_16(int.from_bytes(expected_crc_bytes, 'big'))

    # -------------------------------------------------------------------
    # DEFINE DATA RANGE (UNIFIED RULE: STARTING FROM AA55)
    # -------------------------------------------------------------------

    # ATTENTION: Based on the working MODBUS implementation, we adopt the rule:
    # The entire packet, including AA55, is used for the calculation.
    data_for_crc = full_packet[:-2]

    if len(data_for_crc) == 0:
        return "CRC Status: N/A. Message: Payload/ID is empty."

    # Calculate CRC (Using the MODBUS function)
    calculated_crc_int = calculate_crc16_modbus(data_for_crc)

    # MODBUS result is typically little-endian, but in AoBo it is presented big-endian.
    # Therefore, we simply compare Big Endian bytes.
    # We use big endian for comparison as the incoming data uses big endian for the 2-byte CRC field.
    calculated_crc_bytes = calculated_crc_int.to_bytes(2, byteorder='big')
    calculated_crc_hex = to_hex_16(calculated_crc_int)

    # Comparison
    if calculated_crc_bytes == expected_crc_bytes:
        message = f"CRC Status: OK. Calc/Expected: {calculated_crc_hex}"
    else:
        message = f"CRC Status: BAD. Calc: {calculated_crc_hex} != Expected: {expected_crc_hex}"

    return message