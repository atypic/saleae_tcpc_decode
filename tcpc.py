# High Level Analyzer
# For more information and documentation, please go to https://support.saleae.com/extensions/high-level-analyzer-extensions

from saleae.analyzers import HighLevelAnalyzer, AnalyzerFrame, StringSetting, NumberSetting, ChoicesSetting

class bcolors:
    OKBLUE = '\033[94m'
    PINK = '\033[95m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'


filter_ports = ['PORT 2']

extra_decode_regs = ["FAULT_STATUS", 
                     "ALERT", 
                     "READABLE_BYTE_COUNT", 
                     "I2C_WRITE_BYTE_COUNT",
                     "POWER_STATUS",
                     "CC_STATUS",
                     "ROLE_CONTROL",
                     "POWER_CONTROL",
                     "TCPC_CONTROL",
                     "EXT_GPIO_CONFIG",
                     "EXT_GPIO_CONTROL",
                     "COMMAND"
                     ]

#0 is highest level, prints all.
#1 does not print raw transactions.
def print_filtered(message, verbosity=0):
    if verbosity == 0:
        print(message)

dhaul_addrs = {
    0x50: "PORT 1",
    0x51: "PORT 2"
}


def iterate_bits(byte):
    for i in range(8):
        bit = (byte >> i) & 1
        print(f"Bit {i}: {bit}")


def parse_out_bits(bit_field: int, start_index: int, end_index: int) -> int:
    mask = (1 << (end_index - start_index + 1)) - 1
    return (bit_field >> start_index) & mask


ptn5110_vals = {
    0x1F: [
        "VCON overcurrent",
        "VCON over voltage",
        "Over current protection",
        "Force discharge failed",
        "Auto discharge failed",
        "Force off VBUS",
        "All registers reset",
        "No meaning"
    ]
}


def role_control_cc_decode(bits):
    if bits == 0b00:
        return "Ra"
    elif bits == 0b01:
        return "Rp"
    elif bits == 0b10:
        return "Rd"
    elif bits == 0b11:
        return "(open) Enabling DRP"


def role_control_rp_value(bits):
    if bits == 0b00:
        return "Rp default"
    elif bits == 0b01:
        return "Rp 1.5A"
    elif bits == 0b10:
        return "Rp 3.0A"
    elif bits == 0b11:
        return "Reserved"


def print_role_control(byte, color):
    print(f"{color}ROLE CONTROL:")
    print(f"{color}    CC1: {role_control_cc_decode(parse_out_bits(byte, 0, 1))}")
    print(f"{color}    CC2: {role_control_cc_decode(parse_out_bits(byte, 2, 3))}")
    print(f"{color}    RPVAL: {role_control_rp_value(parse_out_bits(byte, 4, 5))}")
    print(f"{color}    DRP enabled: {parse_out_bits(byte, 6, 6)}")

def print_tcpc_control(byte, color):
    print(f"{color}TCPC Control Message")
    print(f"{color}    Plug orientation:     {parse_out_bits(byte, 0, 0)}")
    print(f"{color}    BIST Test mode:       {parse_out_bits(byte, 1, 1)}")
    print(f"{color}    I2C Clock stretching: {parse_out_bits(byte, 2, 3)}")
    print(f"{color}    Debug acc control:    {parse_out_bits(byte, 4, 4)}")
    print(f"{color}    Enable WDOG timer:    {parse_out_bits(byte, 5, 5)}")
    print(f"{color}    Enable L4C Alert:     {parse_out_bits(byte, 6, 6)}")
    print(f"{color}    Enable SMBus PEC:     {parse_out_bits(byte, 7, 7)}")

def print_power_control(byte, color):
    print(f"{color}Power Control Message")
    print(f"{color}    Enable VCONN:          {parse_out_bits(byte, 0, 0)}")
    print(f"{color}    VCONN Pow support:     {parse_out_bits(byte, 1, 1)}")
    print(f"{color}    Force discharge:       {parse_out_bits(byte, 2, 3)}")
    print(f"{color}    Enable bleed discharge:{parse_out_bits(byte, 4, 4)}")
    print(f"{color}    AutoChargeDisconnect:  {parse_out_bits(byte, 5, 5)}")
    print(f"{color}    VBUS Voltage monitor:  {parse_out_bits(byte, 6, 6)}")
    print(f"{color}    Fast role swap enable: {parse_out_bits(byte, 7, 7)}")

def print_ext_gpio_config(byte, color):
    print(f"{color}EXT_GPIO_CONFIG")
    print(f"{color}    Input_current_lim_5V_BUS:    {parse_out_bits(byte, 3,3)}")
    print(f"{color}    EN_SNK1:                     {parse_out_bits(byte, 4,4)}")
    print(f"{color}    EN_SRC:                      {parse_out_bits(byte, 5,5)}")
    print(f"{color}    FRS_EN:                      {parse_out_bits(byte, 6,6)}")

def print_ext_gpio_control(byte, color):
    print(f"{color}EXT_CPIO_CONTROL")
    print(f"{color}    Drive ILIM_5V_VBUS:          {parse_out_bits(byte, 3,3)}")
    print(f"{color}    Drive EN_SNK1:               {parse_out_bits(byte, 4,4)}")
    print(f"{color}    Drive EN_SRC:                {parse_out_bits(byte, 5,5)}")
    print(f"{color}    Drive FRS_EN:                {parse_out_bits(byte, 6,6)}")

def sop_ctrl_msg_type(bits):
    msg = {
        0b00000: "Reserved",
        0b00001: "GoodCRC",
        0b00010: "GotoMin",
        0b00011: "Accept",
        0b00100: "Reject",
        0b00101: "PingSource",
        0b00110: "PS_RDY",
        0b00111: "Get_Source_Cap",
        0b01000: "Get_Sink_Cap",
        0b01001: "DR_Swap",
        0b01010: "PR_Swap",
        0b01011: "VCONN_Swap",
        0b01100: "WaitSource",
        0b01101: "Soft_Reset",
        0b01111: "Data_Reset_Complete",
        0b10000: "Not_Supported",
        0b10010: "Get_Status",
        0b10100: "Get_PPS_Status",
        0b10101: "Get_Country_Codes",
        0b10110: "Get_Sink_Cap_Extended",
        0b10111: "Get_Source_InfoSink",
        0b11000: "Get_Revision"
    }
    if bits in msg.keys():
        return msg[bits]
    else:
      return f"Unknown control: {bits}"

def sop_data_msg_type(bits):
    msg = {
        0b00000: "Reserved",
        0b00001: "Source Capabilities",
        0b00010: "Request (sinking port is requesting power)",
        0b00011: "BIST",
        0b00100: "Sink Capabilities",
        0b00101: "Battery Status",
        0b00110: "Alert",
        0b00111: "Get Country Info",
        0b01000: "Enter_USB",
        0b01001: "EPR_Request",
        0b01010: "EPR_Mode",
        0b01011: "Source_info",
        0b01100: "Revision",
        0b01111: "Vendor Defined"
    }
    if bits in msg.keys():
        return msg[bits]
    else:
        return f"Reserved/Unknown data msg: {bits}"

# seems like SOP messages are LSB first.
def print_sop_message(bytes, color):
    #LSB first
    message_type = parse_out_bits(bytes[0], 0, 4)
    port_data_role = parse_out_bits(bytes[0], 5, 5)
    revision = parse_out_bits(bytes[0],6,7)
    #bits 15...8 is in byte 1.
    port_power_role = parse_out_bits(bytes[1], 0, 0)  # first bit of byte.
    message_id = parse_out_bits(bytes[1], 1, 3)
    num_do = parse_out_bits(bytes[1], 4, 6)
    extended = parse_out_bits(bytes[1], 7, 7)
    
    if port_power_role == 0:
        pr = 'Sink (eats power)'
    else:
        pr = 'Source (provides power)'
    if port_data_role == 0:
        dr = 'UFP (DEVICE)'
    else:
        dr = 'DFP (HOST)'
 
    if num_do == 0:
        print(f"{color}    CONTROL Message Type: {sop_ctrl_msg_type(message_type)}")
    else:
        print(f"{color}    DATA Message Type: {sop_data_msg_type(message_type)}")
        
    print(f"{color}    Power Role: {pr}")
    print(f"{color}    Data Role: {dr}") 
    print(f"{color}    Revision: {revision}")
    print(f"{color}    Data objects: {num_do}")
    print(f"{color}    Message ID: {message_id}")

def print_alert(byte, color):
    bitfields = [
        "CC Status Alert",
        "Port Power Status",
        "Received SOP* Message status",
        "Received Hard Reset",
        "Transmit SOP Message failed",
        "Transmit SOP Message discarded",
        "Transmit SOP Message successfull",
        "VBUS Voltage Alarm Hi",
        "VBUS Voltage Alarm Lo",
        "Fault",
        "Rx_Buffer_Overflow",
        "VBUS Sink Disconnect Detected",
        "Begnning SOP Message Status",
        "Extended status",
        "Alert Extended",
        "Vendor Defined Extended"]
    print(f"{color}ALERT")
    for i in range(8):
        bit = (byte[0] >> i) & 1
        print(f"    {color}{i}: {bit} - {bitfields[i]}")
    for i in range(8):
        bit = (byte[1] >> i) & 1
        print(f"    {color}{i}: {bit} - {bitfields[i + 8]}")



def print_power_status(byte, color):
    bitfields = [
        "Sinking VBUS",
        "VCONN Present",
        "VBUS Present",
        "VBUS Detection Enabled",
        "Sourcing VBUS",
        "Sourcing High Voltage",
        "TCPC Init Status",
        "Debug Accessory Connected",
    ]
    print("\n")
    print(f"{color}POWER STATUS REPORT:")
    for i in range(8):
        bit = (byte >> i) & 1
        print(f"    {color} {i}: {bit} - {bitfields[i]}")
    print('\n')


def cc_state_bits(bits):
    if bits == 0b00:
        return "SNK_OPEN"
    elif bits == 0b01:
        return "SNK_Default"
    elif bits == 0b10:
        return "SNK_Power_1_5"
    elif bits == 0b11:
        return "SNK_POWER_3_0"


def print_cc_status(byte, color):
    print(f"{color}CC STATUS REPORT:")
    print(f"{color}    CC1: {cc_state_bits(parse_out_bits(byte, 0, 1))}")
    print(f"{color}    CC2: {cc_state_bits(parse_out_bits(byte, 2, 3))}")
    print(f"{color}    ConnectResult: {parse_out_bits(byte, 4, 4)}")
    print(f"{color}    Looking4Conn : {parse_out_bits(byte, 5, 5)}")

def print_command(byte, color):
    print(f"{color}COMMAND")
    if   byte == 0b00010001: print(f"{color}  WakeI2C")
    elif byte == 0b00100010: print(f"{color}  DisableVBUSDetect")
    elif byte == 0b00110011: print(f"{color}  EnableVBUSDetect")
    elif byte == 0b01000100: print(f"{color}  DisableSinkVBUS")
    elif byte == 0b01010101: print(f"{color}  SinkVBUS")
    elif byte == 0b01100110: print(f"{color}  DisableSourceVBUS")
    elif byte == 0b01110111: print(f"{color}  SourceVBUSDefaultVoltage")
    elif byte == 0b10001000: print(f"{color}  SourceVBUSHighVoltage")
    elif byte == 0b10011001: print(f"{color}  Look4Connection")
    elif byte == 0b10101010: print(f"{color}  RxOneMore")
    elif byte == 0b11001100: print(f"{color}  SendFRSwapSignal")
    elif byte == 0b11011101: print(f"{color}  ResetTransmitBuffer")
    elif byte == 0b11101110: print(f"{color}  ResetReceiveBuffer")
    elif byte == 0b11111111: print(f"{color}  I2CIdle")


def decode_vbus_voltage(bytes):
    bits_0_9 = (bytes[0] & 0xFF) | ((bytes[1] & 0x3) << 8)
    bits_10_11 = (bytes[1] >> 2) & 0x3

    if bits_10_11 == 2:
        scale_factor = 4
    elif bits_10_11 == 1:
        scale_factor = 2
    else:
        scale_factor = 1

    result = (bits_0_9 * (25/1000.)) * (scale_factor)
    return result

def print_fault_status(byte, color):
    print(f"{color}FAULT STATUS:")
    print(f"{color}   I2C Interface error: {parse_out_bits(byte, 0, 0)}")
    print(f"{color}    VCON over current fault: {parse_out_bits(byte, 1, 1)}")
    print(f"{color}    Internal or External VBUS Over Voltage Protection Fault: {parse_out_bits(byte, 2, 2)}")
    print(f"{color}    Internal or External VBUS Over Current Protection Fault: {parse_out_bits(byte, 3, 3)}")
    print(f"{color}    Force Discharge Failed: {parse_out_bits(byte, 4, 4)}")
    print(f"{color}    Auto Discharge Failed: {parse_out_bits(byte, 5, 5)}")
    print(f"{color}    Force off VBUS Status: {parse_out_bits(byte, 6, 6)}")
    print(f"{color}    All registers reset to default: {parse_out_bits(byte, 7, 7)}")

def print_transaction(time, port, reg, data, isread, write_raw):
    if port in filter_ports:
        if write_raw and isread:
            print(f"{time} : {port} READ @ {reg_to_name(reg)}: {data}")
        elif write_raw and not isread:
            print(f"{time} : {port} WRITE @ {reg_to_name(reg)}: {data}")
        
        if not (reg in ptn5110_regs.keys()):  
            print("Wops, unknown register")
            return 
        
        if ptn5110_regs[reg] in extra_decode_regs:
            if ptn5110_regs[reg] == "FAULT_STATUS":
                print_fault_status(data[0], bcolors.FAIL)
            elif ptn5110_regs[reg] == "ALERT":
                print_alert(data, bcolors.WARNING)
            elif ptn5110_regs[reg] == "READABLE_BYTE_COUNT":
                print_sop_message(data[2:], bcolors.OKCYAN)
            elif ptn5110_regs[reg] == "I2C_WRITE_BYTE_COUNT":
                print_sop_message(data[1:], bcolors.OKGREEN)
            elif ptn5110_regs[reg] == "POWER_STATUS":
                print_power_status(data[0], bcolors.PINK)
            elif ptn5110_regs[reg] == "CC_STATUS":
                print_cc_status(data[0], bcolors.PINK)
            elif ptn5110_regs[reg] == "ROLE_CONTROL":
                print_role_control(data[0], bcolors.OKCYAN)
            elif ptn5110_regs[reg] == "POWER_CONTROL":
                print_power_control(data[0], bcolors.OKCYAN)
            elif ptn5110_regs[reg] == "TCPC_CONTROL":
                print_tcpc_control(data[0], bcolors.OKCYAN)
            elif ptn5110_regs[reg] == "EXT_GPIO_CONFIG":
                print_ext_gpio_config(data[0], bcolors.OKCYAN)
            elif ptn5110_regs[reg] == "EXT_GPIO_CONTROL":
                print_ext_gpio_control(data[0], bcolors.OKCYAN)
            elif ptn5110_regs[reg] == "COMMAND":
                print_command(data[0], bcolors.FAIL)





ptn5110_regs = {
    0x00: "VENDOR_ID",
    0x02: "PRODUCT_ID",
    0x04: "DEVICE_ID",
    0x05: "DEVICE_ID_BYTE_2",
    0x06: "USBTYPEC_REV",
    0x08: "USBPD_REV_VER",
    0x0A: "PD_INTERFACE_REV",
    0x10: "ALERT",
    0x12: "ALERT_MASK",
    0x14: "POWER_STATUS_MASK",
    0x15: "FAULT_STATUS_MASK",
    0x16: "EXTENDED_STATUS_MASK",
    0x17: "ALERT_EXTENDED_MASK",
    0x18: "CONFIGURE_STANDARD_OUTPUT",
    0x19: "TCPC_CONTROL",
    0x1A: "ROLE_CONTROL",
    0x1B: "FAULT_CONTROL",
    0x1C: "POWER_CONTROL",
    0x1D: "CC_STATUS",
    0x1E: "POWER_STATUS",
    0x1F: "FAULT_STATUS",
    0x20: "EXTENDED_STATUS",
    0x21: "ALERT_EXTENDED",
    0x23: "COMMAND",
    0x24: "DEVICE_CAPABILITIES_1",
    0x26: "DEVICE_CAPABILITIES_2",
    0x28: "STANDARD_INPUT_CAPABILITIES",
    0x2A: "CONFIGURE_EXTENDED",
    0x2C: "GENERIC_TIMER",
    0x2E: "MESSAGE_HEADER_INFO",
    0x2F: "RECEIVE_DETECT",
    0x30: "READABLE_BYTE_COUNT",
    0x50: "TRANSMIT",
    0x51: "I2C_WRITE_BYTE_COUNT",
    0x70: "VBUS_VOLTAGE",
    0x72: "VBUS_SINK_DISCONNECT_THRESHOLD",
    0x74: "VBUS_STOP_DISCHARGE_THRESHOLD",
    0x76: "VBUS_VOLTAGE_ALARM_HI_CFG",
    0x78: "VBUS_VOLTAGE_ALARM_LO_CFG",
    0x7A: "VBUS_HV_TARGET",
    0x80: "EXT_CFG_ID",
    0x82: "EXT_ALERT",
    0x86: "EXT_CONFIG",
    0x84: "EXT_ALERT_MASK",
    0x88: "EXT_FAULT_CONFIG",
    0x8a: "Reserved",
    0x8e: "EXT_CONTROL",
    0x8f: "Reserved",
    0x90: "EXT_STATUS",
    0x92: "EXT_GPIO_CONFIG",
    0x93: "EXT_GPIO_CONTROL",
    0x96: "EXT_GPIO_STATUS",
    0x97: "SOURCE_HIGH_VOLTAGE_MB4B",
    0x98: "Reserved",
    0x99: "Reserved",
    0x9A: "ADC_FILTER_CONTROL_1",
    0x9B: "ADC_FILTER_CONTROL_2",
    0x9C: "VCONN_CONFIG",
    0x9D: "VCONN_FAULT_DEBOUNCE",
    0x9E: "VCONN_FAULT_RECOVERY",
    0x9F: "VCONN_FAULT_ATTEMPTS"
}


def reg_to_name(reg):
    if reg in ptn5110_regs.keys():
        return ptn5110_regs[reg]
    else:
        return f"Unknown register {hex(reg)}"

# High level analyzers must subclass the HighLevelAnalyzer class.


class TCPC(HighLevelAnalyzer):
    # List of settings that a user can set for this High Level Analyzer.
    #my_string_setting = StringSetting()
    #my_number_setting = NumberSetting(min_value=0, max_value=100)
    #my_choices_setting = ChoicesSetting(choices=('A', 'B'))

    # An optional list of types this analyzer produces, providing a way to customize the way frames are displayed in Logic 2.
    result_types = {
        'framestart': {
            'format': 'Transaction start'
        },
        'framestop': {
            'format': 'Transaction stop'
        },
        'addr': {
            'format': '{{data.tcpc_byte}}'
        },
        'read_reg': {
            'format': 'RDA: {{data.tcpc_byte}}'
        },
        'write_val': {
            'format': 'WR: {{data.tcpc_byte}}'
        },
        'read_val': {
            'format': 'RD: {{data.tcpc_byte}}'
        },
        'write_reg': {
            'format': 'WRA: {{data.tcpc_byte}}'
        },
    }

    def __init__(self):
        '''
        Initialize HLA.

        Settings can be accessed using the same name used above.
        '''
        self._analysis_start_time = None
        self._current_trans_num_bytes = 0
        self._current_frame_data_bytes = 0
        self._current_regaddr = 0
        self._isread = False
        self._current_relative_time_s = 0

        #print("Settings:", self.my_string_setting,
        #      self.my_number_setting, self.my_choices_setting)

    def decode(self, frame: AnalyzerFrame):
        '''
        Process a frame from the input analyzer, and optionally return a single `AnalyzerFrame` or a list of `AnalyzerFrame`s.

        The type and data values in `frame` will depend on the input analyzer.
        '''

        databyte = 0
        typeof = "framestart"
        byteshow = ""

        if frame.type == 'start':
            self._current_trans_num_bytes = 0
            self._current_frame_data_bytes = []
            if self._analysis_start_time == None:
                self._analysis_start_time = frame.start_time
            #First measurement to set the start time

        # This can either be a register offset byte or a data byte (for a read)
        if frame.type == 'data':
            self._current_trans_num_bytes += 1
            databyte = frame.data['data'][0]

            # The isread flag is set for a data byte, so we collect it no matter what.
            if self._isread:
                typeof = 'read_val'
                self._current_frame_data_bytes.append(databyte)
                byteshow = hex(databyte)
                
                print_filtered(
                    f"  READ @ {reg_to_name(self._current_regaddr)}: {byteshow}", verbosity=1)
            else:
                # Second byte in a write transaction is always register offset
                typeof = 'write_reg'
                if self._current_trans_num_bytes == 2:
                    byteshow = reg_to_name(databyte)
                    self._current_regaddr = databyte
                else:
                    # This is the written byte value.
                    byteshow = f"{hex(databyte)}"
                    self._current_frame_data_bytes.append(databyte)
                    print_filtered(
                        f"  WRITE @ {reg_to_name(self._current_regaddr)}: {byteshow}", verbosity=1)

        # Address type. 
        if frame.type == 'address':
            self._current_trans_num_bytes = 1
            self._isread = frame.data['read']

            databyte = frame.data['address'][0]
            typeof = 'addr'
            if databyte in dhaul_addrs.keys():
                byteshow = f"{dhaul_addrs[databyte]}"
                self._current_port  = byteshow
            else:
                byteshow = f"Unk port: {hex(databyte)}"
#            if not self._isread:
#                print(f"Transaction started @ {byteshow}")

        if frame.type == 'stop':
            relative_time = float(frame.start_time - self._analysis_start_time)
            typeof = 'framestop'
            print_transaction(relative_time, self._current_port, self._current_regaddr, self._current_frame_data_bytes, self._isread, True)
            
            self._isread = False
            self._current_trans_num_bytes = 0
            self._current_frame_data_bytes = []

        # Return the data frame itself
        return AnalyzerFrame(typeof, frame.start_time, frame.end_time, {
            'tcpc_byte': byteshow
        })
