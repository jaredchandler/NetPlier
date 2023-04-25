def get_true_keyword(protocol_type, message):
    if protocol_type == "dhcp":
        kw = message.data[242:243]
    elif protocol_type == "dnp3":
        kw = message.data[12:13]
    elif protocol_type == "ftp":
        kw = re.split(" |-|\r|\n", message.data.decode())[0]
    elif protocol_type ==  "icmp":
        kw = message.data[0:2]
    elif protocol_type == "modbus":
        kw = message.data[7:8]
    elif protocol_type == "ntp":
        kw = message.data[0] & 0x07
    elif protocol_type == "smb":
        kw = message.data[4+4]
    elif protocol_type == "smb2":
        kw = struct.unpack("<H", message.data[4+12:4+12+2])[0]
    elif protocol_type == "tftp":
        kw = message.data[0:2]
    elif protocol_type == "zeroaccess":
        kw = message.data[4:8]
    else:
        print("The TestName is not given known method for detecting direction.")

    return kw
