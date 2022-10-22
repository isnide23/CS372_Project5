# read in a txt file
# split the source and destination address
# convert ip data into a bytes
from tabnanny import check

def convert_to_byte_stream(addr):
    buffer = b''
    for x in addr:
        x = int(x).to_bytes(1, "big")
        buffer+= x
        # print(x)
    return buffer

def checksum(data):
    offset = 0   # byte offset into data
    total = 0

    while offset < len(data):
        # Slice 2 bytes out and get their value:

        word = int.from_bytes(data[offset:offset + 2], "big")
        total += word
        total = (total & 0xffff) + (total >> 16)  # carry around

        offset += 2   # Go to the next 2-byte value
    return (~total) & 0xffff  # one's complement

def comp_checksum(total_1, total_2):
    if total_1 == total_2:
        print('PASS')
        # print(total_1)
        # print(total_2)
    else:
        print('FAIL')
        # print(total_1)
        # print(total_2)

for i in range(0, 10): 
    f = open(f"tcp_addrs_{i}.txt", "r")
    ip_data = f.readline()
    source, dest = ip_data.split()

    source = source.split('.')
    dest = dest.split('.')
    # print("source")
    # print(source)
    # print("dest")
    # print(dest)

    source_bytes = convert_to_byte_stream(source)
    dest_bytes = convert_to_byte_stream(dest)
    f.close()

    # get tcp data length

    with open(f"tcp_data_{i}.dat", "rb") as fp:
        tcp_data = fp.read()
        tcp_length = len(tcp_data)

    tcp_length_bytes = tcp_length.to_bytes(2, "big")

    # build pseudo header

    pseudo_header = source_bytes + dest_bytes + b'\x00' + b'\x06' + tcp_length_bytes
    # print(pseudo_header.hex())

    # Build a new version of the TCP data that has the checksum set to zero.

    # print("----tcp data checksum----")
    # print(hex(int.from_bytes(tcp_data[16:18], "big")))
    tcp_zero_cksum = tcp_data[:16] + b'\x00\x00' + tcp_data[18:]

    if len(tcp_zero_cksum) % 2 == 1:
        tcp_zero_cksum += b'\x00'

    data = pseudo_header + tcp_zero_cksum

    # print(hex(checksum(data)))

    comp_checksum(hex(int.from_bytes(tcp_data[16:18], "big")), hex(checksum(data)) )
