import argparse
import socket
import struct
import time
from pathlib import Path


GROUP = "224.0.0.251"
PORT = 5353
HOSTNAME = "az3166-mdns-test.local"
SERVICE = "_http._tcp.local"
TXT = b"path=/hardware-validation"
INSTANCE_NAME = "az3166-mdns-test._http._tcp.local"


def encode_name(name):
    return b"".join(
        bytes([len(part)]) + part.encode("ascii")
        for part in name.split(".")
    ) + b"\0"


def make_query(name, record_type):
    return (
        struct.pack("!HHHHHH", 0, 0, 1, 0, 0, 0)
        + encode_name(name)
        + struct.pack("!HH", record_type, 1)
    )


def open_multicast_socket(local_address):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(("", PORT))
    sock.setsockopt(
        socket.IPPROTO_IP,
        socket.IP_ADD_MEMBERSHIP,
        socket.inet_aton(GROUP) + socket.inet_aton(local_address),
    )
    sock.setsockopt(
        socket.IPPROTO_IP,
        socket.IP_MULTICAST_IF,
        socket.inet_aton(local_address),
    )
    sock.settimeout(0.3)
    return sock


def drain(sock):
    while True:
        try:
            sock.recvfrom(4096)
        except socket.timeout:
            return


def decode_name(packet, offset):
    labels = []
    consumed = 0
    cursor = offset
    jumped = False
    visited = set()
    while True:
        if cursor >= len(packet) or cursor in visited:
            raise ValueError("Invalid or cyclic DNS name")
        visited.add(cursor)
        length = packet[cursor]
        if length & 0xC0 == 0xC0:
            if cursor + 1 >= len(packet):
                raise ValueError("Truncated DNS compression pointer")
            if not jumped:
                consumed += 2
            cursor = ((length & 0x3F) << 8) | packet[cursor + 1]
            jumped = True
            continue
        if length & 0xC0:
            raise ValueError("Invalid DNS label type")
        cursor += 1
        if not jumped:
            consumed += 1
        if length == 0:
            return ".".join(labels).lower(), consumed
        if length > 63 or cursor + length > len(packet):
            raise ValueError("Invalid DNS label length")
        labels.append(packet[cursor:cursor + length].decode("ascii"))
        cursor += length
        if not jumped:
            consumed += length


def parse_message(packet):
    if len(packet) < 12:
        raise ValueError("Truncated DNS header")
    _, flags, question_count, answer_count, authority_count, additional_count = (
        struct.unpack("!HHHHHH", packet[:12])
    )
    offset = 12
    for _ in range(question_count):
        _, consumed = decode_name(packet, offset)
        offset += consumed
        if offset + 4 > len(packet):
            raise ValueError("Truncated DNS question")
        offset += 4

    records = []
    for _ in range(answer_count + authority_count + additional_count):
        owner, consumed = decode_name(packet, offset)
        offset += consumed
        if offset + 10 > len(packet):
            raise ValueError("Truncated DNS record header")
        record_type, record_class, ttl, data_length = struct.unpack(
            "!HHIH", packet[offset:offset + 10]
        )
        offset += 10
        data_offset = offset
        data_end = data_offset + data_length
        if data_end > len(packet):
            raise ValueError("Truncated DNS record data")
        record = {
            "owner": owner,
            "type": record_type,
            "class": record_class,
            "ttl": ttl,
            "data": packet[data_offset:data_end],
        }
        if record_type == 1 and data_length == 4:
            record["address"] = socket.inet_ntoa(record["data"])
        elif record_type == 12:
            record["target"], consumed = decode_name(packet, data_offset)
            if consumed > data_length:
                raise ValueError("PTR target exceeds RDATA")
        elif record_type == 33:
            if data_length < 6:
                raise ValueError("Truncated SRV record")
            _, _, record["port"] = struct.unpack(
                "!HHH", packet[data_offset:data_offset + 6]
            )
            record["target"], consumed = decode_name(packet, data_offset + 6)
            if 6 + consumed > data_length:
                raise ValueError("SRV target exceeds RDATA")
        elif record_type == 16:
            strings = []
            cursor = data_offset
            while cursor < data_end:
                length = packet[cursor]
                cursor += 1
                if cursor + length > data_end:
                    raise ValueError("TXT character-string exceeds RDATA")
                strings.append(packet[cursor:cursor + length])
                cursor += length
            record["strings"] = strings
        records.append(record)
        offset = data_end
    return flags, records


def wait_for_response(sock, board, predicate, timeout=8):
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            data, source = sock.recvfrom(4096)
        except socket.timeout:
            continue
        if source[0] != board or len(data) < 12:
            continue
        try:
            flags, records = parse_message(data)
        except (UnicodeDecodeError, ValueError):
            continue
        if flags & 0x8000 and predicate(records):
            return data, records
    raise RuntimeError("No matching mDNS response was received")


def probe(local_address, board, send_only):
    sock = open_multicast_socket(local_address)
    try:
        drain(sock)
        address_query = make_query(HOSTNAME, 1)
        service_query = make_query(SERVICE, 12)
        query = service_query if send_only else address_query
        for _ in range(3):
            sock.sendto(query, (GROUP, PORT))
            time.sleep(0.15)
        if send_only:
            time.sleep(3)
            return

        address, _ = wait_for_response(
            sock,
            board,
            lambda records: any(
                record["owner"] == HOSTNAME
                and record["type"] == 1
                and record.get("address") == board
                for record in records
            ),
        )
        drain(sock)
        for _ in range(3):
            sock.sendto(service_query, (GROUP, PORT))
            time.sleep(0.15)
        service, records = wait_for_response(
            sock,
            board,
            lambda items: (
                any(
                    item["owner"] == SERVICE
                    and item["type"] == 12
                    and item.get("target") == INSTANCE_NAME
                    for item in items
                )
                and any(
                    item["owner"] == INSTANCE_NAME
                    and item["type"] == 33
                    and item.get("port") == 8080
                    and item.get("target") == HOSTNAME
                    for item in items
                )
                and any(
                    item["owner"] == INSTANCE_NAME
                    and item["type"] == 16
                    and TXT in item.get("strings", [])
                    for item in items
                )
                and any(
                    item["owner"] == HOSTNAME
                    and item["type"] == 1
                    and item.get("address") == board
                    for item in items
                )
            ),
        )
        _, flags, questions, answers, authority, additional = struct.unpack(
            "!HHHHHH", service[:12]
        )
        print(
            "MDNS_DNSSD_HARDWARE_PASS "
            f"address_bytes={len(address)} service_bytes={len(service)} "
            f"flags=0x{flags:04x} questions={questions} answers={answers} "
            f"authority={authority} additional={additional}"
        )
    finally:
        sock.close()


def iter_pcapng_data(data):
    offset = 0
    byte_order = "<"
    while offset + 12 <= len(data):
        raw_type = data[offset:offset + 4]
        if raw_type == b"\x0a\x0d\x0d\x0a":
            magic = data[offset + 8:offset + 12]
            if magic == b"\x1a\x2b\x3c\x4d":
                byte_order = ">"
            elif magic == b"\x4d\x3c\x2b\x1a":
                byte_order = "<"
            else:
                raise RuntimeError("Invalid PCAPNG byte-order magic")
            block_type = 0x0A0D0D0A
        else:
            block_type = struct.unpack_from(byte_order + "I", data, offset)[0]
        block_length = struct.unpack_from(byte_order + "I", data, offset + 4)[0]
        if block_length < 12 or offset + block_length > len(data):
            raise RuntimeError("Invalid PCAPNG block length")
        trailing_length = struct.unpack_from(
            byte_order + "I", data, offset + block_length - 4
        )[0]
        if trailing_length != block_length:
            raise RuntimeError("Mismatched PCAPNG block lengths")
        if block_type == 0x0A0D0D0A:
            pass
        elif block_type == 6 and block_length >= 32:
            captured_length = struct.unpack_from(
                byte_order + "I", data, offset + 20
            )[0]
            packet_start = offset + 28
            yield data[packet_start:packet_start + captured_length]
        offset += block_length


def iter_pcapng_packets(path):
    yield from iter_pcapng_data(Path(path).read_bytes())


def verify_ttl(path, board):
    matches = []
    board_bytes = socket.inet_aton(board)
    for frame in iter_pcapng_packets(path):
        if len(frame) < 42 or frame[12:14] != b"\x08\x00":
            continue
        ip_offset = 14
        header_length = (frame[ip_offset] & 0x0F) * 4
        if header_length < 20 or len(frame) < ip_offset + header_length + 8:
            continue
        if frame[ip_offset + 9] != socket.IPPROTO_UDP:
            continue
        if frame[ip_offset + 12:ip_offset + 16] != board_bytes:
            continue
        udp_offset = ip_offset + header_length
        source_port = struct.unpack("!H", frame[udp_offset:udp_offset + 2])[0]
        if source_port == PORT:
            matches.append(frame[ip_offset + 8])
    if not matches:
        raise RuntimeError("No board mDNS responses were found in the capture")
    if any(ttl != 255 for ttl in matches):
        raise RuntimeError(f"Board mDNS TTL values were not all 255: {matches}")
    print(f"MDNS_TTL_255_HARDWARE_PASS packets={len(matches)}")


def make_record(owner, record_type, data):
    return (
        encode_name(owner)
        + struct.pack("!HHIH", record_type, 1, 120, len(data))
        + data
    )


def self_test():
    board = "192.0.2.10"
    service_data = (
        make_record(SERVICE, 12, encode_name(INSTANCE_NAME))
        + make_record(
            INSTANCE_NAME,
            33,
            struct.pack("!HHH", 0, 0, 8080) + encode_name(HOSTNAME),
        )
        + make_record(INSTANCE_NAME, 16, bytes([len(TXT)]) + TXT)
        + make_record(HOSTNAME, 1, socket.inet_aton(board))
    )
    packet = struct.pack("!HHHHHH", 0, 0x8400, 0, 4, 0, 0) + service_data
    flags, records = parse_message(packet)
    if flags != 0x8400 or len(records) != 4:
        raise RuntimeError("DNS parser self-test header mismatch")
    if not any(
        item["owner"] == SERVICE
        and item["type"] == 12
        and item.get("target") == INSTANCE_NAME
        for item in records
    ):
        raise RuntimeError("DNS parser self-test PTR mismatch")
    if not any(
        item["owner"] == INSTANCE_NAME
        and item["type"] == 33
        and item.get("port") == 8080
        and item.get("target") == HOSTNAME
        for item in records
    ):
        raise RuntimeError("DNS parser self-test SRV mismatch")
    if not any(
        item["owner"] == INSTANCE_NAME
        and item["type"] == 16
        and TXT in item.get("strings", [])
        for item in records
    ):
        raise RuntimeError("DNS parser self-test TXT mismatch")
    if not any(
        item["owner"] == HOSTNAME
        and item["type"] == 1
        and item.get("address") == board
        for item in records
    ):
        raise RuntimeError("DNS parser self-test A mismatch")

    payload = b"abc"
    padding = b"\0"
    for byte_order, magic in (("<", b"\x4d\x3c\x2b\x1a"), (">", b"\x1a\x2b\x3c\x4d")):
        section_length = 28
        section = (
            b"\x0a\x0d\x0d\x0a"
            + struct.pack(byte_order + "I", section_length)
            + magic
            + struct.pack(byte_order + "HHqI", 1, 0, -1, section_length)
        )
        packet_length = 36
        packet = (
            struct.pack(
                byte_order + "IIIIIII",
                6, packet_length, 0, 0, 0, len(payload), len(payload),
            )
            + payload
            + padding
            + struct.pack(byte_order + "I", packet_length)
        )
        if list(iter_pcapng_data(section + packet)) != [payload]:
            raise RuntimeError(
                f"PCAPNG parser self-test failed for byte order {byte_order}"
            )
    print("MDNS_PROBE_SELF_TEST_PASS")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--local")
    parser.add_argument("--board")
    parser.add_argument("--send-only", action="store_true")
    parser.add_argument("--pcap")
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    if args.self_test:
        self_test()
    elif args.pcap and args.board:
        verify_ttl(args.pcap, args.board)
    elif args.local and args.board:
        probe(args.local, args.board, args.send_only)
    else:
        parser.error(
            "--board plus --local or --pcap is required unless --self-test is used"
        )


if __name__ == "__main__":
    main()
