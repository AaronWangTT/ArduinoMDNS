import contextlib
import io
import socket
import struct
import tempfile
import unittest
from pathlib import Path

import mdns_probe


def pcapng(frame, byte_order="<"):
    magic = b"\x4d\x3c\x2b\x1a" if byte_order == "<" else b"\x1a\x2b\x3c\x4d"
    section = (
        b"\x0a\x0d\x0d\x0a"
        + struct.pack(byte_order + "I", 28)
        + magic
        + struct.pack(byte_order + "HHqI", 1, 0, -1, 28)
    )
    interface = struct.pack(byte_order + "IIHHII", 1, 20, 1, 0, 65535, 20)
    padding = b"\0" * (-len(frame) % 4)
    length = 32 + len(frame) + len(padding)
    packet = (
        struct.pack(byte_order + "IIIIIII", 6, length, 0, 0, 0, len(frame), len(frame))
        + frame
        + padding
        + struct.pack(byte_order + "I", length)
    )
    return section + interface + packet


def udp_frame(ttl=255, source="192.0.2.10", source_port=5353,
              destination_port=5353, payload=None):
    if payload is None:
        payload = (
            struct.pack("!HHHHHH", 0, 0x8400, 0, 1, 0, 0)
            + mdns_probe.make_record(mdns_probe.HOSTNAME, 1, socket.inet_aton(source))
        )
    return (
        b"\0" * 12
        + b"\x08\x00"
        + struct.pack(
            "!BBHHHBBH4s4s",
            0x45, 0, 28 + len(payload), 0, 0, ttl, socket.IPPROTO_UDP, 0,
            socket.inet_aton(source), socket.inet_aton(mdns_probe.GROUP),
        )
        + struct.pack("!HHHH", source_port, destination_port, 8 + len(payload), 0)
        + payload
    )


class ProbeTests(unittest.TestCase):
    def test_original_self_test(self):
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            mdns_probe.self_test()
        self.assertIn("MDNS_PROBE_SELF_TEST_PASS", output.getvalue())

    def test_query_shape(self):
        packet = mdns_probe.make_query(mdns_probe.HOSTNAME, 1)
        self.assertEqual(struct.unpack("!HHHHHH", packet[:12]), (0, 0, 1, 0, 0, 0))
        name, consumed = mdns_probe.decode_name(packet, 12)
        self.assertEqual(name, mdns_probe.HOSTNAME)
        self.assertEqual(packet[12 + consumed:], b"\0\x01\0\x01")

    def test_compression_preserves_original_consumption(self):
        name = mdns_probe.encode_name("device.local")
        self.assertEqual(
            mdns_probe.decode_name(name + b"\xc0\0", len(name)),
            ("device.local", 2),
        )

    def test_bad_names_rejected(self):
        for packet in (b"\xc0\0", b"\xc0", b"\xc0\xff", b"\x03ab", b"\x40",
                       b"\xc0\x02\x01a\0"):
            with self.subTest(packet=packet), self.assertRaises(ValueError):
                mdns_probe.decode_name(packet, 0)

    def test_expanded_name_limit(self):
        valid = ".".join(["a" * 63] * 3 + ["b" * 61])
        packet = mdns_probe.encode_name(valid)
        self.assertEqual(len(packet), 255)
        self.assertEqual(mdns_probe.decode_name(packet, 0), (valid, 255))
        with self.assertRaises(ValueError):
            mdns_probe.decode_name(mdns_probe.encode_name(valid + "b"), 0)

    def test_truncated_messages_rejected(self):
        for length in range(12):
            with self.subTest(length=length), self.assertRaises(ValueError):
                mdns_probe.parse_message(b"\0" * length)
        header = struct.pack("!HHHHHH", 0, 0x8400, 0, 1, 0, 0)
        record = mdns_probe.make_record(mdns_probe.HOSTNAME, 1, b"\xc0\0\x02\x0a")
        with self.assertRaises(ValueError):
            mdns_probe.parse_message(header + record[:-1])

    def test_truncated_txt_segment_rejected(self):
        header = struct.pack("!HHHHHH", 0, 0x8400, 0, 1, 0, 0)
        record = mdns_probe.make_record(mdns_probe.INSTANCE_NAME, 16, b"\x05abc")
        with self.assertRaises(ValueError):
            mdns_probe.parse_message(header + record)

    def test_pcapng_byte_orders(self):
        frame = udp_frame()
        for order in ("<", ">"):
            with self.subTest(order=order):
                self.assertEqual(list(mdns_probe.iter_pcapng_data(pcapng(frame, order))), [frame])

    def test_mismatched_pcapng_lengths_rejected(self):
        capture = bytearray(pcapng(udp_frame()))
        capture[-4:] = b"\0" * 4
        with self.assertRaises(RuntimeError):
            list(mdns_probe.iter_pcapng_data(capture))

    def test_capture_length_cannot_escape_packet_block(self):
        frame = udp_frame()
        capture = bytearray(pcapng(frame))
        struct.pack_into("<I", capture, 28 + 20 + 20, len(frame) + 16)
        with self.assertRaises(RuntimeError):
            list(mdns_probe.iter_pcapng_data(capture + pcapng(frame)))

    def test_invalid_packet_and_capture_tails_rejected(self):
        capture = pcapng(udp_frame())
        for malformed in (capture + b"x", capture[:48] + struct.pack("<III", 6, 12, 12)):
            with self.subTest(capture=malformed), self.assertRaises(RuntimeError):
                list(mdns_probe.iter_pcapng_data(malformed))

    def test_packet_interface_metadata_is_required(self):
        original = pcapng(udp_frame())
        cases = [(36, "H", 101), (56, "I", 1), (40, "I", 10)]
        for offset, format_code, value in cases:
            capture = bytearray(original)
            struct.pack_into("<" + format_code, capture, offset, value)
            with self.subTest(offset=offset), self.assertRaises(RuntimeError):
                list(mdns_probe.iter_pcapng_data(capture))
        with self.assertRaises(RuntimeError):
            list(mdns_probe.iter_pcapng_data(original[48:]))

    def test_invalid_rr_shapes_and_dns_tails_rejected(self):
        header = struct.pack("!HHHHHH", 0, 0x8400, 0, 1, 0, 0)
        records = (
            mdns_probe.make_record(mdns_probe.HOSTNAME, 1, b"\x01\x02\x03"),
            mdns_probe.make_record(mdns_probe.SERVICE, 12,
                                   mdns_probe.encode_name(mdns_probe.INSTANCE_NAME) + b"\0"),
            mdns_probe.make_record(mdns_probe.INSTANCE_NAME, 33,
                                   struct.pack("!HHH", 0, 0, 8080)
                                   + mdns_probe.encode_name(mdns_probe.HOSTNAME) + b"\0"),
            mdns_probe.make_record(mdns_probe.HOSTNAME, 1, b"\xc0\0\x02\x0a") + b"x",
        )
        for record in records:
            with self.subTest(record=record), self.assertRaises(ValueError):
                mdns_probe.parse_message(header + record)

    def test_live_response_requires_mdns_source_port(self):
        good = (
            struct.pack("!HHHHHH", 0, 0x8400, 0, 1, 0, 0)
            + mdns_probe.make_record(mdns_probe.HOSTNAME, 1, b"\xc0\0\x02\x0a")
        )
        bad = b"\x01" + good[1:]

        class Packets:
            def __init__(self):
                self.packets = [(bad, ("192.0.2.10", 9999)), (good, ("192.0.2.10", 5353))]

            def recvfrom(self, size):
                return self.packets.pop(0)

        packet, _ = mdns_probe.wait_for_response(Packets(), "192.0.2.10", lambda records: True)
        self.assertEqual(packet, good)

    def test_ttl_requires_complete_dns_responses(self):
        query = mdns_probe.make_query(mdns_probe.HOSTNAME, 1)
        frames = [
            udp_frame(payload=query),
            udp_frame(payload=b""),
            udp_frame(payload=struct.pack("!HHHHHH", 0, 0x8400, 0, 0, 0, 0)),
            udp_frame(destination_port=9999),
            udp_frame()[:-1],
        ]
        for offset, value in ((16, 65535), (38, 8), (38, 65535), (20, 0x2000)):
            frame = bytearray(udp_frame())
            struct.pack_into("!H", frame, offset, value)
            frames.append(frame)
        with tempfile.TemporaryDirectory() as directory:
            capture = Path(directory) / "synthetic.pcapng"
            for frame in frames:
                with self.subTest(frame=frame):
                    capture.write_bytes(pcapng(frame))
                    with self.assertRaises(RuntimeError), contextlib.redirect_stdout(io.StringIO()):
                        mdns_probe.verify_ttl(capture, "192.0.2.10")

    def test_queries_do_not_pollute_response_ttl_evidence(self):
        query = mdns_probe.make_query(mdns_probe.HOSTNAME, 1)
        with tempfile.TemporaryDirectory() as directory:
            capture = Path(directory) / "synthetic.pcapng"
            capture.write_bytes(pcapng(udp_frame()) + pcapng(udp_frame(64, payload=query)))
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                mdns_probe.verify_ttl(capture, "192.0.2.10")
            self.assertIn("packets=1", output.getvalue())

    def test_ttl_acceptance_and_rejection(self):
        with tempfile.TemporaryDirectory() as directory:
            capture = Path(directory) / "synthetic.pcapng"
            for ttl in (0, 64, 254, 255):
                with self.subTest(ttl=ttl):
                    capture.write_bytes(pcapng(udp_frame(ttl)))
                    with contextlib.redirect_stdout(io.StringIO()):
                        if ttl == 255:
                            mdns_probe.verify_ttl(capture, "192.0.2.10")
                        else:
                            with self.assertRaises(RuntimeError):
                                mdns_probe.verify_ttl(capture, "192.0.2.10")

    def test_unrelated_packets_cannot_pass_ttl_gate(self):
        frames = (
            udp_frame(source="192.0.2.11"),
            udp_frame(source_port=9999),
        )
        with tempfile.TemporaryDirectory() as directory:
            capture = Path(directory) / "synthetic.pcapng"
            for frame in frames:
                with self.subTest(frame=frame):
                    capture.write_bytes(pcapng(frame))
                    with self.assertRaises(RuntimeError):
                        mdns_probe.verify_ttl(capture, "192.0.2.10")


if __name__ == "__main__":
    unittest.main()
