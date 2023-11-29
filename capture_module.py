import pyshark
import logging


class IPPacket:
    def __init__(self, source_ip, destination_ip, data):
        self.source_ip = source_ip
        self.destination_ip = destination_ip
        self.data = data


class PacketProcessor:
    def __init__(self, interface='Wi-Fi'):
        self.interface = interface
        self.setup_capture()

    @staticmethod
    def extract_packet_data(packet):
        data = b""
        for layer in packet.layers:
            try:
                data += bytes(layer)
            except TypeError:
                pass  # Skipping layers that can't be converted to bytes
        return data

    @staticmethod
    def fragment_packets(packet, max_fragment_size):
        data = packet.data
        fragment_offset = 0
        total_packets = (len(data) + max_fragment_size - 1) // max_fragment_size

        fragments = []
        for i in range(total_packets):
            fragment_data = data[i * max_fragment_size: (i + 1) * max_fragment_size]
            fragment = IPPacket(packet.source_ip, packet.destination_ip, fragment_data)
            fragment.fragment_offset = fragment_offset
            fragment.total_packets = total_packets
            fragments.append(fragment)
            fragment_offset += len(fragment_data) // 8

        return fragments

    @staticmethod
    def reassemble_packets(fragments):
        fragments.sort(key=lambda x: x.fragment_offset)
        data = b''
        for fragment in fragments:
            data += fragment.data
        return data

    @staticmethod
    def process_non_fragmented_packet(non_fragmented_packet):
        print("Non-fragmented packet:")
        print(non_fragmented_packet)

    def process_packet(self, packet):
        try:
            if 'IP' in packet:
                if packet.ip.flags_df == '1' and packet.ip.flags_mf == '0':
                    self.process_non_fragmented_packet(packet)
                else:
                    original_data = self.extract_packet_data(packet)
                    original_packet = IPPacket(packet.ip.src, packet.ip.dst, original_data)
                    max_fragment_size = 20
                    fragments = self.fragment_packets(original_packet, max_fragment_size)
                    reassembled_data = self.reassemble_packets(fragments)
                    print(reassembled_data.decode())  # Reassembled fragmented packets
            # print("\n")

        except Exception as e:
            print(f"Error processing packet: {str(e)}")

    def setup_capture(self):
        self.capture = pyshark.LiveCapture(interface=self.interface)
        logging.basicConfig(filename='packet_capture.log', level=logging.ERROR,
                            format='%(asctime)s [%(levelname)s]: %(message)s', datefmt='%Y-%m-%d %H:%M:%S')
