import pyshark
import logging
import time
from datetime import datetime


class IPPacket:
    def __init__(self, source_ip, destination_ip, data):
        self.source_ip = source_ip
        self.destination_ip = destination_ip
        self.data = data


class PacketProcessor:
    def __init__(self, interface='Wi-Fi'):
        self.interface = interface

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
                    print("Reassembled fragmented packets:", reassembled_data.decode())

            if hasattr(packet, 'ip'):
                print(f"Source IP: {packet.ip.src}")
                print(f"Destination IP: {packet.ip.dst}")
            else:
                print("IP information not found in the packet.")

            print(f"Пакет: №{packet.number}")
            print(f"Время: {datetime.fromtimestamp(float(packet.sniff_timestamp)).strftime('%Y-%m-%d %H:%M:%S')}")

            if 'ip' in packet:
                print(f"Протокол сетевого уровня: IPv{packet.ip.version}")

            if 'TCP' in packet:
                print(f"Протокол транспортного уровня: TCP")
                print(f"Исходный порт: {packet.tcp.srcport}")
                print(f"Порт назначения: {packet.tcp.dstport}")

            elif 'UDP' in packet:
                print(f"Протокол транспортного уровня: UDP")
                print(f"Исходный порт: {packet.udp.srcport}")
                print(f"Порт назначения: {packet.udp.dstport}")

            if 'HTTP' in packet:
                print(f"Протокол прикладного уровня: HTTP")
            elif 'SSH' in packet:
                print(f"Протокол прикладного уровня: SSH")

            if 'ARP' in packet:
                arp_packet = packet.arp
                print("ARP пакет обнаружен:")
                print(f"MAC отправителя: {arp_packet.src_hw_mac}")
                print(f"IP отправителя: {arp_packet.src_proto_ipv4}")
                print(f"MAC назначения: {arp_packet.dst_hw_mac}")
                print(f"IP назначения: {arp_packet.dst_proto_ipv4}")

            print("\n")

        except Exception as e:
            print(f"Error processing packet: {str(e)}")

    def packet_capture(self):
        try:
            capture = pyshark.LiveCapture(interface=self.interface)
            logging.basicConfig(filename='packet_capture.log', level=logging.ERROR,
                                format='%(asctime)s [%(levelname)s]: %(message)s', datefmt='%Y-%m-%d %H:%M:%S')

            for packet in capture.sniff_continuously(packet_count=0):
                self.process_packet(packet)
                time.sleep(1)

        except Exception as e:
            print(f"Error capturing packet: {str(e)}")
            logging.error(f"Error capturing packet: {str(e)}")

        except KeyboardInterrupt:
            print("Program interrupted by user, cleaning up and exiting...")
            logging.error("Program interrupted by user, cleaning up and exiting...")

        except ConnectionError as e:
            logging.error(f"Произошла ошибка подключения {str(e)}")


if __name__ == '__main__':
    processor = PacketProcessor()
    processor.packet_capture()
