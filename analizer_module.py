import logging
import time
from capture_module import PacketProcessor
from datetime import datetime


class HTTPAnalyzer:

    @staticmethod
    def analyze(packet):
        # Add rules for HTTP packet analysis
        print("Analyzing HTTP packet...")
        if 'HTTP' in packet:
            print(f"Протокол прикладного уровня: HTTP")
        elif 'SSH' in packet:
            print(f"Протокол прикладного уровня: SSH")
        # Rules for HTTP packet analysis go here


class IPAnalyzer:

    @staticmethod
    def analyze(packet):
        # Add rules for IP packet analysis
        print("Reassembled fragmented packets: ")
        print(f"Пакет: №{packet.number}")
        print(f"Время: {datetime.fromtimestamp(float(packet.sniff_timestamp)).strftime('%Y-%m-%d %H:%M:%S')}")

        if hasattr(packet, 'ip'):
            print(f"Source IP: {packet.ip.src}")
            print(f"Destination IP: {packet.ip.dst}")
        else:
            print("IP information not found in the packet.")
        if 'ip' in packet:
            print(f"Протокол сетевого уровня: IPv{packet.ip.version}")


class SSHAnalyzer:

    @staticmethod
    def analyze(packet):
        # Add rules for SSH packet analysis
        if 'SSH' in packet:
            print(f"Протокол прикладного уровня: SSH")
        elif 'TCP' in packet:
            print(f"Протокол транспортного уровня: TCP")
            print(f"Исходный порт: {packet.tcp.srcport}")
            print(f"Порт назначения: {packet.tcp.dstport}")
        elif 'UDP' in packet:
            print(f"Протокол транспортного уровня: UDP")
            print(f"Исходный порт: {packet.udp.srcport}")
            print(f"Порт назначения: {packet.udp.dstport}")
        # Rules for SSH packet analysis go here


class TCPUDPAnalyzer:

    @staticmethod
    def analyze(packet):
        # Add rules for SSH packet analysis
        if 'TCP' in packet:
            print(f"Протокол транспортного уровня: TCP")
            print(f"Исходный порт: {packet.tcp.srcport}")
            print(f"Порт назначения: {packet.tcp.dstport}")
        if 'UDP' in packet:
            print(f"Протокол транспортного уровня: UDP")
            print(f"Исходный порт: {packet.udp.srcport}")
            print(f"Порт назначения: {packet.udp.dstport}")


class ARPAnalyzer:

    @staticmethod
    def analyze(packet):
        if 'ARP' in packet:
            arp_packet = packet.arp
            print("ARP пакет обнаружен:")
            print(f"MAC отправителя: {arp_packet.src_hw_mac}")
            print(f"IP отправителя: {arp_packet.src_proto_ipv4}")
            print(f"MAC назначения: {arp_packet.dst_hw_mac}")
            print(f"IP назначения: {arp_packet.dst_proto_ipv4}")
        # Rules for ARP packet analysis go here


class Analyzer:
    def __init__(self, interface='Wi-Fi'):
        self.processor = PacketProcessor(interface)

    def process_packet(self, packet):
        try:
            # Extracting and processing packet information using the packet processor
            self.processor.process_packet(packet)

            # Analyzing packets using different rule sets for specific protocols
            if 'HTTP' in packet:
                http_analyzer = HTTPAnalyzer()
                http_analyzer.analyze(packet)

            if 'SSH' in packet:
                ssh_analyzer = SSHAnalyzer()
                ssh_analyzer.analyze(packet)

            if 'IP' in packet:
                ip_analyzer = IPAnalyzer()
                ip_analyzer.analyze(packet)

            if 'TPC' in packet:
                tcp_analyzer = TCPUDPAnalyzer()
                tcp_analyzer.analyze(packet)

            if 'UDP' in packet:
                udp_analyzer = TCPUDPAnalyzer()
                udp_analyzer.analyze(packet)

            if 'ARP' in packet:
                arp_analyzer = ARPAnalyzer()
                arp_analyzer.analyze(packet)

        except Exception as e:
            print(f"Error processing or analyzing packet: {str(e)}")


class MainAnalyzer:
    def __init__(self, interface='Wi-Fi'):
        self.interface = interface

    def packet_capture(self):
        try:
            analyzer = Analyzer(self.interface)
            for packet in analyzer.processor.capture.sniff_continuously(packet_count=0):
                analyzer.process_packet(packet)
                time.sleep(1)

        except Exception as e:
            print(f"Error capturing or processing packet: {str(e)}")
            logging.error(f"Error capturing or processing packet: {str(e)}")

        except KeyboardInterrupt:
            print("Program interrupted by user, cleaning up and exiting...")
            logging.error("Program interrupted by user, cleaning up and exiting...")

        except ConnectionError as e:
            logging.error(f"Connection error occurred: {str(e)}")


if __name__ == '__main__':
    main_analyzer = MainAnalyzer()
    main_analyzer.packet_capture()
