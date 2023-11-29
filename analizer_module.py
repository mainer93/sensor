import logging
import time
from capture_module import PacketProcessor
from datetime import datetime
import yara

# Сборка YARA правил из файла
rules = yara.compile('network_rules.yar')


class HTTPAnalyzer:

    @staticmethod
    def analyze(packet):
        # Добавлены правила для анализа HTTP и SSH протоколов в пакете
        if 'HTTP' in packet:
            print(f"Протокол прикладного уровня: HTTP")
        elif 'SSH' in packet:
            print(f"Протокол прикладного уровня: SSH")


class IPAnalyzer:

    @staticmethod
    def analyze(packet):
        # Добавлены правила для анализа IP пакетов
        print("\n")
        print("Объединенные фрагментированные пакеты: ")
        print(f"Пакет: №{packet.number}")
        print(f"Время: {datetime.fromtimestamp(float(packet.sniff_timestamp)).strftime('%Y-%m-%d %H:%M:%S')}")

        if hasattr(packet, 'ip'):
            print(f"Исходный IP: {packet.ip.src}")
            print(f"IP-адрес назначения: {packet.ip.dst}")
        else:
            print("IP информация не найдена в пакете.")
        if 'ip' in packet:
            print(f"Протокол сетевого уровня: IPv{packet.ip.version}")


class SSHAnalyzer:

    @staticmethod
    def analyze(packet):
        # Добавлены правила для анализа SSH пакетов
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


class TCPUDPAnalyzer:

    @staticmethod
    def analyze(packet):
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


class Analyzer:
    def __init__(self, interface='Wi-Fi'):
        self.processor = PacketProcessor(interface)

    def process_packet(self, packet):
        try:
            if 'ip' in packet:
                ip_traffic = f"IP источника: {packet.ip.src}, IP получателя: {packet.ip.dst}," \
                             f" Протокол сетевого уровня: IPv{packet.ip.version}"
                for rule in rules.match(data=ip_traffic):
                    print(f"Совпадение IP правил: {rule}")
            else:
                print(f"Несовпадение IP правил")

            if 'tcp' in packet:
                tcp_traffic = f"Протокол транспортного уровня: TCP, Исходный порт: {packet.tcp.srcport}, " \
                              f"Порт назначения: {packet.tcp.dstport}"
                for rule in rules.match(data=tcp_traffic):
                    print(f"Совпадение TCP правил: {rule}")
            else:
                print(f"Несовпадение TCP правил")

            if 'udp' in packet:
                udp_traffic = f"Протокол транспортного уровня: TCP, Исходный порт: {packet.udp.srcport}, " \
                              f"Порт назначения: {packet.udp.dstport}"
                for rule in rules.match(data=udp_traffic):
                    print(f"Совпадение UDP правил: {rule}")
            else:
                print(f"Несовпадение UDP правил")

            if 'eth' in packet and packet.eth.type == '0x0806':
                arp_traffic = f"ARP: src_mac={packet.arp.src_hw_mac}, ARP: src_proto= {packet.arp.src_proto_ipv4}, " \
                              f"ARP: dst_mac={packet.arp.dst_hw_mac}, ARP: dst_proto={packet.arp.dst_proto_ipv4}"
                for rule in rules.match(data=arp_traffic):
                    print(f"Совпадение ARP правил: {rule}")
            else:
                print(f"Несовпадение ARP правил")

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
            print(f"Ошибка обработки или анализа пакета: {str(e)}")


class MainAnalyzer:
    def __init__(self, interface='Wi-Fi'):
        self.interface = interface

    def packet_capture(self):
        try:
            analyzer = Analyzer(self.interface)
            for packet in analyzer.processor.capture.sniff_continuously(packet_count=0):
                analyzer.process_packet(packet)
                time.sleep(0)

        except Exception as e:
            print(f"Ошибка захвата или обработки пакета: {str(e)}")
            logging.error(f"Ошибка захвата или обработки пакета: {str(e)}")

        except KeyboardInterrupt:
            print("Программа прервана пользователем, очистка и выход...")
            logging.error("Программа прервана пользователем, очистка и выход...")

        except ConnectionError as e:
            logging.error(f"Произошла ошибка подключения: {str(e)}")


if __name__ == '__main__':
    main_analyzer = MainAnalyzer()
    main_analyzer.packet_capture()
