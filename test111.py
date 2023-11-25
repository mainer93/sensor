import pyshark
import logging
import time


# Фрагментированный пакет
def process_fragmented_packet(fragment_packet):
    print("Фрагментированный пакет:")
    print(fragment_packet)


# Нефрагментированный пакет
def process_non_fragmented_packet(non_fragmented_packet):
    print("Нефрагментированный пакет:")
    print(non_fragmented_packet)


# Захват пакетов
def packet_capture(interface):

    try:
        capture = pyshark.LiveCapture(interface=interface)
        # Логирование ошибок
        logging.basicConfig(filename='packet_capture.log', level=logging.ERROR,
                            format='%(asctime)s [%(levelname)s]: %(message)s', datefmt='%Y-%m-%d %H:%M:%S')

        for packet in capture.sniff_continuously(packet_count=0):
            process_packet(packet)

    # Обработка ошибок
    except Exception as e:
        print(f"Ошибка при захвате пакета: {str(e)}")
        logging.error(f"Ошибка при захвате пакета: {str(e)}")

    # Обработка ошибок
    except KeyboardInterrupt:
        print("Программа прервана пользователем, очистка и выход...")
        logging.error("Программа прервана пользователем, очистка и выход...")


# Определение вида пакетов (здесь же объединение фрагментированных пакетов)
def process_packet(packet):

    try:
        # Нефрагментированные пакеты
        if packet.ip.flags_df == '1' and packet.ip.flags_mf == '0':
            process_non_fragmented_packet(packet)
        else:
            # Фрагментированные пакеты
            process_fragmented_packet(packet)

        # Если IP отобразился, то:
        if hasattr(packet, 'ip'):
            print(f"Исходный IP: {packet.ip.src}")
            print(f"IP-адрес назначения: {packet.ip.dst}")
        else:
            # Если IP не отобразился, то:
            print("IP информация не найдена в пакете.")
        # Выводим всегда информацию ниже
        print(f"Пакет №{packet.number}")
        print(f"Время: {packet.sniff_timestamp}")
        print(f"Протокол: {packet.transport_layer}")

        # Определение протокола сетевого уровня
        if 'ip' in packet:
            print(f"Протокол сетевого уровня: IPv{packet.ip.version}")

        # Определение протоколов транспортного уровня
        if 'TCP' in packet:
            print(f"Протокол транспортного уровня: TCP")
            print(f"Исходный порт: {packet.tcp.srcport}")
            print(f"Порт назначения: {packet.tcp.dstport}")

        elif 'UDP' in packet:
            print(f"Протокол транспортного уровня: UDP")
            print(f"Исходный порт: {packet.udp.srcport}")
            print(f"Порт назначения: {packet.udp.dstport}")

        # Определение протоколов прикладного уровня
        if 'HTTP' in packet:
            print(f"Протокол прикладного уровня: HTTP")
        elif 'SSH' in packet:
            print(f"Протокол прикладного уровня: SSH")

        # Определение протокола ARP
        if 'ARP' in packet:
            arp_packet = packet.arp
            print("ARP пакет обнаружен:")
            print(f"MAC отправителя: {arp_packet.src_hw_mac}")
            print(f"IP отправителя: {arp_packet.src_proto_ipv4}")
            print(f"MAC назначения: {arp_packet.dst_hw_mac}")
            print(f"IP назначения: {arp_packet.dst_proto_ipv4}")

        print("\n")

    # Обработка ошибок
    except Exception as e:
        print(f"Ошибка при захвате пакета: {str(e)}")
        logging.error(f"Ошибка при обработке пакета: {str(e)}")

    # Обработка ошибок
    except KeyboardInterrupt:
        print("Программа прервана пользователем. Очистка и выход...")
        logging.error("Программа прервана пользователем. Очистка и выход...")

    # Обработка ошибок
    except ConnectionError as e:
        logging.error(f"Произошла ошибка подключения {str(e)}")

    # Время поступления посылок, ставь по фану, но лучше 1 :))))) Энн Хэтэуэй топ, время 5:56 утра
    time.sleep(0)


if __name__ == '__main__':
    network_interface = 'Ethernet 3'  # Здесь свой интерфейс пишем
    packet_capture(network_interface)
