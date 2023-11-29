import pyshark
import logging


# Определяет класс с именем IPPacket, представляющий пакет IP с атрибутами для source IP, destination IP и packet data
class IPPacket:
    def __init__(self, source_ip, destination_ip, data):
        self.source_ip = source_ip
        self.destination_ip = destination_ip
        self.data = data


# Определяет класс, отвечающий за обработку пакетов и захват сетевого трафика.
class PacketProcessor:
    def __init__(self, interface='Wi-Fi'):
        self.interface = interface
        self.setup_capture()

    # Извлекает данные из различных уровней пакета и возвращает их в виде байтов.
    @staticmethod
    def extract_packet_data(packet):
        data = b""
        # Цикл for проходится по слоям пакета.
        # Для каждого слоя происходит попытка преобразования данных слоя в байты и добавления их к общему буферу данных.
        for layer in packet.layers:
            try:
                data += bytes(layer)
            except TypeError:
                pass  # Пропускаем слои, которые нельзя преобразовать в байты
        # Метод возвращает буфер данных в виде байтового объекта, содержащего информацию
        # из различных слоев пакета, объединенных в один поток.
        return data

    # Разбивает данные пакета на более мелкие фрагменты на основе максимального
    # размера фрагмента и создает экземпляры IPPacket для каждого фрагмента.
    @staticmethod
    def fragment_packets(packet, max_fragment_size):
        data = packet.data  # Данные пакета
        # Поле в IP-заголовке фрагментированного пакета, которое указывает
        # на смещение данного фрагмента относительно начала данных исходного пакета.
        fragment_offset = 0
        # В IP-заголовке фрагмента указывает на общее количество фрагментов, на которые был разделен исходный пакет
        total_packets = (len(data) + max_fragment_size - 1) // max_fragment_size

        fragments = []
        for i in range(total_packets):  # Cоздает фрагменты путем итерации через данные пакета с шагом max_fragment_size
            fragment_data = data[i * max_fragment_size: (i + 1) * max_fragment_size]
            # Для фрагмента создается новый объект IPPacket с данными, источником и назначением IP из исходного пакета.
            # Каждый фрагмент также получает информацию о своем смещении и общем количестве фрагментов,
            # что помогает в последующей объединении фрагментов в исходные данные.
            fragment = IPPacket(packet.source_ip, packet.destination_ip, fragment_data)
            fragment.fragment_offset = fragment_offset
            fragment.total_packets = total_packets
            fragments.append(fragment)
            fragment_offset += len(fragment_data) // 8

        return fragments

    # Объединяет фрагменты пакета в один поток
    @staticmethod
    def reassemble_packets(fragments):
        # Фрагменты пакета, содержащие части данных, сортируются по смещению фрагмента,
        # чтобы упорядочить их в правильной последовательности для объединения обратно в исходные данные.
        fragments.sort(key=lambda x: x.fragment_offset)
        # Создается пустой байтовый объект data, в который будут добавляться данные из отсортированных фрагментов.
        data = b''
        # Цикл перебирает фрагменты, начиная с самого первого (с наименьшим смещением).
        for fragment in fragments:
            # Данные каждого фрагмента добавляются к общему байтовому объекту data
            data += fragment.data
        # Метод возвращает data, который содержит все объединенные данные из фрагментов пакета.
        return data

    # Нефрагментированный пакет
    @staticmethod
    def process_non_fragmented_packet(non_fragmented_packet):
        print("Нефрагментированный пакет:")
        print(non_fragmented_packet)

    # Обработка входящих пакетов
    def process_packet(self, packet):
        try:
            if 'IP' in packet:
                # Если пакет нефрагментированный
                if packet.ip.flags_df == '1' and packet.ip.flags_mf == '0':
                    self.process_non_fragmented_packet(packet)
                else:
                    # Если пакет фрагментированный, данные пакета извлекаются с использованием метода
                    # extract_packet_data, создается экземпляр IPPacket, который представляет исходные данные пакета,
                    # и фрагменты формируются при помощи метода fragment_packets.
                    original_data = self.extract_packet_data(packet)
                    original_packet = IPPacket(packet.ip.src, packet.ip.dst, original_data)
                    max_fragment_size = 20
                    fragments = self.fragment_packets(original_packet, max_fragment_size)
                    # Фрагменты собираются обратно в исходные данные с помощью метода reassemble_packets.
                    reassembled_data = self.reassemble_packets(fragments)
                    # Результат выводится в виде текста, декодированного из байтов.
                    print(reassembled_data.decode())  # Объединенные фрагментированные пакеты

        # Обработка ошибок
        except Exception as e:
            print(f"Ошибка обработки пакета: {str(e)}")

    # Захват пакетов
    def setup_capture(self):
        self.capture = pyshark.LiveCapture(interface=self.interface)
        logging.basicConfig(filename='../packet_capture.log', level=logging.ERROR,
                            format='%(asctime)s [%(levelname)s]: %(message)s', datefmt='%Y-%m-%d %H:%M:%S')
