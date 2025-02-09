import queue
import time
from threading import Thread
from settings import logger as logging
from utils import get_date_string

"""
Packet Analyzer for the Capture Module
 :StartTime
 :Dur
 :Proto
 :SrcAddr
 :Sport
 :DstAddr
 :Dport
 :State
 :sTos
 :dTos
 :TotPkts
 :TotBytes
 :SrcBytes
 :Label
"""

INTERVAL = 15
FLAGS_ORDER = 'FSRPAECU'
ICMP_STATES = {'0': 'ECR', '1': 'UNK', '2': 'UNK', '3': 'URH', '5': 'RED', '7': 'URP', '8': 'ECO', '9': 'RTA',
                           '10': 'RTS', '11': 'TXD', '12': 'PAR', '13': 'TST', '14': 'TSR', '40': 'PHO'}


class FlowAnalysis(Thread):
    def __init__(self, name, packet):
        super().__init__(name=name)

        self.q = queue.Queue()
        self.continue_flag = True
        self.packet = packet

    def init(self):
        self.start_time = get_date_string(self.packet.frame_info.time)

        self.duration = 0

        pkt_protocol = self.packet.highest_layer
        if 'TCP' in self.packet:
            pkt_protocol = 'TCP'
        elif 'UDP' in self.packet:
            pkt_protocol = 'UDP'
        self.protocol = pkt_protocol
        self.src_port = ''
        self.dst_port = ''
        if self.protocol == 'ARP':
            self.src_adr = self.packet.arp.src_proto_ipv4
            self.dst_adr = self.packet.arp.dst_proto_ipv4
        elif 'IP' in self.packet:
            self.src_adr = self.packet.ip.src
            self.dst_adr = self.packet.ip.dst
            self.s_tos = self.packet.ip.dsfield_dscp
        elif 'IPv6' in self.packet:
            self.src_adr = self.packet.ipv6.src
            self.dst_adr = self.packet.ipv6.dst

        if 'TCP' in self.packet:
            self.src_port = self.packet.tcp.srcport
            self.dst_port = self.packet.tcp.dstport
        elif 'ICMP' in self.packet:
            self.src_port = self.packet.icmp.checksum
        elif 'UDP' in self.packet:
            self.src_port = self.packet.udp.srcport
            self.dst_port = self.packet.udp.dstport

        self.state = ''
        self.state = self.calculate_network_state(self.packet)
        self.d_tos = ''
        if not hasattr(self, 's_tos'):
            self.s_tos = ''

        self.tot_pkts = 1
        self.tot_bytes = int(self.packet.length)
        self.src_bytes = int(self.packet.length)

        self.flow = 'Background'
        if '172.26.0' in self.src_adr or '172.26.0' in self.dst_adr:
            last_src = None
            last_dst = None
            if '172.26.0' in self.src_adr:
                last_src = int(self.src_adr.split('.')[len(self.src_adr.split('.')) - 1])
            if '172.26.0' in self.dst_adr:
                last_dst = int(self.dst_adr.split('.')[len(self.dst_adr.split('.')) - 1])
            if (last_src and last_src > 3) or (last_dst and last_dst > 3):
                self.flow = 'Botnet'
            elif (last_src and last_src == 1) or (last_dst and last_dst == 1):
                self.flow = 'Normal'

        logging.info(f'Packet #{self.packet.number} processed in thread: %s', self.name)

    def on_thread(self, function, *args, **kwargs):
        self.q.put((function, args, kwargs))

    def run(self):
        self.init()
        while self.continue_flag:
            try:
                function, args, kwargs = self.q.get(block=True, timeout=INTERVAL)
            except queue.Empty:
                self.save_to_file()
                self.continue_flag = False
            else:
                function(*args, **kwargs)

    def idle(self):
        pass

    def interrupt_handler(self, packet):
        self.wait_time = 0

    def handle_incoming_packet(self, packet):

        inc_time = get_date_string(packet.frame_info.time)
        self.duration = (inc_time - self.start_time).total_seconds()

        self.tot_pkts += 1
        self.tot_bytes += int(packet.length)

        # check if packet ip src is self.src_adr
        if self.protocol == 'ARP':
            if self.src_adr == packet.arp.src_proto_ipv4:
                self.src_bytes += int(packet.length)
        elif 'IP' in packet:
            if self.src_adr == packet.ip.src:
                self.src_bytes += int(packet.length)
                self.s_tos = packet.ip.dsfield_dscp
            else:
                self.d_tos = packet.ip.dsfield_dscp
        elif 'IPv6' in packet:
            if self.src_adr == packet.ipv6.src:
                self.src_bytes += int(packet.length)

        self.state = self.calculate_network_state(packet)
        terminate = False
        if 'F' in self.state or 'R' in self.state:
            pass

        logging.info(f'Packet #{packet.number} processed in thread: %s', self.name)
        if terminate:
            self.save_to_file()
            self.kill()

    def calculate_network_state(self, packet):
        state = ''
        if 'UDP' in packet:
            state = 'CON'
            if 'UDP' != packet.highest_layer:
                state = 'INT'
        if 'TCP' in packet:
            is_src = False
            if self.src_adr == packet.ip.src:
                is_src = True
            # [flags_res', 'flags_ns', 'flags_cwr' ,'flags_ece', 'flags_urg', 'flags_ack', 'flags_push',
            # 'flags_reset', 'flags_syn', 'flags_fin', 'flags_str'] LETTERS OF STATES: flags_cwr - C, tcp.flags_ece -
            # E, tcp.flags_urg - U, tcp.flags_ack - A, flags_push - P 8          flags_reset - R, flags_syn - S,
            # flags_fin - F discarted tcp: tcp.flags_res ,tcp.flags_ns,
            tcp_flags = {'F': packet.tcp.flags_fin, 'S': packet.tcp.flags_syn, 'R': packet.tcp.flags_reset,
                         'P': packet.tcp.flags_push, 'A': packet.tcp.flags_ack, 'E': packet.tcp.flags_ece,
                         'C': packet.tcp.flags_cwr, 'U': packet.tcp.flags_urg}

            if self.state == '':
                self.state = '_'
            state_split = self.state.split('_')
            if is_src:
                state_update = state_split[0]
            else:
                state_update = state_split[1]
            # iterate tcp_flags dictionary
            for key in tcp_flags.keys():
                if tcp_flags[key] == '1':
                    if key not in state_update:
                        if state_update == '':
                            state_update = key
                        else:
                            flags_before = FLAGS_ORDER[:FLAGS_ORDER.index(key)]
                            index = None
                            for flag in flags_before:
                                if flag in state_update:
                                    index = state_update.index(flag)
                            if index is not None:
                                index += 1
                                state_update = ''.join([state_update[:index], key, state_update[index:]])
                            else:
                                state_update = ''.join([key, state_update])
            if is_src:
                state = ''.join([state_update, '_', state_split[1]])
            else:
                state = ''.join([state_split[0], '_', state_update])

        if self.protocol == 'ARP':
            if packet.arp.opcode == '1':
                state = 'CON'
            elif packet.arp.opcode == '2':
                state = 'RSP'
        elif self.protocol == 'IGMP':
            state = 'INT'
        elif self.protocol == 'ICMP':
            state = ICMP_STATES[packet.icmp.type]
        return state

    def save_to_file(self):
        with open('flow_analysis.binetflow', 'a') as f:
            try:
                f.write(f'{self.start_time},{self.duration},{self.protocol},{self.src_adr},{self.src_port},'
                        f'{self.dst_adr},{self.dst_port},{self.state},{self.s_tos},{self.d_tos},{self.tot_pkts},'
                        f'{self.tot_bytes},{self.src_bytes},flow={self.flow}\n')
                logging.info('Saving to file flow with id: %s', self.name)
            except Exception as e:
                logging.error('Error writing to file: ' + str(e))
