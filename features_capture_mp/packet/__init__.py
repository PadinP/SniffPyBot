import os
import queue
from multiprocessing import Process, Queue
from settings import logger as logging
from utils import get_date_string

# Timeout to wait for new packets
INTERVAL = 15
# TCP flags order for network state
FLAGS_ORDER = "FSRPAECU"
ICMP_STATES = {
    "0": "ECR",
    "1": "UNK",
    "2": "UNK",
    "3": "URH",
    "5": "RED",
    "7": "URP",
    "8": "ECO",
    "9": "RTA",
    "10": "RTS",
    "11": "TXD",
    "12": "PAR",
    "13": "TST",
    "14": "TSR",
    "40": "PHO",
}


class FlowAnalysis(Process):
    """
    Class that inherits from multiprocessing.Process and
    creates a new process to analyze packets from same netflow.
    """

    def __init__(self, name, packet):
        """
        @param name: name of the process
        @param packet: first packet of the netflow received
        """
        super().__init__(name=name)
        self.q = Queue()
        self.continue_flag = True
        self.packet = packet

    def init(self):
        """
        Continuation of the constructor method because when creating a new
        process the init method is executed in the main process (sequential).
        Extracts the basic info of the netflow.
        """
        self.start_time = get_date_string(self.packet.frame_info.time)
        self.duration = 0
        pkt_protocol = self.packet.highest_layer
        if "TCP" in self.packet:
            pkt_protocol = "TCP"
        elif "UDP" in self.packet:
            pkt_protocol = "UDP"
        self.protocol = pkt_protocol
        self.src_port = ""
        self.dst_port = ""
        if self.protocol == "ARP":
            self.src_adr = self.packet.arp.src_proto_ipv4
            self.dst_adr = self.packet.arp.dst_proto_ipv4
        elif "IP" in self.packet:
            self.src_adr = self.packet.ip.src
            self.dst_adr = self.packet.ip.dst
            self.s_tos = self.packet.ip.dsfield_dscp
        elif "IPv6" in self.packet:
            self.src_adr = self.packet.ipv6.src
            self.dst_adr = self.packet.ipv6.dst

        if "TCP" in self.packet:
            self.src_port = self.packet.tcp.srcport
            self.dst_port = self.packet.tcp.dstport
        elif "ICMP" in self.packet:
            self.src_port = self.packet.icmp.checksum
        elif "UDP" in self.packet:
            self.src_port = self.packet.udp.srcport
            self.dst_port = self.packet.udp.dstport

        self.state = ""
        self.state = self.calculate_network_state(self.packet)
        self.d_tos = ""
        if not hasattr(self, "s_tos"):
            self.s_tos = ""

        self.tot_pkts = 1
        self.tot_bytes = int(self.packet.length)
        self.src_bytes = int(self.packet.length)

        self.flow = "Background"
        if "172.18.0" in self.src_adr or "172.18.0" in self.dst_adr:
            last_src = None
            last_dst = None
            if "172.18.0" in self.src_adr:
                last_src = int(self.src_adr.split(".")[-1])
            if "172.18.0" in self.dst_adr:
                last_dst = int(self.dst_adr.split(".")[-1])
            if (last_src and last_src > 3) or (last_dst and last_dst > 3):
                self.flow = "Botnet"
            elif (last_src and last_src == 1) or (last_dst and last_dst == 1):
                self.flow = "Normal"

        logging.info(
            f"Packet #{self.packet.number} processed in process: %s", self.name
        )

    def on_thread(self, packet):
        """
        Allow communication with the main process to send new packets
        to an already captured netflow. Puts the packets in the queue of
        packets to be analyzed.
        @param packet: new packet to analyze
        """
        self.q.put(packet)

    def run(self):
        """
        Override method from multiprocessing. Start the execution of the
        process and keep the process alive to wait for new packets until the
        queue timeout is over.
        """
        self.init()
        while self.continue_flag:
            try:
                packet = self.q.get(block=True, timeout=INTERVAL)
            except queue.Empty:
                self.save_to_file()
                self.continue_flag = False
            else:
                self.handle_incoming_packet(packet)

    def handle_incoming_packet(self, packet):
        """
        Method to analyze new packets and update netflow with extracted
        features.
        @param packet: network packet to analyze
        """
        inc_time = get_date_string(packet.frame_info.time)
        self.duration = (inc_time - self.start_time).total_seconds()

        self.tot_pkts += 1
        self.tot_bytes += int(packet.length)

        if self.protocol == "ARP":
            if self.src_adr == packet.arp.src_proto_ipv4:
                self.src_bytes += int(packet.length)
        elif "IP" in packet:
            if self.src_adr == packet.ip.src:
                self.src_bytes += int(packet.length)
                self.s_tos = packet.ip.dsfield_dscp
            else:
                self.d_tos = packet.ip.dsfield_dscp
        elif "IPv6" in packet:
            if self.src_adr == packet.ipv6.src:
                self.src_bytes += int(packet.length)

        self.state = self.calculate_network_state(packet)
        logging.info(f"Packet #{packet.number} processed in process: %s", self.name)

    def calculate_network_state(self, packet):
        """
        @param packet: network packet to analyze network state
        @return: network state
        """
        state = ""
        if "UDP" in packet:
            state = "CON"
            if "UDP" != packet.highest_layer:
                state = "INT"
        elif "TCP" in packet:
            is_src = self.src_adr == packet.ip.src
            tcp_flags = {
                "F": packet.tcp.flags_fin,
                "S": packet.tcp.flags_syn,
                "R": packet.tcp.flags_reset,
                "P": packet.tcp.flags_push,
                "A": packet.tcp.flags_ack,
                "E": packet.tcp.flags_ece,
                "C": packet.tcp.flags_cwr,
                "U": packet.tcp.flags_urg,
            }

            if self.state == "":
                self.state = "_"
            state_split = self.state.split("_")
            state_update = state_split[0] if is_src else state_split[1]

            for key, value in tcp_flags.items():
                if value == "1" and key not in state_update:
                    flags_before = FLAGS_ORDER[: FLAGS_ORDER.index(key)]
                    index = next(
                        (
                            state_update.index(flag)
                            for flag in flags_before
                            if flag in state_update
                        ),
                        None,
                    )
                    if index is not None:
                        index += 1
                        state_update = state_update[:index] + key + state_update[index:]
                    else:
                        state_update = key + state_update
            if is_src:
                state = state_update + "_" + state_split[1]
            else:
                state = state_split[0] + "_" + state_update
        elif self.protocol == "ARP":
            state = "CON" if packet.arp.opcode == "1" else "RSP"
        elif self.protocol == "IGMP":
            state = "INT"
        elif self.protocol == "ICMP":
            state = ICMP_STATES[packet.icmp.type]

        return state

    def save_to_file(self):
        file_path = "flow_analysis.binetflow"
        headers = "StartTime,Dur,Proto,SrcAddr,Sport,Dir,DstAddr,Dport,State,sTos,dTos,TotPkts,TotBytes,SrcBytes,Label\n"
        dirDict = {
            "   ->": 1,
            "   ?>": 2,
            "  <->": 3,
            "  <?>": 4,
            "  who": 5,
            "  <-": 6,
            "  <?": 7,
        }

        if not os.path.exists(file_path) or os.path.getsize(file_path) == 0:
            with open(file_path, "w") as f:
                f.write(headers)

        try:
            dir_key = "   ->" if self.src_adr and self.dst_adr else "  <->"
            dir_key = "  <-" if not self.src_adr and self.dst_adr else dir_key
            dir_key = "   ?>" if self.src_adr and not self.dst_adr else dir_key
            dir_key = dir_key if dir_key in dirDict else "  <?>"

            with open(file_path, "a") as f:
                f.write(
                    f"{self.start_time},{self.duration},{self.protocol},{self.src_adr},{self.src_port},{dir_key},"
                    f"{self.dst_adr},{self.dst_port},{self.state},{self.s_tos},{self.d_tos},{self.tot_pkts},"
                    f"{self.tot_bytes},{self.src_bytes},flow={self.flow}\n"
                )
                logging.info(
                    f"Saved flow with ID: {self.name} and direction: {dir_key}"
                )
        except Exception as e:
            logging.error(f"Error writing to file: {str(e)}")
