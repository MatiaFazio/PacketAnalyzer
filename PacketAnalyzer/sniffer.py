from scapy.all import sniff, get_if_addr
from scapy.layers.inet import TCP, IP
from prettytable import PrettyTable
import logging
import os

global net_interface, no, limit, tmp_limit, table, ports, logger
flags = {'C': 0, 'E': 0, 'U': 0, 'A': 0, 'P': 0, 'R': 0, 'S': 0, 'F': 0}
protocols = {'C': 'CVR', 'E': 'ECE', 'U': 'URG', 'A': 'ACK', 'P': 'PSH', 'R': 'RST', 'S': 'SYN', 'F': 'FYN',
             'SA': 'SYN, ACK', 'FA': 'FIN, ACK', 'PA': 'PSH, ACK', 'RA': 'RST, ACK'}
protocols_numbers = {1: 'ICMP', 4: 'IPv4', 6: 'TCP', 56: 'TLSP', 143: 'Ethernet', 17: 'UDP'}
net_int_list = []


# List all the available network interfaces saved in the path /sys/class/net
def get_network_interfaces():
    ni_list = os.listdir('/sys/class/net')
    i = 0
    print('Available network interfaces:')
    for ni in ni_list:
        net_int_list.append(ni)
        print('{i}: {ni}'.format(i=i, ni=ni_list[i]))
        i += 1


# Get the network interface chosen by the user
def set_sniffer_params():
    global net_interface, table, no, limit, tmp_limit,  ports
    print('Select the network interface with the corresponding number: ', end='')
    i = input()
    table = PrettyTable()
    table.field_names = ["No.", "  Source  ", "Destination", "Protocol", "Length", "       Info       "]
    no = 1
    ports = []
    print("How many syn packets can you receive before assuming you are under a syn flood attack?: ", end='')
    limit = input()

    # Check if input values are correct
    if i.isdigit() and i and limit and limit.isdigit():
        limit = int(limit)
        tmp_limit = limit
        try:
            net_interface = net_int_list[int(i)]
        except IndexError as error:
            print("Insert valid numbers, %s." % error)
            set_sniffer_params()
    else:
        print("Insert valid numbers.")
        set_sniffer_params()

    print('Start capture packets in the %s network interface...' % net_interface)
    print(table)


# The Syn Flood Attack analyzer function that check if there are ack packets after receiving a number of syn packets
# chosen by the user (limit)
def sfa_analyzer(packet):
    global no, limit, tmp_limit, logger
    no += 1
    if TCP in packet:
        # Save or increase flag values of received tcp packets in a dictionary
        if str(packet[TCP].flags) in flags:
            flags[str(packet[TCP].flags)] += 1
        else:
            flags[str(packet[TCP].flags)] = 1
        if str(packet[TCP].flags) == 'S':
            tmp_limit -= 1

        # If I received exactly 'limit' packets, if there are only SYN packets and ANY ACK packets, maybe a syn flood
        # attack is received
        if tmp_limit == 0:
            if flags['S'] > 1 and flags['A'] == 0:
                logger = setup_logger('attacks_logger', 'attacks.log', logging.WARNING, 'a')
                logger.warning("It's highly probable that you're undergoing a syn flood attack!")
                logger = setup_logger('packets_logger', 'scan_results.log', logging.INFO, 'w')
                tmp_limit = limit


# The port scanning analyzer
def port_scanning(packet):
    global ports, logger
    if TCP in packet:
        # If I receive more then 10 packets with the same ip destination address of my nic, but every time on
        # different ports, maybe I'm under a port scanning attack
        if packet[IP].dst == get_if_addr(net_interface) and packet[TCP].dport not in ports:
            ports.append(packet[TCP].dport)
        if len(ports) > 10:
            logger = setup_logger('attacks_logger', 'attacks.log', logging.WARNING, 'a')
            logger.warning("It's highly probable that you're undergoing a port scanning attack!")
            logger = setup_logger('packets_logger', 'scan_results.log', logging.INFO, 'w')


# It analyze the packet, sets the info field, add the new received packet to the table and scan it to check if it is
# part of an attack
def analyze_packets(packet):
    global table, logger
    if TCP in packet:
        try:
            info = "[%s]" % protocols[str(packet[TCP].flags)]
            info += ", ttl=%d" % packet[IP].ttl
        except KeyError:
            info = "[%s]" % packet[TCP].flags
            info += ", ttl=%d" % packet[IP].ttl
    elif IP in packet:
        info = "ttl=%d" % packet[IP].ttl
    else:
        info = ''

    table.add_row([no, packet[IP].src, packet[IP].dst, protocols_numbers[packet[IP].proto], packet[IP].len, info])
    print("\n".join(table.get_string().splitlines()[-2:]))
    sfa_analyzer(packet)
    port_scanning(packet)


# A simple function to start to sniff the packets (until to sniff 500 packets) transmitted through the specified nic
def sniff_packets(nic):
    sniff(filter='tcp', iface=nic, count=500, prn=analyze_packets)


# This function setups a logger. It was created to use two different loggers, one for packets, and one for attacks.
def setup_logger(name, log_file, level, filemode):
    global logger

    handler = logging.FileHandler(log_file, mode=filemode)
    logger = logging.getLogger(name)
    logger.setLevel(level)
    logger.addHandler(handler)
    return logger


# The main function. This is where the program starts
def main():
    global logger
    open("attacks.log", 'w').close()
    open("scan_results.log", 'w').close()
    logger = setup_logger('packets_logger', 'scan_results.log', logging.INFO, 'w')
    get_network_interfaces()
    set_sniffer_params()
    sniff_packets(net_interface)
    logger.info(table)


if __name__ == '__main__':
    main()
