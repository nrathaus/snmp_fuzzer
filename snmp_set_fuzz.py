#!/usr/bin/env python
# coding:utf-8
import socket

from scapy.all import *
import scapy.layers.inet
import scapy.layers.snmp

from Base import BaseTarget

# loading mibs
load_mib("mibs/*")

snmp_error_id = [2, 3, 4, 5, 6, 17, 10, 12, 14]

ASN1_Type = {
    0: [scapy.asn1.asn1.ASN1_IPADDRESS, RandIP()],
    1: [scapy.asn1.asn1.ASN1_STRING, RandBin()],
    2: [scapy.asn1.asn1.ASN1_INTEGER, RandInt()],
    3: [scapy.asn1.asn1.ASN1_GAUGE32, RandInt()],
}

SNMP_Error_code = {
    0: [0, "noError (0)"],
    1: [1, "tooBig (1)"],
    2: [2, "noSuchName (2)"],
    3: [3, "badValue (3)"],
    4: [4, "readOnly (4)"],
    5: [5, "genErr (5)"],
    6: [6, "noAccess (6)"],
    7: [7, "wrongType (7)"],
    8: [8, "wrongLength (8)"],
    9: [9, "wrongEncoding (9)"],
    10: [10, "wrongValue (10)"],
    11: [11, "noCreation (11)"],
    12: [12, "inconsistentValue (12)"],
    13: [13, "resourceUnavailable (13)"],
    14: [14, "commitFailed (14)"],
    15: [15, "undoFailed (15)"],
    16: [16, "authorizationError (16)"],
    17: [17, "notWritable (17)"],
    18: [18, "inconsistentName (18)"],
}


class SnmpTarget(BaseTarget):
    def __init__(
        self,
        name,
        target,
        monitor_port=None,
        community="private",
        version=2,
        oid=".1",
        output_path="./output",
        fuzz_count=100,
        timeout=1,
        nic=None,
        logger=None,
    ):
        """
        :param name: Name of target
        :param target: scapy.layers.inet.IP address of target
        :param monitor_port: Tcp port used to check target alive
        :param community: Snmp community with write privilege, default:'private'
        :param version: Snmp version only support version 1 and 2
        :param oid: Snmp scan start oid, default: '.1'
        :param output_path: Path to store scan result
        :param fuzz_count: Fuzz count of each writable oid
        :param timeout: Timeout for connect (float, in seconds)
        :param nic: Network interface name which used to connect to target
        :param logger: Logger of this target
        """
        super(SnmpTarget, self).__init__(name, logger)
        self._target = target
        self._monitor_port = monitor_port
        self._community = community
        self._oid = oid
        self._nic = nic
        self._timeout = timeout
        self.oid_list = []
        self.oid_write_list = []
        self.set_packets = []
        self._test_cases = []
        self._sent_packets = []
        self._crash_packets = []
        self._fuzz_count = fuzz_count
        self._output_path = output_path
        self._sent_packets_file_count = 0
        if version == 1:
            self._version = "v1"
        elif version == 2:
            self._version = "v2c"
        if not os.path.exists(self._output_path):
            os.mkdir(self._output_path)
        self._oid_list_file = open(
            f"{self._output_path}/{self._target}_oid_list_file.txt",
            "w",
            encoding="latin1",
        )
        self._oid_writeable_list_file = open(
            f"{self._output_path}/{self._target}_oid_writeable_list_file.txt",
            "w",
            encoding="latin1",
        )
        self._snmp_set_packets_filename = (
            f"{self._output_path}/{self._target}_snmp_set_packet_list.pcap"
        )
        self._snmp_crash_packets_filename = (
            f"{self._output_path}/{self._target}_snmp_crash_packets.pcap"
        )
        self._snmp_sent_packets_filename = (
            f"{self._output_path}/"
            f"{self._target}_snmp_sent_packets_"
            f"{self._sent_packets_file_count}.pcap"
        )

    def _create_get_request(self, my_oid, include_headers: bool = True):
        get_payload = scapy.layers.snmp.SNMP(
            version=self._version,
            community=self._community,
            PDU=scapy.layers.snmp.SNMPnext(
                varbindlist=[scapy.layers.snmp.SNMPvarbind(oid=ASN1_OID(my_oid))]
            ),
        )

        if include_headers:
            get_payload = (
                scapy.layers.inet.IP(dst=self._target)
                / scapy.layers.inet.UDP(sport=161, dport=161)
                / get_payload
            )

        return get_payload

    def _create_set_request(self, varbindlist, include_headers: bool = True):
        set_payload = scapy.layers.snmp.SNMP(
            version=self._version,
            community=self._community,
            PDU=scapy.layers.snmp.SNMPset(varbindlist=[varbindlist]),
        )

        if include_headers:
            set_payload = (
                scapy.layers.inet.IP(dst=self._target)
                / scapy.layers.inet.UDP(sport=161, dport=161)
                / set_payload
            )

        return set_payload

    def _create_get_request_by_packet(self, packet):
        my_oid = packet[scapy.layers.snmp.SNMP].PDU[scapy.layers.snmp.SNMPvarbind].oid
        get_payload = copy.deepcopy(packet)
        get_payload[scapy.layers.snmp.SNMP].PDU = scapy.layers.snmp.SNMPget(
            varbindlist=[scapy.layers.snmp.SNMPvarbind(oid=my_oid)]
        )

        # fix the packet
        del get_payload[scapy.layers.inet.IP].chksum
        del get_payload[scapy.layers.inet.IP].len
        del get_payload[scapy.layers.inet.UDP].chksum
        del get_payload[scapy.layers.inet.UDP].len
        del get_payload.len
        return get_payload

    def _create_get_next_request_by_packet(self, packet):
        my_oid = packet[scapy.layers.snmp.SNMP].PDU[scapy.layers.snmp.SNMPvarbind].oid
        get_next_payload = copy.deepcopy(packet)
        get_next_payload[scapy.layers.snmp.SNMP].PDU = scapy.layers.snmp.SNMPnext(
            varbindlist=[scapy.layers.snmp.SNMPvarbind(oid=my_oid)]
        )
        # fix the packet
        del get_next_payload[scapy.layers.inet.IP].chksum
        del get_next_payload[scapy.layers.inet.IP].len
        del get_next_payload[scapy.layers.inet.UDP].chksum
        del get_next_payload[scapy.layers.inet.UDP].len
        del get_next_payload.len
        return get_next_payload

    def _create_fuzz_packet(self, packet):
        my_valtype = (
            packet[scapy.layers.snmp.SNMP].PDU[scapy.layers.snmp.SNMPvarbind].value
        )
        if isinstance(my_valtype, ASN1_Type[2][0]):
            packet[scapy.layers.snmp.SNMP].PDU[
                scapy.layers.snmp.SNMPvarbind
            ].value.val = self._get_asn_value_type(my_valtype)
        else:
            packet[scapy.layers.snmp.SNMP].PDU[
                scapy.layers.snmp.SNMPvarbind
            ].value.val = str(self._get_asn_value_type(my_valtype))

        # fix the packet
        del packet[scapy.layers.inet.IP].chksum
        del packet[scapy.layers.inet.IP].len
        del packet[scapy.layers.inet.UDP].chksum
        del packet[scapy.layers.inet.UDP].len
        del packet.len
        return packet

    def oid_scan(self, use_socket: bool = False, max_oids: int = 100):
        """
        Scan target for available oids
         * use_socket - defined to whether use scapy send, or socket send
         * max_oids - maximum number of oids to query (default: 100)
        """

        retry = 0
        while len(self.oid_list) < max_oids:
            self.logger.info(f"Querying: {self._oid}")
            get_payload = self._create_get_request(
                self._oid, include_headers=(not use_socket)
            )

            get_rsp_payload = None
            if use_socket:
                s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                s.connect((self._target, self._monitor_port))
                s.settimeout(self._timeout)
                s.send(bytes(get_payload))

                res = None
                try:
                    res = s.recv(1024)
                except Exception as exception:
                    self.logger.info(
                        f"An exception has occurred during 'get_payload' recv(): {exception}"
                    )
                    pass

                s.close()

                if res is None:
                    retry += 1

                    self.logger.info(
                        f"No response received from target (verify community name: '{self._community}') (retry #{retry})"
                    )

                    if retry > 5:
                        break

                    time.sleep(self._timeout)
                    continue

                try:
                    get_rsp_payload = (
                        scapy.layers.inet.IP(dst=self._target)
                        / scapy.layers.inet.UDP(sport=161, dport=161)
                        / scapy.layers.snmp.SNMP(_pkt=res, version=2)
                    )
                except Exception as exception:
                    self.logger.error(
                        f"Failed to handle SNMP packet:\n"
                        f"{hexdump(res, dump=True)}\n"
                        f"Exception: {exception}"
                    )
                    break
            else:
                get_rsp_payload = sr1(
                    get_payload, timeout=self._timeout, verbose=0, iface=self._nic
                )

                if get_rsp_payload is None:
                    self.logger.debug(
                        f"No response received from target (verify community name: '{self._community}') (retry #{retry})"
                    )
                    retry += 1

                    if retry > 5:
                        break

                    continue

            self.logger.debug(hexdump(get_rsp_payload, dump=True))
            self.logger.debug(get_rsp_payload.show(dump=True))

            if get_rsp_payload.getlayer("ICMP"):
                rsp_icmp = get_rsp_payload.getlayer("ICMP")
                if (
                    rsp_icmp.type == 3  # port-unreachable
                    or rsp_icmp.code == 3  # dest unreach
                ):
                    self.logger.info("Port or Destination unreachable")
                    break

                self.logger.info(
                    f"Got a ICMP packet back: {get_rsp_payload.show(dump=True)}"
                )

            retry = 0
            try:
                if (
                    self._oid
                    == get_rsp_payload[scapy.layers.snmp.SNMP]
                    .PDU[scapy.layers.snmp.SNMPvarbind]
                    .oid.val
                ):
                    self.logger.info("End of MIB")
                    break
            except Exception as exception:
                error_msg = f"Exception: {exception}"
                self.logger.error(error_msg)
                break

            value = (
                get_rsp_payload[scapy.layers.snmp.SNMP]
                .PDU[scapy.layers.snmp.SNMPvarbind]
                .value
            )

            self._oid = (
                get_rsp_payload[scapy.layers.snmp.SNMP]
                .PDU[scapy.layers.snmp.SNMPvarbind]
                .oid.val
            )
            self.logger.info(
                f"Found oid: '{self._oid}' with value '{value}' (oid #{len(self.oid_list)+1} out of {max_oids})"
            )

            oid_display = conf.mib._oidname(self._oid)
            value_type = (
                get_rsp_payload[scapy.layers.snmp.SNMP]
                .PDU[scapy.layers.snmp.SNMPvarbind]
                .value
            )

            value = (
                get_rsp_payload[scapy.layers.snmp.SNMP]
                .PDU[scapy.layers.snmp.SNMPvarbind]
                .value.val
            )

            varbindlist = get_rsp_payload[scapy.layers.snmp.SNMP].PDU[
                scapy.layers.snmp.SNMPvarbind
            ]

            # Try to see if we can 'set'
            set_payload = self._create_set_request(
                varbindlist, include_headers=(not use_socket)
            )

            set_rsp = None
            if use_socket:
                s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                s.connect((self._target, self._monitor_port))
                s.settimeout(self._timeout)
                s.send(bytes(set_payload))

                res = None
                try:
                    res = s.recv(1024)
                except Exception as exception:
                    self.logger.debug(
                        f"An exception has occurred during 'set_payload' recv(): {exception}"
                    )
                    pass

                s.close()

                if res is not None:
                    set_rsp = (
                        scapy.layers.inet.IP(dst=self._target)
                        / scapy.layers.inet.UDP(sport=161, dport=161)
                        / scapy.layers.snmp.SNMP(_pkt=res)
                    )
            else:
                set_rsp = sr1(
                    set_payload, timeout=self._timeout, verbose=0, iface=self._nic
                )

            if (
                set_rsp is not None
                and set_rsp[scapy.layers.snmp.SNMP].PDU.error.val not in snmp_error_id
            ):
                self.logger.info(f"'{self._oid}' is writeable")
                self.oid_write_list.append(
                    (oid_display, self._oid, type(value_type), value)
                )
                self.set_packets.append(set_payload)

            self.oid_list.append((oid_display, self._oid, type(value_type), value))
            # sr1 and recv already have a timeout, no need for another:
            # time.sleep(0.05)

    def set_test_case_range(self, test_case_range=None):
        if test_case_range is None:
            max_cases = len(self.set_packets)
            self._test_cases = range(max_cases)
        else:
            p_single = re.compile(r"(\d+)$")
            p_open_left = re.compile(r"-(\d+)$")
            p_open_right = re.compile(r"(\d+)-$")
            p_closed = re.compile(r"(\d+)-(\d+)$")
            open_left_found = False
            open_right_found = False
            open_end_start = None
            for entry in test_case_range.split(","):
                entry = entry.strip()

                # single number
                match = p_single.match(entry)
                if match:
                    self._test_cases.append(int(match.groups()[0]))
                    # self._list.append(int(match.groups()[0]))
                    continue

                # open left
                match = p_open_left.match(entry)
                if match:
                    if open_left_found:
                        raise Exception("You have two test ranges that start from zero")
                    open_left_found = True
                    end = int(match.groups()[0])
                    self._test_cases.extend(list(range(0, end + 1)))
                    # self._list.extend(list(range(0, end + 1)))
                    continue

                # open right
                match = p_open_right.match(entry)
                if match:
                    if open_right_found:
                        raise Exception("You have two test ranges that does not end")
                    open_right_found = True
                    open_end_start = int(match.groups()[0])
                    continue

                # closed range
                match = p_closed.match(entry)
                if match:
                    start = int(match.groups()[0])
                    end = int(match.groups()[1])
                    self._test_cases.extend(list(range(start, end + 1)))
                    continue

                # invalid expression
                raise Exception(f"Invalid range found: {entry}")
            as_set = set(self._test_cases)
            if len(as_set) < len(self._test_cases):
                raise Exception("Overlapping ranges in range list")
            self._test_cases = sorted(list(as_set))
            if (
                open_end_start
                and len(self._test_cases)
                and self._test_cases[-1] >= open_end_start
            ):
                raise Exception("Overlapping ranges in range list")
            pass

    def save_scan_result(self):
        for oid in self.oid_list:
            self._oid_list_file.write(f"{oid}\r")

        for oid in self.oid_write_list:
            self._oid_writeable_list_file.write(f"{oid}\r")

        wrpcap(self._snmp_set_packets_filename, self.set_packets)
        self._oid_writeable_list_file.close()
        self._oid_list_file.close()

    def save_fuzz_result(self):
        if len(self._sent_packets) > 0:
            wrpcap(self._snmp_sent_packets_filename, self._sent_packets)

        if len(self._crash_packets) > 0:
            wrpcap(self._snmp_crash_packets_filename, self._crash_packets)

    def _save_sent_packet(self, packet):
        self._sent_packets.append(packet)
        if len(self._sent_packets) >= 200:
            wrpcap(self._snmp_sent_packets_filename, self._sent_packets)
            self._sent_packets = []
            self._sent_packets_file_count += 1
            self._snmp_sent_packets_filename = (
                f"{self._output_path}/"
                f"{self._target}_snmp_sent_packets_"
                f"{self._sent_packets_file_count}.pcap"
            )

    def read_test_case_from_pcap(self, pcap_set_file):
        """Read from the saved pcap files the packets for fuzzing"""
        self.set_packets = rdpcap(pcap_set_file)
        return len(self.set_packets) == 0

    def _get_asn_value_type(self, value_type):
        for i in range(len(ASN1_Type)):
            if isinstance(value_type, ASN1_Type[i][0]) is True:
                return ASN1_Type[i][1]

    def _get_errror_code(self, code):
        for i in range(len(SNMP_Error_code)):
            if SNMP_Error_code[i][0] == code:
                return SNMP_Error_code[i][1]
        self.logger.error(f"Unknown Error Code: {code}")

    def _is_target_alive(self):
        """
        Check if the target is online:
        1. If we have an oid in the oid_list, try to "get" it
        2. If we don't have an oid in the oid_list, try to UDP "ping"
        """

        oid = ".1.3"

        if len(self.oid_list) > 0:
            oid = self.oid_list[0]

        failed = 0
        count = 0  # Try 2 times to "ping"
        while count < 5:
            count += 1
            self.logger.debug(
                f"Checking if {self._target} is responding to get SNMP packet (attempt #{count})"
            )

            get_payload = self._create_get_request(oid)
            get_rsp_payload = sr1(
                get_payload, timeout=self._timeout, verbose=0, iface=self._nic
            )

            if get_rsp_payload is None:
                failed += 1
                time.sleep(0.1)
                continue

            if get_rsp_payload.getlayer("ICMP"):
                failed += 1
                time.sleep(0.1)
                continue

            failed = 0
            self.logger.debug("Got a response")
            break

        return failed == 0

    def fuzz(self):
        """Fuzz a given list of packets"""
        if not self._test_cases:
            self.set_test_case_range()

        for test_case in self._test_cases:
            for i in range(self._fuzz_count):
                try:
                    # send set packet
                    set_payload = copy.deepcopy(self.set_packets[test_case])
                    set_payload = self._create_fuzz_packet(set_payload)
                    self.logger.info(
                        f"Running test case No.{test_case} {i}/{self._fuzz_count}"
                    )
                    self._save_sent_packet(set_payload)
                    set_rsp = sr1(
                        set_payload,
                        timeout=self._timeout,
                        verbose=0,
                        iface=self._nic,
                    )
                    if set_rsp is None:
                        self.logger.warning(
                            "Target did not respond with SNMP set packet in packet "
                            f"NO.{i},"
                            f"TestCase No.{test_case}"
                        )
                        if self._is_target_alive():
                            self.logger.info("Target is still alive!")
                        else:
                            self.logger.error(
                                f"Target seems to no longer respond to UDP traffic on port: {self._monitor_port}"
                            )
                            self._crash_packets.append(set_payload)
                            return
                    else:
                        self._save_sent_packet(set_rsp)
                        if set_rsp[scapy.layers.snmp.SNMP].PDU.error.val != 0:
                            error_code = self._get_errror_code(
                                set_rsp[scapy.layers.snmp.SNMP].PDU.error.val
                            )
                            self.logger.warning(
                                "Set failed with error code: "
                                f"{error_code} in packet NO.{i},"
                                f"TestCase No.{test_case}"
                            )

                    # send get packet
                    get_payload = copy.deepcopy(self.set_packets[test_case])
                    get_payload = self._create_get_request_by_packet(get_payload)
                    self._save_sent_packet(get_payload)
                    get_rsp = sr1(
                        get_payload,
                        timeout=self._timeout,
                        verbose=0,
                        iface=self._nic,
                    )
                    if get_rsp is None:
                        self.logger.warning(
                            "Target not respond with SNMP get packet in packet "
                            f"NO.{i},"
                            f"TestCase No.{test_case}"
                        )
                        if self._is_target_alive():
                            self.logger.info("Target is still alive!")
                        else:
                            self.logger.error(
                                f"Target seems to no longer respond to UDP traffic on port: {self._monitor_port}"
                            )
                            self._crash_packets.append(set_payload)
                            return
                    else:
                        self._save_sent_packet(get_rsp)
                        if get_rsp.haslayer(scapy.layers.snmp.SNMP):
                            if get_rsp[scapy.layers.snmp.SNMP].PDU.error.val != 0:
                                error_code = self._get_errror_code(
                                    get_rsp[scapy.layers.snmp.SNMP].PDU.error.val
                                )
                                self.logger.info(
                                    "Get failed with error code "
                                    f"{error_code} in packet NO.{i},"
                                    f"TestCase No.{test_case}"
                                )

                    # send get_next packet
                    get_next_payload = copy.deepcopy(self.set_packets[test_case])
                    get_next_payload = self._create_get_next_request_by_packet(
                        get_next_payload
                    )
                    self._save_sent_packet(get_next_payload)
                    get_next_rsp = sr1(
                        get_next_payload,
                        timeout=self._timeout,
                        verbose=0,
                        iface=self._nic,
                    )
                    if get_next_rsp is None:
                        self.logger.warning(
                            "Target not respond with SNMP get_next packet in packet "
                            f"NO.{i},"
                            f"TestCase No.{test_case}"
                        )
                        if self._is_target_alive():
                            self.logger.info("Target is still alive!")
                        else:
                            self.logger.error(
                                f"Target seems to no longer respond to UDP traffic on port: {self._monitor_port}"
                            )
                            self._crash_packets.append(set_payload)
                            return
                    else:
                        self._save_sent_packet(get_next_rsp)
                        if get_rsp.haslayer(scapy.layers.snmp.SNMP):
                            if get_next_rsp[scapy.layers.snmp.SNMP].PDU.error.val != 0:
                                error_code = self._get_errror_code(
                                    get_next_rsp[scapy.layers.snmp.SNMP].PDU.error.val
                                )
                                self.logger.info(
                                    "Get_next failed with error code "
                                    f"{error_code} in packet "
                                    f"NO.{i},TestCase No.{test_case}"
                                )
                except KeyboardInterrupt:
                    self.save_fuzz_result()
                    time.sleep(1)
                    return

                except:
                    self.save_fuzz_result()
                    self.logger.error(f"Unexpected error: {sys.exc_info()[0]}")
                    return
