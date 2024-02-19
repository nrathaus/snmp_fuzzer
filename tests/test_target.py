#!/usr/bin/python3

import logging
from snmp_set_fuzz import *


target = "192.168.8.222"
port = 161
nic = conf.route.route(target)[0]
logger = BaseTarget.get_logger()
logger.setLevel(logging.INFO)

Target = SnmpTarget(
    name="test",
    community="public",
    monitor_port=port,
    oid=".1.3",
    version=2,
    target=target,
    nic=nic,
    logger=logger,
)

Target.oid_scan(max_oids=10)

Target.save_scan_result()

Target.read_test_case_from_pcap(
    f"./output/{target}_snmp_set_packet_list.pcap",
)

Target._fuzz_count = 100
Target.fuzz()
