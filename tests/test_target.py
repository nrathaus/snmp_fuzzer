#!/usr/bin/python3

import logging
from snmp_set_fuzz import *


target = "192.168.8.222"
port = 161
count = 10
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
    fuzz_count=count,
    logger=logger,
)
Target.oid_scan()
