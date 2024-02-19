#!/usr/bin/python3

from snmp_set_fuzz import *

target = "192.168.8.222"
port = 161
count = 10
nic = conf.route.route(target)[0]
Target = SnmpTarget(
    name="test",
    community="public",
    monitor_port=port,
    oid=".1.3",
    version=2,
    target=target,
    nic=nic,
    fuzz_count=count,
)
Target.oid_scan()
