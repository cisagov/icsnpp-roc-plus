# @TEST-DOC: Test custom TCP and UDP port registration and response-first direction inference.
#
# @TEST-EXEC: mkdir tcp_before udp_before tcp_env udp_env tcp_redef udp_redef
#
# The response-only captures must not parse before port 12345 is configured.
# @TEST-EXEC: cd tcp_before && env -u ZEEK_ROC_PLUS_PORTS zeek -C -r ${TRACES}/custom_port_12345_tcp_response.pcap ${PACKAGE}
# @TEST-EXEC: cd udp_before && env -u ZEEK_ROC_PLUS_PORTS zeek -C -r ${TRACES}/custom_port_12345_udp_response.pcap ${PACKAGE}
# @TEST-EXEC: test ! -e tcp_before/roc_plus.log
# @TEST-EXEC: test ! -e udp_before/roc_plus.log
#
# Exercise the environment-based configuration path.
# @TEST-EXEC: cd tcp_env && env ZEEK_ROC_PLUS_PORTS=12345/tcp zeek -C -r ${TRACES}/custom_port_12345_tcp_response.pcap ${PACKAGE}
# @TEST-EXEC: cd udp_env && env ZEEK_ROC_PLUS_PORTS=12345/udp zeek -C -r ${TRACES}/custom_port_12345_udp_response.pcap ${PACKAGE}
#
# Exercise site-policy redefinitions of the exported transport sets.
# @TEST-EXEC: cd tcp_redef && env -u ZEEK_ROC_PLUS_PORTS zeek -C -r ${TRACES}/custom_port_12345_tcp_response.pcap ${PACKAGE} ${DIST}/testing/files/custom-ports.zeek
# @TEST-EXEC: cd udp_redef && env -u ZEEK_ROC_PLUS_PORTS zeek -C -r ${TRACES}/custom_port_12345_udp_response.pcap ${PACKAGE} ${DIST}/testing/files/custom-ports.zeek
#
# @TEST-EXEC: zeek-cut protocol packet_type opcode < tcp_env/roc_plus.log > custom_ports.out
# @TEST-EXEC: zeek-cut protocol packet_type opcode < udp_env/roc_plus.log >> custom_ports.out
# @TEST-EXEC: zeek-cut protocol packet_type opcode < tcp_redef/roc_plus.log >> custom_ports.out
# @TEST-EXEC: zeek-cut protocol packet_type opcode < udp_redef/roc_plus.log >> custom_ports.out
# @TEST-EXEC: btest-diff custom_ports.out
