# ICSNPP-ROC-PLUS
Industrial Control Systems Network Protocol Parsers (ICSNPP) - Emerson ROC Plus

## Overview
ICSNPP-ROC-PLUS is a Spicy based Zeek plugin for parsing and logging fields within the ROC Plus protocol.

ROC Plus is a protocol created by Emerson for communication between Emerson devices in industrial automation systems. It is widely used in industrial applications such as oil and gas operations.

This parser targets the ROC Plus commands specified in the publicly available 2022 version of the spec.

## Installation (via zkg)

### Package Manager
This script is available as a package for [Zeek Package Manager](https://docs.zeek.org/projects/package-manager/en/stable/index.html). Zeek includes Spicy support by default as of [v6.0.0](https://github.com/zeek/zeek/releases/tag/v6.0.0).

```bash
$ zkg refresh
$ zkg install icsnpp-roc-plus
```

If this package is installed from ZKG, it will be added to the available plugins. This can be tested by running zeek -NN. If installed correctly, users will see `ANALYZER_ROC_PLUS_TCP` and `ANALYZER_ROC_PLUS_UDP` under the list of `Zeek::Spicy` analyzers.

If users have ZKG configured to load packages (see `@load packages` in the [ZKG Quickstart Guide](https://docs.zeek.org/projects/package-manager/en/stable/quickstart.html)), this plugin and these scripts will automatically be loaded and ready to go.

## Installation (via git clone)

```bash
git clone https://github.com/cisagov/icsnpp-roc-plus.git
cd icsnpp-roc-plus
mkdir build && cd build && cmake .. && make && cd ..
```

From here you can install the locally built files through `zkg install ./icsnpp-roc-plus` and run it like you would normally.

Or you can manually run the parser without installing it: `zeek ./build/roc_plus.hlto ./scripts/__load__.zeek  -Cr <pcap>`


## Log Files
The ROC Plus analyzer generates several log files based on the type of ROC Plus traffic observed. 

## Main ROC Plus Log (roc_plus.log)

This log file contains the core fields for all ROC Plus protocol traffic.

| Field | Type | Description |
|-------|------|-------------|
| ts | time | Timestamp |
| uid | string | Unique identifier for the connection |
| id | conn_id | Connection identifier |
| protocol | transport_proto | Transport protocol |
| roc_plus_link_id | string | Unique identifier for the ROC Plus connection |
| packet_type | string | Type of packet (e.g., "REQUEST", "RESPONSE", "UNKNOWN") |
| destination_unit | count | Destination unit address |
| destination_group | count | Destination group address |
| source_unit | count | Source unit address |
| source_group | count | Source group address |
| opcode | string | Operation code for the ROC Plus command |
| data_length | count | Length of the following data portion in bytes (not including this byte, the CRC bytes, or the error bytes) |
| lsb_crc | count | Least significant byte of the CRC checksum |
| msb_crc | count | Most significant byte of the CRC checksum |
| error_code | vector of string | Error codes returned in the response (if any) |
| error_offset | vector of count | Offsets where errors occurred (if any) |

## Additional ROC Plus Logs

### System Configuration (roc_plus_sys_cfg.log)

This log captures system configuration information for ROC Plus devices and logs it to `roc_plus_sys_cfg.log`.

* See the `ROC_PLUS::roc_plus_sys_cfg_log: record` in file `scripts/roc_plus_types.zeek` for a list of the fields logged.
* This log is associated with ROC Plus Opcode 6 (SENDS ROC800 CONFIGURATION).

### Historical Min/Max Values (roc_plus_historical_min_max_vals.log)

This log captures the historical minimum and maximum values for points and logs it to `roc_plus_historical_min_max_vals.log`.

* See the `ROC_PLUS::roc_plus_historical_min_max_vals_log: record` in file `scripts/roc_plus_types.zeek` for a list of the fields logged.
* This log is associated with ROC Plus Opcode 105 (SENDS HISTORY POINT DEFINITION, MIN/MAX DATA, AND CURRENT VALUES).

### Real-time Clock (roc_plus_realtime_clock.log)

This log captures real-time clock data and logs it to `roc_plus_realtime_clock.log`.

* See the `ROC_PLUS::roc_plus_realtime_clock_log: record` in file `scripts/roc_plus_types.zeek` for a list of the fields logged.
* This log is associated with ROC Plus Opcodes 7 (READ REAL-TIME CLOCK) and 8 (SET REAL-TIME CLOCK).

### Configurable Opcode (roc_plus_configurable_opcode.log)

This log captures configurable opcode point data and logs it to `roc_plus_configurable_opcode.log`.

* See the `ROC_PLUS::roc_plus_configurable_opcode_log: record` in file `scripts/roc_plus_types.zeek` for a list of the fields logged.
* This log is associated with ROC Plus Opcodes 10 (READ CONFIGURABLE OPCODE POINT DATA) and 11 (WRITE CONFIGURABLE OPCODE POINT DATA).

### Login (roc_plus_login.log)

This log captures login information and logs it to `roc_plus_login.log`.

* See the `ROC_PLUS::roc_plus_login_log: record` in file `scripts/roc_plus_types.zeek` for a list of the fields logged.
* This log is associated with ROC Plus Opcode 17 (LOGIN REQUEST).

### Store and Forward (roc_plus_store_and_forward.log)

This log captures store and forward messaging data and logs it to `roc_plus_store_and_forward.log`.

* See the `ROC_PLUS::roc_plus_store_and_forward_log: record` in file `scripts/roc_plus_types.zeek` for a list of the fields logged.
* This log is associated with ROC Plus Opcode 24 (STORE AND FORWARD MESSAGES).

### Data Request (roc_plus_data_request.log)

This log captures various data request operations and logs it to `roc_plus_data_request.log`.

* See the `ROC_PLUS::roc_plus_data_request_log: record` in file `scripts/roc_plus_types.zeek` for a list of the fields logged.
* This log is associated with ROC Plus Opcodes:
  - 50 (I/O DATA REQUEST)
  - 108 (HISTORICAL DATABASE READ)
  - 118 (READ ALARM LOG)
  - 119 (READ EVENT LOG)
  - 137 (READ HISTORY SETUP)
  - 138 (READ HISTORY POINT INFO)
  - 224 (SRBX Signal)
  - 225 (SRBX Acknowledgement)

### User Defined Info (roc_plus_user_defined_info.log)

This log captures user-defined information and logs it to `roc_plus_user_defined_info.log`.

* See the `ROC_PLUS::roc_plus_user_defined_info_log: record` in file `scripts/roc_plus_types.zeek` for a list of the fields logged.
* This log is associated with ROC Plus Opcode 100 (READ USER DEFINED POINT TYPES).

### History Point Data (roc_plus_history_point_data.log)

This log captures history information data and logs it to `roc_plus_history_point_data.log`.

* See the `ROC_PLUS::roc_plus_history_point_data_log: record` in file `scripts/roc_plus_types.zeek` for a list of the fields logged.
* This log is associated with ROC Plus Opcodes 135 (SINGLE HISTORY POINT DATA) and 136 (MULTIPLE HISTORY POINT DATA).

### History Information (roc_plus_history_information.log)

This log captures history point data and logs it to `roc_plus_history_information.log`.

* See the `ROC_PLUS::roc_plus_history_information_log: record` in file `scripts/roc_plus_types.zeek` for a list of the fields logged.
* This log is associated with ROC Plus Opcode 139 (READ HISTORY INFORMATION).

### Time Period History Points (roc_plus_time_period_history_points.log)

This log captures time period history points data and logs it to `roc_plus_time_period_history_points.log`.

* See the `ROC_PLUS::roc_plus_time_period_history_points_log: record` in file `scripts/roc_plus_types.zeek` for a list of the fields logged.
* This log is associated with ROC Plus Opcode 139 (READ HISTORY INFORMATION).

### Single Point Parameters (roc_plus_single_point_parameters.log)

This log captures single point parameter data and logs it to `roc_plus_single_point_parameters.log`.

* See the `ROC_PLUS::roc_plus_single_point_parameters_log: record` in file `scripts/roc_plus_types.zeek` for a list of the fields logged.
* This log is associated with ROC Plus Opcodes 166 (WRITE SINGLE POINT PARAMETERS) and 167 (READ SINGLE POINT PARAMETERS).

### File Transfer (roc_plus_file_transfer.log)

This log captures file transfer operations and logs it to `roc_plus_file_transfer.log`.

* See the `ROC_PLUS::roc_plus_file_transfer_log: record` in file `scripts/roc_plus_types.zeek` for a list of the fields logged.
* This log is associated with ROC Plus Opcode 203 (GENERAL FILE TRANSFER).

### Peer-to-Peer Network Messages (roc_plus_peer_to_peer_network_messages.log)

This log captures peer-to-peer network message data and logs it to `roc_plus_peer_to_peer_network_messages.log`.

* See the `ROC_PLUS::roc_plus_peer_to_peer_network_messages_log: record` in file `scripts/roc_plus_types.zeek` for a list of the fields logged.
* This log is associated with ROC Plus Opcode 205 (PEER TO PEER NETWORK MESSAGES).
* NOTE: as of right now these opcodes are not parsed so this log is not currently utilized.

### Transaction History (roc_plus_transaction_history.log)

This log captures transaction history data and logs it to `roc_plus_transaction_history.log`.

* See the `ROC_PLUS::roc_plus_transaction_history_log: record` in file `scripts/roc_plus_types.zeek` for a list of the fields logged.
* This log is associated with ROC Plus Opcode 206 (TRANSACTION HISTORY).

### Unknown Data (roc_plus_unknown_data.log)

This log captures raw data from unrecognized or unparseable ROC Plus opcodes and logs it to `roc_plus_unknown_data.log`.

* See the `ROC_PLUS::roc_plus_unknown_data_log: record` in file `scripts/roc_plus_types.zeek` for a list of the fields logged.
* This log is used for any opcode that the parser doesn't specifically handle.

## ICSNPP Packages

All ICSNPP Packages:

* [ICSNPP](https://github.com/cisagov/icsnpp)

### Other Software
Idaho National Laboratory is a national research facility with a focus on development of software and toolchains to improve the security of criticial infrastructure environments around the world. Please review our other software and scientific offerings at:

[Primary Technology Overview Page](https://www.inl.gov/science-technology-overview)

[Supported Open Source Software](https://github.com/idaholab)

[Raw Experiment Open Source Software](https://github.com/IdahoLabResearch)

### License

Copyright 2025 Battelle Energy Alliance, LLC. Released under the terms of the 3-Clause BSD License (see [`LICENSE`](./LICENSE)).