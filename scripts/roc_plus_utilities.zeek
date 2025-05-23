module ROC_PLUS;

    function set_roc_plus_log(c: connection): connection {
        if ( ! c?$roc_plus_log )
            c$roc_plus_log = roc_plus_log(
                $ts=network_time(),
                $uid=c$uid,
                $id=c$id,
                $protocol=get_conn_transport_proto(c$id));

        return c;
    }

    function set_sys_cfg_log(c: connection): connection {
        if ( ! c?$roc_plus_sys_cfg_log )
            c$roc_plus_sys_cfg_log = roc_plus_sys_cfg_log(
                $ts=network_time(),
                $uid=c$uid,
                $id=c$id);

        return c;
    }

    function set_historical_min_max_vals_log(c: connection): connection {
        if ( ! c?$roc_plus_historical_min_max_vals_log )
            c$roc_plus_historical_min_max_vals_log = roc_plus_historical_min_max_vals_log(
                $ts=network_time(),
                $uid=c$uid,
                $id=c$id);

        return c;
    }

    function set_realtime_clock_log(c: connection): connection {
        if ( ! c?$roc_plus_realtime_clock_log )
            c$roc_plus_realtime_clock_log = roc_plus_realtime_clock_log(
                $ts=network_time(),
                $uid=c$uid,
                $id=c$id);

        return c;
    }

    function set_configurable_opcode_log(c: connection): connection {
        if ( ! c?$roc_plus_configurable_opcode_log )
            c$roc_plus_configurable_opcode_log = roc_plus_configurable_opcode_log(
                $ts=network_time(),
                $uid=c$uid,
                $id=c$id);

        return c;
    }

    function set_login_log(c: connection): connection {
        if ( ! c?$roc_plus_login_log )
            c$roc_plus_login_log = roc_plus_login_log(
                $ts=network_time(),
                $uid=c$uid,
                $id=c$id);

        return c;
    }

    function set_store_and_forward_log(c: connection): connection {
        if ( ! c?$roc_plus_store_and_forward_log )
            c$roc_plus_store_and_forward_log = roc_plus_store_and_forward_log(
                $ts=network_time(),
                $uid=c$uid,
                $id=c$id);

        return c;
    }

    function set_data_request_log(c: connection): connection {
        if ( ! c?$roc_plus_data_request_log )
            c$roc_plus_data_request_log = roc_plus_data_request_log(
                $ts=network_time(),
                $uid=c$uid,
                $id=c$id);

        return c;
    }

    function set_user_defined_info_log(c: connection): connection {
        if ( ! c?$roc_plus_user_defined_info_log )
            c$roc_plus_user_defined_info_log = roc_plus_user_defined_info_log(
                $ts=network_time(),
                $uid=c$uid,
                $id=c$id);

        return c;
    }

    function set_single_point_parameters_log(c: connection): connection {
        if ( ! c?$roc_plus_single_point_parameters_log )
            c$roc_plus_single_point_parameters_log = roc_plus_single_point_parameters_log(
                $ts=network_time(),
                $uid=c$uid,
                $id=c$id);

        return c;
    }

    function set_file_transfer_log(c: connection): connection {
        if ( ! c?$roc_plus_file_transfer_log )
            c$roc_plus_file_transfer_log = roc_plus_file_transfer_log(
                $ts=network_time(),
                $uid=c$uid,
                $id=c$id);

        return c;
    }

    function set_transaction_history_log(c: connection): connection {
        if ( ! c?$roc_plus_transaction_history_log )
            c$roc_plus_transaction_history_log = roc_plus_transaction_history_log(
                $ts=network_time(),
                $uid=c$uid,
                $id=c$id);

        return c;
    }

    function set_unknown_data_log(c: connection): connection {
        if ( ! c?$roc_plus_unknown_data_log )
            c$roc_plus_unknown_data_log = roc_plus_unknown_data_log(
                $ts=network_time(),
                $uid=c$uid,
                $id=c$id);

        return c;
    }

    function set_history_point_data_log(c: connection): connection {
        if ( ! c?$roc_plus_history_point_data_log )
            c$roc_plus_history_point_data_log = roc_plus_history_point_data_log(
                $ts=network_time(),
                $uid=c$uid,
                $id=c$id);

        return c;
    }

    function set_history_information_log(c: connection): connection {
        if ( ! c?$roc_plus_history_information_log )
            c$roc_plus_history_information_log = roc_plus_history_information_log(
                $ts=network_time(),
                $uid=c$uid,
                $id=c$id);

        return c;
    }

    function set_time_period_history_points_log(c: connection): connection {
        if ( ! c?$roc_plus_time_period_history_points_log )
            c$roc_plus_time_period_history_points_log = roc_plus_time_period_history_points_log(
                $ts=network_time(),
                $uid=c$uid,
                $id=c$id);

        return c;
    }

    function set_peer_to_peer_network_messages_log(c: connection): connection {
        if ( ! c?$roc_plus_peer_to_peer_network_messages_log )
            c$roc_plus_peer_to_peer_network_messages_log = roc_plus_peer_to_peer_network_messages_log(
                $ts=network_time(),
                $uid=c$uid,
                $id=c$id);

        return c;
    }

