libcm4all_was_simple_0 {
        global:
		was_simple_new;
		was_simple_new_fds;
		was_simple_free;
		was_simple_accept;
		was_simple_accept_non_block;
		was_simple_control_fd;
		was_simple_get_method;
		was_simple_get_script_name;
		was_simple_get_path_info;
		was_simple_get_query_string;
		was_simple_get_header;
		was_simple_get_multi_header;
		was_simple_get_header_iterator;
		was_simple_get_remote_host;
		was_simple_get_parameter;
		was_simple_get_parameter_iterator;
		was_simple_has_body;
		was_simple_input_poll;
		was_simple_input_fd;
		was_simple_received;
		was_simple_read;
		was_simple_input_remaining;
		was_simple_input_close;
		was_simple_status;
		was_simple_set_header;
		was_simple_set_header_n;
		was_simple_copy_all_headers;
		was_simple_set_length;
		was_simple_output_begin;
		was_simple_output_poll;
		was_simple_output_fd;
		was_simple_sent;
		was_simple_write;
		was_simple_puts;
		was_simple_printf;
		was_simple_splice;
		was_simple_end;
		was_simple_abort;
		was_simple_iterator_free;
		was_simple_iterator_next;
		was_simple_want_metrics;
		was_simple_metric;

        local:
                *;
};

libcm4all_was_simple_0b {
        global:
		was_simple_splice_all;
};

libcm4all_was_multi_0 {
        global:
		was_multi_new;
		was_multi_free;
		was_multi_fd;
		was_multi_accept_simple;
};
