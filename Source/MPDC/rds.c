#include "rds.h"
#include "server.h"
#include "certificate.h"
#include "commands.h"
#include "help.h"
#include "menu.h"
#include "mpdc.h"
#include "network.h"
#include "resources.h"
#include "topology.h"
#include "acp.h"
#include "async.h"
#include "consoleutils.h"
#include "fileutils.h"
#include "folderutils.h"
#include "memutils.h"
#include "socketserver.h"
#include "stringutils.h"
#include "timerex.h"
#include "timestamp.h"

/** \cond */
typedef struct rds_receive_state
{
	qsc_socket csock;
} rds_receive_state;
/** \endcond */

static mpdc_server_application_state m_rds_application_state = { 0 };
static mpdc_server_server_loop_status m_rds_command_loop_status;
static mpdc_server_server_loop_status m_rds_server_loop_status;
static uint64_t m_rds_idle_timer;

/* rds functions */

static bool rds_certificate_export(const char* dpath)
{
	MPDC_ASSERT(dpath != NULL);

	bool res;

	res = mpdc_server_root_certificate_export(&m_rds_application_state, dpath);

	return res;
}

static bool rds_server_load_root(void)
{
	bool res;

	res = false;

	/* load the root certificate */
	if (mpdc_server_topology_root_fetch(&m_rds_application_state, &m_rds_application_state.root) == true)
	{
		res = mpdc_topology_node_verify_root(&m_rds_application_state.tlist, &m_rds_application_state.root);
	}

	return res;
}

static bool rds_certificate_generate_root(const char* sprd)
{
	MPDC_ASSERT(sprd != NULL); 

	uint64_t period;
	bool res;

	res = false;

	/* generate a certificate and write to file */
	if (qsc_stringutils_is_numeric(sprd, qsc_stringutils_string_size(sprd)) == true)
	{
		char fpath[MPDC_STORAGE_PATH_MAX] = { 0 };

		mpdc_server_certificate_path(&m_rds_application_state, fpath, sizeof(fpath), m_rds_application_state.issuer);
		period = qsc_stringutils_string_to_int(sprd);
		period *= MPDC_PERIOD_DAY_TO_SECONDS;

		if (period >= MPDC_CERTIFICATE_MINIMUM_PERIOD || period <= MPDC_CERTIFICATE_MAXIMUM_PERIOD)
		{
			if (qsc_fileutils_exists(fpath) == true)
			{
				/* file exists, overwrite challenge */
				if (mpdc_menu_print_predefined_message_confirm(mpdc_application_generate_key_overwrite, m_rds_application_state.mode, m_rds_application_state.hostname) == true)
				{
					/* remove the node entry */
					mpdc_topology_node_remove(&m_rds_application_state.tlist, m_rds_application_state.root.serial);
					/* delete the original */
					qsc_fileutils_delete(fpath);
					/* create the certificate and copy the signing key to state */
					mpdc_server_root_certificate_generate(&m_rds_application_state, &m_rds_application_state.root, period);
					/* write the certificate to file */
					mpdc_server_root_certificate_store(&m_rds_application_state, &m_rds_application_state.root);
					/* store the state */
					res = mpdc_server_state_store(&m_rds_application_state);
					res = rds_server_load_root();
				}
				else
				{
					mpdc_menu_print_predefined_message(mpdc_application_operation_aborted, m_rds_application_state.mode, m_rds_application_state.hostname);
					res = false;
				}
			}
			else
			{
				mpdc_server_root_certificate_generate(&m_rds_application_state, &m_rds_application_state.root, period);
				mpdc_server_root_certificate_store(&m_rds_application_state, &m_rds_application_state.root);
				res = mpdc_server_state_store(&m_rds_application_state);
				res = rds_server_load_root();
			}
		}
		else
		{
			mpdc_menu_print_predefined_message(mpdc_application_invalid_input, m_rds_application_state.mode, m_rds_application_state.hostname);
		}
	}

	return res;
}

static bool rds_certificate_sign(const char* fpath)
{
	MPDC_ASSERT(fpath != NULL);

	bool res;

	res = false;

	if (qsc_fileutils_exists(fpath) == true && 
		qsc_stringutils_string_contains(fpath, MPDC_CERTIFICATE_CHILD_EXTENSION) == true)
	{
		mpdc_child_certificate child = { 0 };

		if (mpdc_certificate_child_file_to_struct(fpath, &child) == true)
		{
			if (mpdc_certificate_root_sign(&child, &m_rds_application_state.root, m_rds_application_state.sigkey) == MPDC_CERTIFICATE_SIGNED_HASH_SIZE)
			{
				res = mpdc_certificate_child_struct_to_file(fpath, &child);
			}
		}
	}

	return res;
}

static mpdc_protocol_errors dla_remote_signing_response(qsc_socket* csock, const mpdc_network_packet* packetin)
{
	MPDC_ASSERT(csock != NULL);
	MPDC_ASSERT(packetin != NULL);

	mpdc_topology_node_state dnode = { 0 };
	mpdc_protocol_errors merr;

	if (m_rds_application_state.joined == true)
	{
		if (mpdc_topology_node_find(&m_rds_application_state.tlist, &dnode, m_rds_application_state.dla.serial) == true)
		{
			if (qsc_memutils_are_equal((const uint8_t*)dnode.address, (const uint8_t*)csock->address, MPDC_CERTIFICATE_ADDRESS_SIZE) == true)
			{
				mpdc_child_certificate rcert = { 0 };

				mpdc_network_remote_signing_response_state rsr = {
					.csock = csock,
					.dcert = &m_rds_application_state.dla,
					.rcert = &rcert,
					.root = &m_rds_application_state.root,
					.sigkey = m_rds_application_state.sigkey
				};

				merr = mpdc_network_remote_signing_response(&rsr, packetin);
			}
			else
			{
				merr = mpdc_protocol_error_invalid_request;
			}
		}
		else
		{
			merr = mpdc_protocol_error_node_not_found;
		}
	}
	else
	{
		merr = mpdc_protocol_error_certificate_not_found;
	}

	return merr;
}

static void rds_server_dispose(void)
{
	mpdc_server_state_initialize(&m_rds_application_state, mpdc_network_designation_rds);
	m_rds_command_loop_status = mpdc_server_loop_status_stopped;
	m_rds_server_loop_status = mpdc_server_loop_status_stopped;
	m_rds_idle_timer = 0U;
}

static bool rds_server_load_dla(void)
{
	bool res;

	res = false;

	/* load the dla certificate */
	if (mpdc_server_topology_dla_fetch(&m_rds_application_state, &m_rds_application_state.dla) == true)
	{
		/* check the dla certificate structure */
		if (mpdc_certificate_child_is_valid(&m_rds_application_state.dla) == true)
		{
			/* verify the root signature */
			if (mpdc_certificate_root_signature_verify(&m_rds_application_state.dla, &m_rds_application_state.root) == true)
			{
				/* verify a hash of the certificate against the hash stored on the topological node */
				res = mpdc_topology_node_verify_dla(&m_rds_application_state.tlist, &m_rds_application_state.dla);
			}
		}
	}

	return res;
}

static bool rds_server_dla_dialogue(void)
{
	char cmsg[MPDC_STORAGE_PATH_MAX] = { 0 };
	char fpath[MPDC_STORAGE_PATH_MAX] = { 0 };
	size_t slen;
	uint8_t rctr;
	bool res;

	res = false;
	rctr = 0U;

	while (res == false)
	{
		++rctr;

		if (rctr > 3U)
		{
			break;
		}

		mpdc_menu_print_predefined_message(mpdc_application_dla_certificate_path_success, mpdc_console_mode_server, m_rds_application_state.hostname);
		mpdc_menu_print_prompt(mpdc_console_mode_server, m_rds_application_state.hostname);
		slen = qsc_consoleutils_get_line(cmsg, sizeof(cmsg)) - 1U;

		if (slen >= MPDC_STORAGE_FILEPATH_MIN && 
			slen <= MPDC_STORAGE_FILEPATH_MAX &&
			qsc_fileutils_exists(cmsg) == true &&
			qsc_stringutils_string_contains(cmsg, MPDC_CERTIFICATE_CHILD_EXTENSION))
		{
			mpdc_child_certificate ccert = { 0 };

			if (mpdc_certificate_child_file_to_struct(cmsg, &ccert) == true)
			{
				if (mpdc_certificate_child_is_valid(&ccert) == true && 
					mpdc_certificate_root_signature_verify(&ccert, &m_rds_application_state.root) == true)
				{
					/* get the DLA ip address */
					qsc_memutils_clear(cmsg, sizeof(cmsg));
					mpdc_menu_print_predefined_message(mpdc_application_dla_certificate_address_challenge, mpdc_console_mode_server, m_rds_application_state.hostname);
					mpdc_menu_print_prompt(mpdc_console_mode_server, m_rds_application_state.hostname);
					slen = qsc_consoleutils_get_line(cmsg, sizeof(cmsg)) - 1U;

					if (slen >= QSC_IPINFO_IPV4_MINLEN)
					{
#if defined(MPDC_NETWORK_PROTOCOL_IPV6)
						qsc_ipinfo_ipv6_address tadd;

						tadd = qsc_ipinfo_ipv6_address_from_string(cmsg);

						if (qsc_ipinfo_ipv6_address_is_valid(&tadd) == true)
						{
#else
						qsc_ipinfo_ipv4_address tadd;

						tadd = qsc_ipinfo_ipv4_address_from_string(cmsg);

						if (qsc_ipinfo_ipv4_address_is_valid(&tadd) == true)
						{
#endif
							mpdc_topology_node_state rnode = { 0 };

							/* add the node to the topology */
							mpdc_topology_child_register(&m_rds_application_state.tlist, &ccert, cmsg);
							mpdc_server_topology_to_file(&m_rds_application_state);

							if (mpdc_topology_node_find(&m_rds_application_state.tlist, &rnode, ccert.serial) == true)
							{
								/* copy the certificate to file */
								mpdc_server_certificate_path(&m_rds_application_state, fpath, sizeof(fpath), rnode.issuer);

								if (mpdc_certificate_child_struct_to_file(fpath, &ccert) == true)
								{
									/* copy certificate to state */
									mpdc_certificate_child_copy(&m_rds_application_state.dla, &ccert);
									m_rds_application_state.joined = true;
									/* store the state */
									res = mpdc_server_state_store(&m_rds_application_state);
									break;
								}
							}
						}
					}
				}
				else
				{
					mpdc_menu_print_predefined_message(mpdc_application_dla_certificate_path_failure, mpdc_console_mode_server, m_rds_application_state.hostname);
				}
			}
			else
			{
				mpdc_menu_print_predefined_message(mpdc_application_certificate_not_found, mpdc_console_mode_server, m_rds_application_state.hostname);
			}
		}
		else
		{
			mpdc_menu_print_predefined_message(mpdc_application_certificate_not_found, mpdc_console_mode_server, m_rds_application_state.hostname);
		}
	}

	return res;
}

static void rds_receive_loop(void* ras)
{
	MPDC_ASSERT(ras != NULL);

	mpdc_network_packet pkt = { 0 };
	uint8_t* buff;
	rds_receive_state* pras;
	const char* cmsg;
	size_t mlen;
	size_t plen;
	mpdc_protocol_errors merr;

	merr = mpdc_protocol_error_none;

	if (ras != NULL)
	{
		pras = (rds_receive_state*)ras;
		buff = (uint8_t*)qsc_memutils_malloc(QSC_SOCKET_TERMINATOR_SIZE);

		if (buff != NULL)
		{
			uint8_t hdr[MPDC_PACKET_HEADER_SIZE] = { 0U };

			mlen = 0U;
			plen = qsc_socket_peek(&pras->csock, hdr, MPDC_PACKET_HEADER_SIZE);

			if (plen == MPDC_PACKET_HEADER_SIZE)
			{
				mpdc_packet_header_deserialize(hdr, &pkt);

				if (pkt.msglen > 0 && pkt.msglen <= MPDC_MESSAGE_MAX_SIZE)
				{
					plen = pkt.msglen + MPDC_PACKET_HEADER_SIZE;
					buff = (uint8_t*)qsc_memutils_realloc(buff, plen);

					if (buff != NULL)
					{
						qsc_memutils_clear(buff, plen);
						mlen = qsc_socket_receive(&pras->csock, buff, plen, qsc_socket_receive_flag_wait_all);
					}
					else
					{
						merr = mpdc_protocol_error_memory_allocation;
						mpdc_server_log_write_message(&m_rds_application_state, mpdc_application_log_allocation_failure, (const char*)pras->csock.address, QSC_SOCKET_ADDRESS_MAX_SIZE);
					}
				}
				else
				{
					merr = mpdc_protocol_error_invalid_request;
					mpdc_server_log_write_message(&m_rds_application_state, mpdc_application_log_receive_failure, (const char*)pras->csock.address, QSC_SOCKET_ADDRESS_MAX_SIZE);
				}

				if (mlen > 0U)
				{
					pkt.pmessage = buff + MPDC_PACKET_HEADER_SIZE;

					if (pkt.flag == mpdc_network_flag_network_remote_signing_request)
					{
						merr = dla_remote_signing_response(&pras->csock, &pkt);

						if (merr == mpdc_protocol_error_none)
						{
							mpdc_server_log_write_message(&m_rds_application_state, mpdc_application_log_remote_signing_success, (const char*)pras->csock.address, QSC_SOCKET_ADDRESS_MAX_SIZE);
						}
						else
						{
							cmsg = mpdc_protocol_error_to_string(merr);

							if (cmsg != NULL)
							{
								mpdc_logger_write_time_stamped_message(m_rds_application_state.logpath, cmsg, qsc_stringutils_string_size(cmsg));
							}

							mpdc_server_log_write_message(&m_rds_application_state, mpdc_application_log_remote_signing_failure, (const char*)pras->csock.address, QSC_SOCKET_ADDRESS_MAX_SIZE);
						}
					}
					else if (pkt.flag == mpdc_network_flag_system_error_condition)
					{
						/* log the error condition */
						cmsg = mpdc_protocol_error_to_string((mpdc_protocol_errors)pkt.pmessage[0U]);

						if (cmsg != NULL)
						{
							mpdc_logger_write_time_stamped_message(m_rds_application_state.logpath, cmsg, qsc_stringutils_string_size(cmsg));
						}

						mpdc_server_log_write_message(&m_rds_application_state, mpdc_application_log_remote_reported_error, (const char*)pras->csock.address, QSC_SOCKET_ADDRESS_MAX_SIZE);
					}
					else
					{
						qsc_socket_exceptions err = qsc_socket_get_last_error();

						if (err != qsc_socket_exception_success)
						{
							/* fatal socket errors */
							if (err == qsc_socket_exception_circuit_reset ||
								err == qsc_socket_exception_circuit_terminated ||
								err == qsc_socket_exception_circuit_timeout ||
								err == qsc_socket_exception_dropped_connection ||
								err == qsc_socket_exception_network_failure ||
								err == qsc_socket_exception_shut_down)
							{
								mpdc_server_log_write_message(&m_rds_application_state, mpdc_application_log_connection_terminated, (const char*)pras->csock.address, QSC_SOCKET_ADDRESS_MAX_SIZE);
							}
						}
						else
						{
							mpdc_network_send_error(&pras->csock, mpdc_protocol_error_invalid_request);
							mpdc_server_log_write_message(&m_rds_application_state, mpdc_application_log_remote_invalid_request, (const char*)pras->csock.address, QSC_SOCKET_ADDRESS_MAX_SIZE);
						}
					}
				}
			}

			qsc_memutils_alloc_free(buff);
		}

		/* close the connection and dispose of the socket */
		mpdc_network_socket_dispose(&pras->csock);

		/* free the socket from memory */
		qsc_memutils_alloc_free(pras);
		pras = NULL;
	}
}

#if defined(MPDC_NETWORK_PROTOCOL_IPV6)

static void rds_ipv6_server_start(void)
{
	qsc_socket lsock = { 0 };
	qsc_ipinfo_ipv6_address addt = { 0 };
	qsc_socket_exceptions serr;

	addt = qsc_ipinfo_ipv6_address_from_string(m_rds_application_state.localip);

	if (qsc_ipinfo_ipv6_address_is_valid(&addt) == true)
	{
		qsc_socket_server_initialize(&lsock);
		serr = qsc_socket_create(&lsock, qsc_socket_address_family_ipv6, qsc_socket_transport_stream, qsc_socket_protocol_tcp);

		if (serr == qsc_socket_exception_success)
		{
			serr = qsc_socket_bind_ipv6(&lsock, &addt, MPDC_APPLICATION_RDS_PORT);

			if (serr == qsc_socket_exception_success)
			{
				serr = qsc_socket_listen(&lsock, QSC_SOCKET_SERVER_LISTEN_BACKLOG);

				if (serr == qsc_socket_exception_success)
				{
					while (true)
					{
						rds_receive_state* ras;

						ras = (rds_receive_state*)qsc_memutils_malloc(sizeof(rds_receive_state));

						if (ras != NULL)
						{
							qsc_memutils_clear(&ras->csock, sizeof(qsc_socket));

							if (serr == qsc_socket_exception_success)
							{
								serr = qsc_socket_accept(&lsock, &ras->csock);
							}
							else
							{
								/* free the resources if connect fails */
								qsc_memutils_alloc_free(ras);
								mpdc_server_log_write_message(&m_rds_application_state, mpdc_application_log_allocation_failure, (const char*)lsock.address, QSC_SOCKET_ADDRESS_MAX_SIZE);
							}

							if (serr == qsc_socket_exception_success)
							{
								qsc_async_thread_create(&rds_receive_loop, ras);
							}
							else
							{
								/* free the resources if connect fails */
								qsc_memutils_alloc_free(ras);
								mpdc_server_log_write_message(&m_rds_application_state, mpdc_application_log_allocation_failure, (const char*)lsock.address, QSC_SOCKET_ADDRESS_MAX_SIZE);
							}
						}
						else
						{
							/* exit on memory allocation failure */
							break;
						}
					};
				}
			}
		}
	}
}

#else

static void rds_ipv4_server_start(void)
{
	qsc_socket lsock = { 0 };
	qsc_ipinfo_ipv4_address addt = { 0 };
	qsc_socket_exceptions serr;

	addt = qsc_ipinfo_ipv4_address_from_string(m_rds_application_state.localip);

	if (qsc_ipinfo_ipv4_address_is_valid(&addt) == true)
	{
		qsc_socket_server_initialize(&lsock);
		serr = qsc_socket_create(&lsock, qsc_socket_address_family_ipv4, qsc_socket_transport_stream, qsc_socket_protocol_tcp);

		if (serr == qsc_socket_exception_success)
		{
			serr = qsc_socket_bind_ipv4(&lsock, &addt, MPDC_APPLICATION_RDS_PORT);

			if (serr == qsc_socket_exception_success)
			{
				serr = qsc_socket_listen(&lsock, QSC_SOCKET_SERVER_LISTEN_BACKLOG);

				if (serr == qsc_socket_exception_success)
				{
					while (true)
					{
						rds_receive_state* ras;

						ras = (rds_receive_state*)qsc_memutils_malloc(sizeof(rds_receive_state));

						if (ras != NULL)
						{
							qsc_memutils_clear(&ras->csock, sizeof(qsc_socket));

							if (serr == qsc_socket_exception_success)
							{
								serr = qsc_socket_accept(&lsock, &ras->csock);
							}

							if (serr == qsc_socket_exception_success)
							{
								qsc_async_thread_create(&rds_receive_loop, ras);
							}
							else
							{
								/* free the resources if connect fails */
								qsc_memutils_alloc_free(ras);
								mpdc_server_log_write_message(&m_rds_application_state, mpdc_application_log_allocation_failure, (const char*)lsock.address, QSC_SOCKET_ADDRESS_MAX_SIZE);
							}
						}
						else
						{
							/* exit on memory allocation failure */
							mpdc_server_log_write_message(&m_rds_application_state, mpdc_application_log_allocation_failure, (const char*)lsock.address, QSC_SOCKET_ADDRESS_MAX_SIZE);
						}
					};
				}
			}
		}
	}
}

#endif

static bool rds_server_service_start(void)
{
#if defined(MPDC_NETWORK_PROTOCOL_IPV6)
	/* start the main receive loop on a new thread */
	if (qsc_async_thread_create_noargs(&rds_ipv6_server_start))
#else
	if (qsc_async_thread_create_noargs(&rds_ipv4_server_start))
#endif
	{
		m_rds_server_loop_status = mpdc_server_loop_status_started;
	}

	return (m_rds_server_loop_status == mpdc_server_loop_status_started);
}

/* application functions */

static void rds_get_command_mode(const char* command)
{
	MPDC_ASSERT(command != NULL);

	mpdc_console_modes nmode;

	nmode = m_rds_application_state.mode;

	switch (m_rds_application_state.mode)
	{
		case mpdc_console_mode_config:
		{
			if (qsc_consoleutils_line_equals(command, "certificate"))
			{
				nmode = mpdc_console_mode_certificate;
			}
			else if (qsc_consoleutils_line_equals(command, "server"))
			{
				nmode = mpdc_console_mode_server;
			}
			else if (qsc_consoleutils_line_equals(command, "exit"))
			{
				nmode = mpdc_console_mode_enable;
			}

			break;
		}
		case mpdc_console_mode_certificate:
		{
			if (qsc_consoleutils_line_equals(command, "exit"))
			{
				nmode = mpdc_console_mode_config;
			}

			break;
		}
		case mpdc_console_mode_server:
		{
			if (qsc_consoleutils_line_equals(command, "exit"))
			{
				nmode = mpdc_console_mode_config;
			}

			break;
		}
		case mpdc_console_mode_enable:
		{
			if (qsc_consoleutils_line_equals(command, "config"))
			{
				nmode = mpdc_console_mode_config;
			}
			else if (qsc_consoleutils_line_equals(command, "exit"))
			{
				nmode = mpdc_console_mode_user;
			}

			break;
		}
		case mpdc_console_mode_user:
		{
			if (qsc_consoleutils_line_equals(command, "enable"))
			{
				nmode = mpdc_console_mode_enable;
			}
			else if (qsc_stringutils_string_size(command) > 0U)
			{
				nmode = mpdc_console_mode_user;
			}

			break;
		}
		default:
		{
		}
	}

	m_rds_application_state.mode = nmode;
}

static void rds_set_command_action(const char* command)
{
	MPDC_ASSERT(command != NULL);

	mpdc_command_actions res;
	size_t clen;

	res = mpdc_command_action_command_unrecognized;
	clen = qsc_stringutils_string_size(command);

	if (clen == 0U || clen > QSC_CONSOLE_MAX_LINE)
	{
		res = mpdc_command_action_none;
	}
	else
	{
		if (m_rds_application_state.mode == mpdc_console_mode_config)
		{
			if (qsc_consoleutils_line_equals(command, "clear all"))
			{
				res = mpdc_command_action_config_clear_all;
			}
			else if (qsc_consoleutils_line_equals(command, "clear config"))
			{
				res = mpdc_command_action_config_clear_config;
			}
			else if (qsc_consoleutils_line_equals(command, "clear log"))
			{
				res = mpdc_command_action_config_clear_log;
			}
			else if (qsc_consoleutils_line_equals(command, "certificate"))
			{
				res = mpdc_command_action_config_certificate;
			}
			else if (qsc_consoleutils_line_equals(command, "exit"))
			{
				res = mpdc_command_action_config_exit;
			}
			else if (qsc_consoleutils_line_equals(command, "help"))
			{
				res = mpdc_command_action_config_help;
			}
			else if (qsc_consoleutils_line_contains(command, "log "))
			{
				res = mpdc_command_action_config_log_host;
			}
			else if (qsc_consoleutils_line_contains(command, "address "))
			{
				res = mpdc_command_action_config_address;
			}
			else if (qsc_consoleutils_line_contains(command, "name domain "))
			{
				res = mpdc_command_action_config_name_domain;
			}
			else if (qsc_consoleutils_line_contains(command, "name host "))
			{
				res = mpdc_command_action_config_name_host;
			}
			else if (qsc_consoleutils_line_contains(command, "retries "))
			{
				res = mpdc_command_action_config_retries;
			}
			else if (qsc_consoleutils_line_equals(command, "server"))
			{
				res = mpdc_command_action_config_server;
			}
			else if (qsc_consoleutils_line_contains(command, "timeout "))
			{
				res = mpdc_command_action_config_timeout;
			}
		}
		else if (m_rds_application_state.mode == mpdc_console_mode_certificate)
		{
			if (qsc_consoleutils_line_equals(command, "exit"))
			{
				res = mpdc_command_action_certificate_exit;
			}
			else if (qsc_consoleutils_line_contains(command, "export "))
			{
				res = mpdc_command_action_certificate_export;
			}
			else if (qsc_consoleutils_line_equals(command, "help"))
			{
				res = mpdc_command_action_certificate_help;
			}
			else if (qsc_consoleutils_line_contains(command, "generate "))
			{
				res = mpdc_command_action_certificate_generate;
			}
			else if (qsc_consoleutils_line_equals(command, "print"))
			{
				res = mpdc_command_action_certificate_import;
			}
			else if (qsc_consoleutils_line_contains(command, "sign "))
			{
				res = mpdc_command_action_certificate_sign;
			}
		}
		else if (m_rds_application_state.mode == mpdc_console_mode_server)
		{
			if (qsc_consoleutils_line_equals(command, "backup"))
			{
				res = mpdc_command_action_server_backup;
			}
			else if (qsc_consoleutils_line_equals(command, "exit"))
			{
				res = mpdc_command_action_server_exit;
			}
			else if (qsc_consoleutils_line_equals(command, "help"))
			{
				res = mpdc_command_action_server_help;
			}
			else if (qsc_consoleutils_line_equals(command, "restore"))
			{
				res = mpdc_command_action_server_restore;
			}
			else if (qsc_consoleutils_line_contains(command, "service "))
			{
				res = mpdc_command_action_server_service;
			}
		}
		else if (m_rds_application_state.mode == mpdc_console_mode_enable)
		{
			if (qsc_consoleutils_line_equals(command, "clear screen"))
			{
				res = mpdc_command_action_enable_clear_screen;
			}
			else if (qsc_consoleutils_line_equals(command, "show config"))
			{
				res = mpdc_command_action_enable_show_config;
			}
			else if (qsc_consoleutils_line_equals(command, "show log"))
			{
				res = mpdc_command_action_enable_show_log;
			}
			else if (qsc_consoleutils_line_equals(command, "config"))
			{
				res = mpdc_command_action_enable_config;
			}
			else if (qsc_consoleutils_line_equals(command, "exit"))
			{
				res = mpdc_command_action_enable_exit;
			}
			else if (qsc_consoleutils_line_equals(command, "help"))
			{
				res = mpdc_command_action_enable_help;
			}
			else if (qsc_consoleutils_line_equals(command, "quit"))
			{
				res = mpdc_command_action_enable_quit;
			}
		}
		else if (m_rds_application_state.mode == mpdc_console_mode_user)
		{
			if (qsc_consoleutils_line_equals(command, "enable"))
			{
				res = mpdc_command_action_user_enable;
			}
			else if (qsc_consoleutils_line_equals(command, "help"))
			{
				res = mpdc_command_action_user_help;
			}
			else if (qsc_consoleutils_line_equals(command, "quit"))
			{
				res = mpdc_command_action_user_quit;
			}
		}
	}

	m_rds_application_state.action = res;
}

static void rds_command_execute(const char* command)
{
	MPDC_ASSERT(command != NULL);

	const char* cmsg;
	size_t slen;
	bool res;

	switch (m_rds_application_state.action)
	{
	case mpdc_command_action_certificate_exit:
	{
		/* mode change, do nothing */
		break;
	}
	case mpdc_command_action_certificate_export:
	{
		cmsg = qsc_stringutils_reverse_sub_string(command, " ");

		if (cmsg != NULL)
		{
			res = rds_certificate_export(cmsg);

			if (res == true)
			{
				mpdc_menu_print_predefined_message(mpdc_application_root_copy_success, m_rds_application_state.mode, m_rds_application_state.hostname);
			}
			else
			{
				mpdc_menu_print_predefined_message(mpdc_application_root_copy_failure, m_rds_application_state.mode, m_rds_application_state.hostname);
			}
		}

		break;
	}
	case mpdc_command_action_certificate_generate:
	{
		cmsg = qsc_stringutils_reverse_sub_string(command, " ");
		slen = qsc_stringutils_string_size(m_rds_application_state.username);

		if (cmsg != NULL)
		{
			res = rds_certificate_generate_root(cmsg);

			if (res == true)
			{
				char fpath[MPDC_STORAGE_PATH_MAX] = { 0 };

				mpdc_server_certificate_path(&m_rds_application_state, fpath, sizeof(fpath), m_rds_application_state.issuer);
				mpdc_menu_print_predefined_message(mpdc_application_generate_key_success, m_rds_application_state.mode, m_rds_application_state.hostname);
				mpdc_menu_print_message(fpath, m_rds_application_state.mode, m_rds_application_state.hostname);
				mpdc_server_log_write_message(&m_rds_application_state, mpdc_application_log_generate_success, m_rds_application_state.username, slen);
			}
			else
			{
				mpdc_menu_print_predefined_message(mpdc_application_generate_key_failure, m_rds_application_state.mode, m_rds_application_state.hostname);
				mpdc_server_log_write_message(&m_rds_application_state, mpdc_application_log_generate_failure, m_rds_application_state.username, slen);
			}
		}

		break;
	}
	case mpdc_command_action_certificate_help:
	{
		mpdc_help_print_mode(m_rds_application_state.cmdprompt, mpdc_console_mode_certificate, m_rds_application_state.srvtype);
		break;
	}
	case mpdc_command_action_certificate_import:
	{
		char fpath[MPDC_STORAGE_PATH_MAX] = { 0 };

		res = false;
		mpdc_server_certificate_path(&m_rds_application_state, fpath, sizeof(fpath), m_rds_application_state.issuer);

		if (qsc_fileutils_exists(fpath) == true)
		{
			res = mpdc_server_root_certificate_print(fpath, sizeof(fpath));
		}

		if (res == false)
		{
			mpdc_menu_print_predefined_message(mpdc_application_client_pubkey_path_invalid, m_rds_application_state.mode, m_rds_application_state.hostname);
		}

		break;
	}
	case mpdc_command_action_certificate_sign:
	{
		res = false;
		cmsg = qsc_stringutils_reverse_sub_string(command, " ");

		if (cmsg != NULL)
		{
			res = rds_certificate_sign(cmsg);
			slen = qsc_stringutils_string_size(m_rds_application_state.username);

			if (res == true)
			{
				mpdc_server_log_write_message(&m_rds_application_state, mpdc_application_root_sign_success, m_rds_application_state.username, slen);
				mpdc_menu_print_predefined_message(mpdc_application_root_sign_success, m_rds_application_state.mode, m_rds_application_state.hostname);
			}
			else
			{
				mpdc_server_log_write_message(&m_rds_application_state, mpdc_application_root_sign_failure, m_rds_application_state.username, slen);
				mpdc_menu_print_predefined_message(mpdc_application_root_sign_failure, m_rds_application_state.mode, m_rds_application_state.hostname);
			}
		}

		break;
	}
	case mpdc_command_action_config_address:
	{
		cmsg = qsc_stringutils_reverse_sub_string(command, " ");

		if (cmsg != NULL)
		{
			slen = qsc_stringutils_string_size(cmsg);
			res = mpdc_server_set_ip_address(&m_rds_application_state, cmsg, slen);

			if (res == true)
			{
				mpdc_menu_print_predefined_message(mpdc_application_address_change_success, m_rds_application_state.mode, m_rds_application_state.hostname);
			}
			else
			{
				mpdc_menu_print_predefined_message(mpdc_application_address_change_failure, m_rds_application_state.mode, m_rds_application_state.hostname);
			}
		}

		break;
	}
	case mpdc_command_action_config_clear:
	{
		/* show clear help */
		mpdc_help_print_context(m_rds_application_state.cmdprompt, mpdc_command_action_config_clear_all);
		mpdc_help_print_context(m_rds_application_state.cmdprompt, mpdc_command_action_config_clear_config);
		mpdc_help_print_context(m_rds_application_state.cmdprompt, mpdc_command_action_config_clear_log);

		break;
	}
	case mpdc_command_action_config_log:
	{
		/* show log help */
		mpdc_help_print_context(m_rds_application_state.cmdprompt, mpdc_command_action_config_log_host);

		break;
	}
	case mpdc_command_action_config_name:
	{
		/* show name help */
		mpdc_help_print_context(m_rds_application_state.cmdprompt, mpdc_command_action_config_name_domain);
		mpdc_help_print_context(m_rds_application_state.cmdprompt, mpdc_command_action_config_name_host);

		break;
	}
	case mpdc_command_action_config_clear_all:
	{
		if (mpdc_menu_print_predefined_message_confirm(mpdc_application_erase_erase_all, m_rds_application_state.mode, m_rds_application_state.hostname) == true)
		{
			mpdc_server_erase_all(&m_rds_application_state);
			mpdc_menu_print_predefined_message(mpdc_application_system_erased, m_rds_application_state.mode, m_rds_application_state.hostname);
		}
		else
		{
			mpdc_menu_print_predefined_message(mpdc_application_operation_aborted, m_rds_application_state.mode, m_rds_application_state.hostname);
		}

		break;
	}
	case mpdc_command_action_config_clear_config:
	{
		if (mpdc_menu_print_predefined_message_confirm(mpdc_application_erase_config, mpdc_console_mode_config, m_rds_application_state.hostname) == true)
		{
			mpdc_server_log_write_message(&m_rds_application_state, mpdc_application_log_configuration_erased, m_rds_application_state.username, qsc_stringutils_string_size(m_rds_application_state.username));
			mpdc_server_clear_config(&m_rds_application_state);
			mpdc_menu_print_predefined_message(mpdc_application_configuration_erased, m_rds_application_state.mode, m_rds_application_state.hostname);
		}
		else
		{
			mpdc_menu_print_predefined_message(mpdc_application_operation_aborted, m_rds_application_state.mode, m_rds_application_state.hostname);
		}

		break;
	}
	case mpdc_command_action_config_clear_log:
	{
		if (mpdc_menu_print_predefined_message_confirm(mpdc_application_erase_log, mpdc_console_mode_config, m_rds_application_state.hostname) == true)
		{
			mpdc_server_clear_log(&m_rds_application_state);
			mpdc_menu_print_predefined_message(mpdc_application_log_erased, m_rds_application_state.mode, m_rds_application_state.hostname);
		}
		else
		{
			mpdc_menu_print_predefined_message(mpdc_application_operation_aborted, m_rds_application_state.mode, m_rds_application_state.hostname);
		}

		break;
	}
	case mpdc_command_action_config_certificate:
	{
		/* mode change, do nothing */
		break;
	}
	case mpdc_command_action_config_exit:
	{
		/* mode change, do nothing */
		break;
	}
	case mpdc_command_action_config_help:
	{
		mpdc_help_print_mode(m_rds_application_state.cmdprompt, mpdc_console_mode_config, m_rds_application_state.srvtype);
		break;
	}
	case mpdc_command_action_config_log_host:
	{
		cmsg = qsc_stringutils_reverse_sub_string(command, " ");

		if (cmsg != NULL)
		{
			if (qsc_stringutils_string_contains(cmsg, "enable"))
			{
				/* enable logging */
				m_rds_application_state.loghost = true;
				mpdc_server_log_host(&m_rds_application_state);
				mpdc_menu_print_predefined_message(mpdc_application_logging_enabled, m_rds_application_state.mode, m_rds_application_state.hostname);
			}
			else if (qsc_stringutils_string_contains(cmsg, "disable"))
			{
				/* disable logging */
				m_rds_application_state.loghost = false;
				mpdc_server_log_host(&m_rds_application_state);
				mpdc_menu_print_predefined_message(mpdc_application_logging_disabled, m_rds_application_state.mode, m_rds_application_state.hostname);
			}
			else
			{
				mpdc_menu_print_predefined_message(mpdc_application_not_recognized, m_rds_application_state.mode, m_rds_application_state.hostname);
				mpdc_help_print_context(m_rds_application_state.cmdprompt, mpdc_command_action_config_log_host);
			}
		}
		else
		{
			mpdc_menu_print_predefined_message(mpdc_application_not_recognized, m_rds_application_state.mode, m_rds_application_state.hostname);
			mpdc_help_print_context(m_rds_application_state.cmdprompt, mpdc_command_action_config_log_host);
		}

		break;
	}
	case mpdc_command_action_config_name_domain:
	{
		cmsg = qsc_stringutils_reverse_sub_string(command, " ");

		if (cmsg != NULL)
		{
			slen = qsc_stringutils_string_size(cmsg);

			if (mpdc_server_set_domain_name(&m_rds_application_state, cmsg, slen) == false)
			{
				mpdc_menu_print_predefined_message(mpdc_application_domain_invalid, m_rds_application_state.mode, m_rds_application_state.hostname);
			}
		}

		break;
	}
	case mpdc_command_action_config_name_host:
	{
		cmsg = qsc_stringutils_reverse_sub_string(command, " ");

		if (cmsg != NULL)
		{
			slen = qsc_stringutils_string_size(cmsg);

			if (mpdc_server_set_host_name(&m_rds_application_state, cmsg, slen) == false)
			{
				mpdc_menu_print_predefined_message(mpdc_application_hostname_invalid, m_rds_application_state.mode, m_rds_application_state.hostname);
			}
		}

		break;
	}
	case mpdc_command_action_config_retries:
	{
		cmsg = qsc_stringutils_reverse_sub_string(command, " ");
		slen = qsc_stringutils_string_size(cmsg);

		if (cmsg != NULL)
		{
			slen = qsc_stringutils_string_size(cmsg);

			if (mpdc_server_set_password_retries(&m_rds_application_state, cmsg, slen) == false)
			{
				/* invalid message */
				mpdc_menu_print_predefined_message(mpdc_application_retry_invalid, m_rds_application_state.mode, m_rds_application_state.hostname);
			}
		}

		break;
	}
	case mpdc_command_action_config_server:
	{
		/* mode change, do nothing */
		break;
	}
	case mpdc_command_action_config_timeout:
	{
		cmsg = qsc_stringutils_reverse_sub_string(command, " ");

		if (cmsg != NULL)
		{
			slen = qsc_stringutils_string_size(cmsg);

			if (mpdc_server_set_console_timeout(&m_rds_application_state, cmsg, slen) == false)
			{
				/* invalid message */
				mpdc_menu_print_predefined_message(mpdc_application_timeout_invalid, m_rds_application_state.mode, m_rds_application_state.hostname);
			}
		}

		break;
	}
	case mpdc_command_action_enable_clear_screen:
	{
		/* clear the screen */
		qsc_consoleutils_set_window_clear();
		break;
	}
	case mpdc_command_action_enable_config:
	{
		/* mode change, do nothing */
		break;
	}
	case mpdc_command_action_enable_exit:
	{
		mpdc_server_user_logout(&m_rds_application_state);

		break;
	}
	case mpdc_command_action_enable_help:
	{
		/* show enable help */
		mpdc_help_print_mode(m_rds_application_state.cmdprompt, mpdc_console_mode_enable, m_rds_application_state.srvtype);

		break;
	}
	case mpdc_command_action_enable_quit:
	case mpdc_command_action_enable_show_config:
	{
		/* show config */
		mpdc_server_print_configuration(&m_rds_application_state);

		break;
	}
	case mpdc_command_action_enable_show_log:
	{
		/* read the user log */
		mpdc_server_log_print(&m_rds_application_state);
		break;
	}
	case mpdc_command_action_help_enable_all:
	{
		/* show enable help */
		mpdc_help_print_mode(m_rds_application_state.cmdprompt, mpdc_console_mode_enable, m_rds_application_state.srvtype);

		break;
	}
	case mpdc_command_action_help_enable_show:
	{
		/* show help */
		mpdc_help_print_context(m_rds_application_state.cmdprompt, mpdc_command_action_enable_show_config);
		mpdc_help_print_context(m_rds_application_state.cmdprompt, mpdc_command_action_enable_show_log);

		break;
	}
	case mpdc_command_action_help_enable_user:
	{
		/* show enable user help */
		mpdc_help_print_mode(m_rds_application_state.cmdprompt, mpdc_console_mode_user, m_rds_application_state.srvtype);

		break;
	}
	case mpdc_command_action_server_backup:
	{
		slen = qsc_stringutils_string_size(m_rds_application_state.hostname);
		mpdc_server_state_backup_save(&m_rds_application_state);
		mpdc_server_log_write_message(&m_rds_application_state, mpdc_application_log_state_backup, m_rds_application_state.hostname, slen);
		mpdc_menu_print_predefined_message(mpdc_application_server_backup_save_confirmation, m_rds_application_state.mode, m_rds_application_state.hostname);

		break;
	}
	case mpdc_command_action_server_exit:
	{
		/* mode change, do nothing */
		break;
	}
	case mpdc_command_action_server_help:
	{
		/* show config-server help */
		mpdc_help_print_mode(m_rds_application_state.cmdprompt, mpdc_console_mode_server, m_rds_application_state.srvtype);
		break;
	}
	case mpdc_command_action_server_restore:
	{
		bool dres;

		/* notify that server is already joined to a network */
		dres = mpdc_menu_print_predefined_message_confirm(mpdc_application_server_backup_restore_challenge, m_rds_application_state.mode, m_rds_application_state.hostname);
			
		if (dres == true)
		{
			mpdc_server_state_backup_restore(&m_rds_application_state);
			slen = qsc_stringutils_string_size(m_rds_application_state.hostname);
			mpdc_server_log_write_message(&m_rds_application_state, mpdc_application_log_state_restore, m_rds_application_state.hostname, slen);
		}

		break;
	}
	case mpdc_command_action_server_service:
	{
		cmsg = qsc_stringutils_reverse_sub_string(command, " ");

		if (cmsg != NULL)
		{
			slen = qsc_stringutils_string_size(m_rds_application_state.hostname);

			if (qsc_stringutils_string_contains(cmsg, "start"))
			{
				if (m_rds_server_loop_status != mpdc_server_loop_status_started)
				{
					if (m_rds_application_state.joined == false)
					{
						rds_server_dla_dialogue();
					}

					if (rds_server_service_start() == true &&
						m_rds_server_loop_status == mpdc_server_loop_status_started)
					{
						mpdc_menu_print_predefined_message(mpdc_application_server_service_start_success, m_rds_application_state.mode, m_rds_application_state.hostname);
						mpdc_server_log_write_message(&m_rds_application_state, mpdc_application_log_service_started, m_rds_application_state.hostname, slen);
					}
					else
					{
						mpdc_menu_print_predefined_message(mpdc_application_server_service_start_failure, m_rds_application_state.mode, m_rds_application_state.hostname);
					}
				}
			}
			else if (qsc_stringutils_string_contains(cmsg, "stop"))
			{
				if (m_rds_server_loop_status == mpdc_server_loop_status_started)
				{
					m_rds_server_loop_status = mpdc_server_loop_status_stopped;
					mpdc_menu_print_predefined_message(mpdc_application_server_service_stopped, m_rds_application_state.mode, m_rds_application_state.hostname);
					mpdc_server_log_write_message(&m_rds_application_state, mpdc_application_log_service_stopped, m_rds_application_state.hostname, slen);
				}
			}
			else if (qsc_stringutils_string_contains(cmsg, "pause"))
			{
				if (m_rds_server_loop_status != mpdc_server_loop_status_paused)
				{
					m_rds_server_loop_status = mpdc_server_loop_status_paused;
					mpdc_menu_print_predefined_message(mpdc_application_server_service_paused, m_rds_application_state.mode, m_rds_application_state.hostname);
					mpdc_server_log_write_message(&m_rds_application_state, mpdc_application_log_service_paused, m_rds_application_state.hostname, slen);
				}
			}
			else if (qsc_stringutils_string_contains(cmsg, "resume"))
			{
				if (m_rds_server_loop_status == mpdc_server_loop_status_paused)
				{
					m_rds_server_loop_status = mpdc_server_loop_status_started;
					mpdc_menu_print_predefined_message(mpdc_application_server_service_resume_success, m_rds_application_state.mode, m_rds_application_state.hostname);
					mpdc_server_log_write_message(&m_rds_application_state, mpdc_application_log_service_resumed, m_rds_application_state.hostname, slen);
				}
				else
				{
					mpdc_menu_print_predefined_message(mpdc_application_server_service_resume_failure, m_rds_application_state.mode, m_rds_application_state.hostname);
				}
			}
			else
			{
				mpdc_menu_print_predefined_message(mpdc_application_not_recognized, m_rds_application_state.mode, m_rds_application_state.hostname);
			}
		}

		break;
	}
	case mpdc_command_action_user_enable:
	{
		/* user login */
		if (mpdc_server_user_login(&m_rds_application_state) == true)
		{
			if (rds_server_load_root() == true)
			{
				m_rds_application_state.joined = rds_server_load_dla();
			}
		}
		else
		{
			mpdc_rds_stop_server();
			mpdc_menu_print_predefined_message(mpdc_application_retries_exceeded, m_rds_application_state.mode, m_rds_application_state.hostname);
			mpdc_menu_print_prompt(m_rds_application_state.mode, m_rds_application_state.hostname);
			qsc_consoleutils_get_char();
		}

		break;
	}
	case mpdc_command_action_user_help:
	{
		/* show user help */
		mpdc_help_print_mode(m_rds_application_state.cmdprompt, mpdc_console_mode_user, m_rds_application_state.srvtype);

		break;
	}
	case mpdc_command_action_user_quit:
	{
		m_rds_command_loop_status = mpdc_server_loop_status_stopped;
		mpdc_server_state_unload(&m_rds_application_state);
		mpdc_menu_print_predefined_message(mpdc_application_application_quit, m_rds_application_state.mode, m_rds_application_state.hostname);
		mpdc_menu_print_prompt(m_rds_application_state.mode, m_rds_application_state.hostname);
		qsc_consoleutils_get_char();

		break;
	}
	case mpdc_command_action_none:
	{
		/* empty return, do nothing */
		break;
	}
	case mpdc_command_action_command_unrecognized:
	{
		/* partial command */
		mpdc_menu_print_predefined_message(mpdc_application_not_recognized, m_rds_application_state.mode, m_rds_application_state.hostname);
		mpdc_help_print_mode(m_rds_application_state.cmdprompt, m_rds_application_state.mode, m_rds_application_state.srvtype);
		break;
	}
	default:
	{
		mpdc_help_print_mode(m_rds_application_state.cmdprompt, m_rds_application_state.mode, m_rds_application_state.srvtype);
	}
	}
}

static void rds_idle_timer(void)
{
	const uint32_t MMSEC = 60U * 1000U;

	while (true)
	{
		qsc_async_thread_sleep(MMSEC);
		qsc_mutex mtx = qsc_async_mutex_lock_ex();

		if (m_rds_application_state.mode != mpdc_console_mode_user)
		{
			++m_rds_idle_timer;

			if (m_rds_idle_timer >= m_rds_application_state.timeout)
			{
				mpdc_server_user_logout(&m_rds_application_state);
				m_rds_idle_timer = 0;
				qsc_consoleutils_print_line("");
				mpdc_menu_print_predefined_message(mpdc_application_console_timeout_expired, m_rds_application_state.mode, m_rds_application_state.hostname);
				mpdc_menu_print_prompt(m_rds_application_state.mode, m_rds_application_state.hostname);
			}
		}

		qsc_async_mutex_unlock_ex(mtx);
	};
}

static void rds_command_loop(char* command)
{
	MPDC_ASSERT(command != NULL);

	m_rds_command_loop_status = mpdc_server_loop_status_started;

	while (true)
	{
		qsc_consoleutils_get_line(command, QSC_CONSOLE_MAX_LINE);

		/* lock the mutex */
		qsc_mutex mtx = qsc_async_mutex_lock_ex();
		m_rds_idle_timer = 0U;
		qsc_async_mutex_unlock_ex(mtx);

		rds_set_command_action(command);
		rds_command_execute(command);
		rds_get_command_mode(command);

		mpdc_server_set_command_prompt(&m_rds_application_state);
		mpdc_menu_print_prompt(m_rds_application_state.mode, m_rds_application_state.hostname);
		qsc_stringutils_clear_string(command);

		if (m_rds_command_loop_status == mpdc_server_loop_status_paused)
		{
			qsc_async_thread_sleep(MPDC_STORAGE_SERVER_PAUSE_INTERVAL);
			continue;
		}
		else if (m_rds_command_loop_status == mpdc_server_loop_status_stopped)
		{
			break;
		}
	}

	rds_server_dispose();
}

void mpdc_rds_pause_server(void)
{
	m_rds_command_loop_status = mpdc_server_loop_status_paused;
}

void mpdc_rds_start_server(void)
{
	char command[QSC_CONSOLE_MAX_LINE] = { 0 };
	qsc_thread idle;

	/* initialize the server */
	mpdc_server_state_initialize(&m_rds_application_state, mpdc_network_designation_rds);

	/* set the window parameters */
	qsc_consoleutils_set_virtual_terminal();
	qsc_consoleutils_set_window_size(1000, 600);
	qsc_consoleutils_set_window_title(m_rds_application_state.wtitle);

	/* application banner */
	mpdc_server_print_banner(&m_rds_application_state);

	/* load the command prompt */
	rds_get_command_mode(command);
	mpdc_menu_print_prompt(m_rds_application_state.mode, m_rds_application_state.hostname);

	/* start the idle timer */
	m_rds_idle_timer = 0U;
	idle = qsc_async_thread_create_noargs(&rds_idle_timer);

	if(idle)
	{
		/* command loop */
		rds_command_loop(command);
	}
}

void mpdc_rds_stop_server(void)
{
	m_rds_command_loop_status = mpdc_server_loop_status_stopped;
}

#if defined(MPDC_DEBUG_TESTS_RUN)
bool mpdc_rds_appserv_test(void)
{
	return false;
}
#endif
