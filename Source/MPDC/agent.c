#include "agent.h"
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
#include "collection.h"
#include "consoleutils.h"
#include "fileutils.h"
#include "ipinfo.h"
#include "memutils.h"
#include "socketserver.h"
#include "stringutils.h"
#include "timerex.h"
#include "timestamp.h"

/** \cond */
typedef struct agent_receive_state
{
	qsc_socket csock;
} agent_receive_state;
/** \endcond */

static mpdc_server_application_state m_agent_application_state = { 0 };
static qsc_collection_state m_agent_mfk_collection = { 0 };
static mpdc_child_certificate m_agent_local_certificate = { 0 };
static mpdc_server_server_loop_status m_agent_command_loop_status;
static mpdc_server_server_loop_status m_agent_server_loop_status;
static uint64_t m_agent_idle_timer;

/* agent functions */

static bool agent_certificate_generate(const char* cmsg)
{
	MPDC_ASSERT(cmsg != NULL);

	uint64_t period;
	size_t nlen;
	bool res;

	res = false;
	nlen = qsc_stringutils_string_size(cmsg);

	/* generate a certificate and write to file */
	if (qsc_stringutils_is_numeric(cmsg, nlen) == true)
	{
		char fpath[MPDC_STORAGE_PATH_MAX] = { 0 };

		mpdc_server_child_certificate_path(&m_agent_application_state, fpath, sizeof(fpath));
		/* get number of valid days */
		period = qsc_stringutils_string_to_int(cmsg);
		/* convert time to seconds */
		period *= MPDC_PERIOD_DAY_TO_SECONDS;

		/* check that the root is installed */
		res = mpdc_server_topology_root_exists(&m_agent_application_state);

		if (res == false)
		{
			res = mpdc_server_root_import_dialogue(&m_agent_application_state);
		}

		if (res == true && (period >= MPDC_CERTIFICATE_MINIMUM_PERIOD || period <= MPDC_CERTIFICATE_MAXIMUM_PERIOD))
		{
			char tadd[MPDC_CERTIFICATE_ADDRESS_SIZE] = { 0 };

			res = mpdc_network_get_local_address(tadd);

			if (res == true)
			{
				/* the child certificate is invalid once the root certificate expires,
					if the period is longer than the root, change to the root expiration time */
				if (m_agent_application_state.root.expiration.to < period + qsc_timestamp_epochtime_seconds())
				{
					char tsc[QSC_TIMESTAMP_STRING_SIZE] = { 0 };
					int32_t rtme;

					/* get the root max vaid time */
					period = m_agent_application_state.root.expiration.to - qsc_timestamp_epochtime_seconds();

					/* get comparison time */
					rtme = (int32_t)period / MPDC_PERIOD_DAY_TO_SECONDS;
					qsc_stringutils_int_to_string(rtme, tsc, sizeof(tsc));

					/* notify user of change in duration */
					mpdc_menu_print_predefined_text(mpdc_application_certificate_period_update, m_agent_application_state.mode, m_agent_application_state.hostname);
					mpdc_menu_print_text_line(tsc);
				}

				if (qsc_fileutils_exists(fpath) == true)
				{
					/* file exists, overwrite challenge */
					if (mpdc_menu_print_predefined_message_confirm(mpdc_application_generate_key_overwrite, m_agent_application_state.mode, m_agent_application_state.hostname) == true)
					{
						/* create the certificate and copy the signing key to state */
						mpdc_server_child_certificate_generate(&m_agent_application_state, &m_agent_local_certificate, period);
						/* write the certificate to file and topology */
						mpdc_server_local_certificate_store(&m_agent_application_state, &m_agent_local_certificate, tadd);
						/* store the state */
						res = mpdc_server_state_store(&m_agent_application_state);
						/* log key overwrite */
						mpdc_server_log_write_message(&m_agent_application_state, mpdc_application_log_generate_delete, NULL, 0U);
					}
					else
					{
						mpdc_menu_print_predefined_message(mpdc_application_operation_aborted, m_agent_application_state.mode, m_agent_application_state.hostname);
						res = false;
					}
				}
				else
				{
					mpdc_server_child_certificate_generate(&m_agent_application_state, &m_agent_local_certificate, period);
					mpdc_server_local_certificate_store(&m_agent_application_state, &m_agent_local_certificate, tadd);
					res = mpdc_server_state_store(&m_agent_application_state);
				}
			}
			else
			{
				mpdc_menu_print_predefined_message_confirm(mpdc_application_network_ip_address_not_set, m_agent_application_state.mode, m_agent_application_state.hostname);
			}
		}
		else
		{
			mpdc_menu_print_predefined_message(mpdc_application_invalid_input, m_agent_application_state.mode, m_agent_application_state.hostname);
		}
	}
	else
	{
		mpdc_menu_print_predefined_message(mpdc_application_invalid_input, m_agent_application_state.mode, m_agent_application_state.hostname);
	}

	return res;
}

static mpdc_protocol_errors agent_converge_response(const qsc_socket* csock, const mpdc_network_packet* packetin)
{
	MPDC_ASSERT(csock != NULL);
	MPDC_ASSERT(packetin != NULL);

	mpdc_topology_node_state lnode = { 0 };
	mpdc_protocol_errors merr;

	if (mpdc_topology_node_find(&m_agent_application_state.tlist, &lnode, m_agent_local_certificate.serial) == true)
	{
		mpdc_network_converge_response_state crs = { 
			.csock = csock, 
			.lcert = &m_agent_local_certificate, 
			.lnode = &lnode, 
			.rcert = &m_agent_application_state.dla, 
			.sigkey = m_agent_application_state.sigkey
		};

		/* create and send the converge response to the dla */
		merr = mpdc_network_converge_response(&crs, packetin);
	}
	else
	{
		merr = mpdc_protocol_error_node_not_found;
	}

	return merr;
}

static mpdc_protocol_errors agent_fragment_query_response(const qsc_socket* csock, const mpdc_network_packet* packetin)
{
	MPDC_ASSERT(csock != NULL);
	MPDC_ASSERT(packetin != NULL);

	mpdc_topology_node_state lnode = { 0 };
	mpdc_topology_node_state rnode = { 0 };
	mpdc_protocol_errors merr;
	uint8_t* mser;

	mser = packetin->pmessage + MPDC_CERTIFICATE_SERIAL_SIZE + MPDC_CRYPTO_SYMMETRIC_TOKEN_SIZE; 

	if (mpdc_topology_node_find_issuer(&m_agent_application_state.tlist, &lnode, m_agent_local_certificate.issuer) == true &&
		mpdc_topology_node_find(&m_agent_application_state.tlist, &rnode, mser) == true)
	{
		mpdc_network_fragment_query_response_state fqr = {
			.csock = csock,
			.list = &m_agent_application_state.tlist,
			.lmfk = &m_agent_mfk_collection,
			.lnode = &lnode, 
			.rnode = &rnode 
		};

		merr = mpdc_network_fragment_query_response(&fqr, packetin);

#if defined(MPDC_NETWORK_MFK_HASH_CYCLED)
		if (merr == mpdc_protocol_error_none)
		{
			mpdc_server_mfkcol_to_file(&m_agent_mfk_collection, &m_agent_application_state);
		}
#endif
	}
	else
	{
		merr = mpdc_protocol_error_node_not_found;
	}

	return merr;
}

static mpdc_protocol_errors agent_mfk_response(qsc_socket* csock, const mpdc_network_packet* packetin)
{
	MPDC_ASSERT(csock != NULL);
	MPDC_ASSERT(packetin != NULL);

	mpdc_child_certificate rcert = { 0 };
	qsc_mutex mtx;
	mpdc_protocol_errors merr;

	mpdc_certificate_child_deserialize(&rcert, packetin->pmessage + MPDC_PACKET_SUBHEADER_SIZE);

	if (mpdc_certificate_child_is_valid(&rcert) == true)
	{
		uint8_t mfkey[MPDC_CRYPTO_SYMMETRIC_KEY_SIZE] = { 0U }; 
		
		mpdc_network_mfk_response_state mrs = {
			.csock = csock,
			.lcert = &m_agent_local_certificate,
			.mfk = mfkey,
			.rcert = &rcert,
			.root = &m_agent_application_state.root,
			.sigkey = m_agent_application_state.sigkey
		};

		/* run the key exchange response */
		merr = mpdc_network_mfk_exchange_response(&mrs, packetin);

		if (merr == mpdc_protocol_error_none)
		{
			mtx = qsc_async_mutex_lock_ex();

			/* add the node to the topology */
			mpdc_topology_child_register(&m_agent_application_state.tlist, &rcert, (const char*)csock->address);
			mpdc_server_topology_to_file(&m_agent_application_state);

			/* add the mfk to key collection */
			qsc_collection_add(&m_agent_mfk_collection, mfkey, rcert.serial);
			mpdc_server_mfkcol_to_file(&m_agent_mfk_collection, &m_agent_application_state);

			qsc_async_mutex_unlock_ex(mtx);
		}
	}
	else
	{
		merr = mpdc_protocol_error_message_verification_failure;
	}

	return merr;
}

static mpdc_protocol_errors agent_register_request(const char* address)
{
	MPDC_ASSERT(address != NULL);

	/* register connects the agent to the mpdc network.
	   The agent sends its certificate and downloads the dla certificate. */

	qsc_mutex mtx;
	mpdc_protocol_errors merr;
	bool dres;

	if (mpdc_server_topology_root_exists(&m_agent_application_state) == true)
	{
		/* check if already registered, and rejoin */
		if (m_agent_local_certificate.designation == mpdc_network_designation_agent &&
			m_agent_application_state.dla.designation == mpdc_network_designation_dla)
		{
			/* notify that agent is already joined to a network */
			dres = mpdc_menu_print_predefined_message_confirm(mpdc_application_register_existing, m_agent_application_state.mode, m_agent_application_state.hostname);
		}
		else
		{
			dres = true;
		}

		if (dres == true)
		{
			mpdc_network_register_request_state jrs = {
				.address = address,
				.lcert = &m_agent_local_certificate,
				.rcert = &m_agent_application_state.dla,
				.root = &m_agent_application_state.root,
				.sigkey = m_agent_application_state.sigkey
			};

			/* create and send the join request */
			merr = mpdc_network_register_request(&jrs);

			if (merr == mpdc_protocol_error_none)
			{
				char fpath[MPDC_STORAGE_PATH_MAX] = { 0 };

				mtx = qsc_async_mutex_lock_ex();

				/* register the dla certificate in the topology */
				mpdc_topology_child_register(&m_agent_application_state.tlist, &m_agent_application_state.dla, address);
				mpdc_server_topology_to_file(&m_agent_application_state);
				/* save the dla certificate to file */
				mpdc_server_child_certificate_path_from_issuer(&m_agent_application_state, fpath, sizeof(fpath), m_agent_application_state.dla.issuer);

				if (mpdc_certificate_child_struct_to_file(fpath, &m_agent_application_state.dla) == true)
				{
					m_agent_application_state.joined = true;
				}
				else
				{
					merr = mpdc_protocol_error_file_not_written;
				}

				qsc_async_mutex_unlock_ex(mtx);
			}
		}
		else
		{
			merr = mpdc_protocol_error_operation_cancelled;
		}
	}
	else
	{
		merr = mpdc_protocol_error_certificate_not_found;
	}

 	return merr;
}

static void agent_reset_topology(void)
{
	mpdc_topology_node_state node = { 0 };
	qsc_list_state lstate = { 0 };
	uint8_t item[MPDC_CERTIFICATE_SERIAL_SIZE] = { 0U };

	mpdc_server_topology_remove_certificate(&m_agent_application_state, m_agent_application_state.dla.issuer);
	qsc_memutils_clear(&m_agent_application_state.dla, sizeof(mpdc_child_certificate));
	qsc_collection_erase(&m_agent_mfk_collection);
	qsc_list_initialize(&lstate, MPDC_CERTIFICATE_SERIAL_SIZE);

	/* remove topological nodes except for root and local */
	for (size_t i = 0U; i < m_agent_application_state.tlist.count; ++i)
	{
		if (mpdc_topology_list_item(&m_agent_application_state.tlist, &node, i) == true)
		{
			if (node.designation != mpdc_network_designation_rds &&
				qsc_stringutils_strings_equal(m_agent_application_state.issuer, node.issuer) == false)
			{
				qsc_list_add(&lstate, node.serial);
			}
		}
	}

	for (size_t i = 0U; i < lstate.count; ++i)
	{
		qsc_list_item(&lstate, item, i);
		mpdc_topology_node_remove(&m_agent_application_state.tlist, item);
	}
}

static mpdc_protocol_errors agent_resign_request(const char* address)
{
	MPDC_ASSERT(address != NULL);

	/* resigning removes the dla from the topology, 
	   and deletes the dla certificate and database entry */

	mpdc_topology_node_state lnode = { 0 };
	mpdc_protocol_errors merr;
	
	if (m_agent_application_state.joined == true)
	{
		if (mpdc_topology_node_find_issuer(&m_agent_application_state.tlist, &lnode, m_agent_local_certificate.issuer) == true)
		{
			mpdc_network_resign_request_state rrs = {
				.address = address,
				.lnode = &lnode,
				.sigkey = m_agent_application_state.sigkey
			};

			/* send the resign request to the dla */
			merr = mpdc_network_resign_request(&rrs);

			if (merr == mpdc_protocol_error_none)
			{
				/* reset topology, mfks, signing-key, local, dla, and root certificates */
				agent_reset_topology();
			}
		}
		else
		{
			merr = mpdc_protocol_error_node_not_found;
		}
	}
	else
	{
		merr = mpdc_protocol_error_invalid_request;
	}

	return merr;
}

static mpdc_protocol_errors agent_revoke_response(const mpdc_network_packet* packetin)
{
	MPDC_ASSERT(packetin != NULL);

	mpdc_topology_node_state rnode = { 0 };
	qsc_mutex mtx;
	mpdc_protocol_errors merr;

	mpdc_network_revoke_response_state crs = {
		.dcert = &m_agent_application_state.dla,
		.list = &m_agent_application_state.tlist,
		.rnode = &rnode
	};

	merr = mpdc_network_revoke_response(&crs, packetin);

	if (merr == mpdc_protocol_error_none)
	{
		mtx = qsc_async_mutex_lock_ex();

		qsc_collection_remove(&m_agent_mfk_collection, rnode.serial);
		mpdc_server_topology_remove_certificate(&m_agent_application_state, rnode.issuer);
		mpdc_server_topology_remove_node(&m_agent_application_state, rnode.issuer);
		mpdc_server_topology_to_file(&m_agent_application_state);

		qsc_async_mutex_unlock_ex(mtx);
	}

	return merr;
}

static mpdc_protocol_errors agent_incremental_update_response(const qsc_socket* csock, const mpdc_network_packet* packetin)
{
	MPDC_ASSERT(csock != NULL);
	MPDC_ASSERT(packetin != NULL);

	mpdc_topology_node_state rnode = { 0 };
	mpdc_protocol_errors merr;

	if (mpdc_topology_node_find(&m_agent_application_state.tlist, &rnode, packetin->pmessage) == true)
	{
		mpdc_child_certificate rcert = { 0 };

		if (mpdc_server_child_certificate_from_issuer(&rcert, &m_agent_application_state, rnode.issuer) == true)
		{
			mpdc_network_incremental_update_response_state urs = {
				.csock = csock,
				.rcert = &rcert,
				.sigkey = m_agent_application_state.sigkey
			};

			/* create and send the incremental update */
			merr = mpdc_network_incremental_update_response(&urs, packetin);
		}
		else
		{
			merr = mpdc_protocol_error_certificate_not_found;
		}
	}
	else
	{
		merr = mpdc_protocol_error_node_not_found;
	}

	return merr;
}

static void agent_receive_loop(void* ras)
{
	MPDC_ASSERT(ras != NULL);

	mpdc_network_packet pkt = { 0 };

	uint8_t* buff;
	const char* cmsg;
	agent_receive_state* pras;
	size_t mlen;
	size_t plen;
	mpdc_protocol_errors merr;

	pras = (agent_receive_state*)ras;
	merr = mpdc_protocol_error_none;

	if (pras != NULL)
	{
		buff = (uint8_t*)qsc_memutils_malloc(QSC_SOCKET_TERMINATOR_SIZE);

		if (buff != NULL)
		{
			if (pras->csock.connection_status == qsc_socket_state_connected)
			{
				uint8_t hdr[MPDC_PACKET_HEADER_SIZE] = { 0U };

				mlen = 0U;
				plen = qsc_socket_peek(&pras->csock, hdr, sizeof(hdr));

				if (plen == sizeof(hdr))
				{
					mpdc_packet_header_deserialize(hdr, &pkt);

					if (pkt.msglen > 0U && pkt.msglen <= MPDC_MESSAGE_MAX_SIZE)
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
							mpdc_server_log_write_message(&m_agent_application_state, mpdc_application_log_allocation_failure, (const char*)pras->csock.address, QSC_SOCKET_ADDRESS_MAX_SIZE);
						}
					}
					else
					{
						merr = mpdc_protocol_error_invalid_request;
						mpdc_server_log_write_message(&m_agent_application_state, mpdc_application_log_receive_failure, (const char*)pras->csock.address, QSC_SOCKET_ADDRESS_MAX_SIZE);
					}

					if (mlen > 0U)
					{
						pkt.pmessage = buff + MPDC_PACKET_HEADER_SIZE;

						if (pkt.flag == mpdc_network_flag_tunnel_connection_terminate)
						{
							mpdc_server_log_write_message(&m_agent_application_state, mpdc_application_log_connection_terminated, (const char*)pras->csock.address, QSC_SOCKET_ADDRESS_MAX_SIZE);
						}
						/* agent messages */
						else if (pkt.flag == mpdc_network_flag_network_converge_request)
						{
							/* sent by the dla, preceedes the mfk exchange */
							merr = agent_converge_response(&pras->csock, &pkt);

							if (merr == mpdc_protocol_error_none)
							{
								mpdc_server_log_write_message(&m_agent_application_state, mpdc_application_log_convergence_success, (const char*)pras->csock.address, QSC_SOCKET_ADDRESS_MAX_SIZE);
							}
							else
							{
								cmsg = mpdc_protocol_error_to_string(merr);

								if (cmsg != NULL)
								{
									mpdc_logger_write_time_stamped_message(m_agent_application_state.logpath, cmsg, qsc_stringutils_string_size(cmsg));
								}

								mpdc_server_log_write_message(&m_agent_application_state, mpdc_application_log_convergence_failure, (const char*)pras->csock.address, QSC_SOCKET_ADDRESS_MAX_SIZE);
							}
						}
						else if (pkt.flag == mpdc_network_flag_network_revocation_broadcast)
						{
							/* sent by the dla, revoking a certificate; on an agent, used only for server revocations */

							merr = agent_revoke_response(&pkt);

							if (merr == mpdc_protocol_error_none)
							{
								mpdc_server_log_write_message(&m_agent_application_state, mpdc_application_log_revocation_success, (const char*)pras->csock.address, QSC_SOCKET_ADDRESS_MAX_SIZE);
							}
							else
							{
								cmsg = mpdc_protocol_error_to_string(merr);

								if (cmsg != NULL)
								{
									mpdc_logger_write_time_stamped_message(m_agent_application_state.logpath, cmsg, qsc_stringutils_string_size(cmsg));
								}

								mpdc_server_log_write_message(&m_agent_application_state, mpdc_application_log_revocation_failure, (const char*)pras->csock.address, QSC_SOCKET_ADDRESS_MAX_SIZE);
							}
						}
						else if (pkt.flag == mpdc_network_flag_fragment_query_request)
						{
							/* sent by the server or client, requesting an encrypted fragment key */
							merr = agent_fragment_query_response(&pras->csock, &pkt);

							if (merr == mpdc_protocol_error_none)
							{
								mpdc_server_log_write_message(&m_agent_application_state, mpdc_application_log_fragment_exchange_success, (const char*)pras->csock.address, QSC_SOCKET_ADDRESS_MAX_SIZE);
							}
							else
							{
								cmsg = mpdc_protocol_error_to_string(merr);

								if (cmsg != NULL)
								{
									mpdc_logger_write_time_stamped_message(m_agent_application_state.logpath, cmsg, qsc_stringutils_string_size(cmsg));
								}

								mpdc_server_log_write_message(&m_agent_application_state, mpdc_application_log_fragment_exchange_failure, (const char*)pras->csock.address, QSC_SOCKET_ADDRESS_MAX_SIZE);
							}
						}
						else if (pkt.flag == mpdc_network_flag_incremental_update_request)
						{
							/* sent by a client or server, requesting an agents topological info */
							merr = agent_incremental_update_response(&pras->csock, &pkt);

							if (merr == mpdc_protocol_error_none)
							{
								mpdc_server_log_write_message(&m_agent_application_state, mpdc_application_log_incremental_success, (const char*)pras->csock.address, QSC_SOCKET_ADDRESS_MAX_SIZE);
							}
							else
							{
								cmsg = mpdc_protocol_error_to_string(merr);

								if (cmsg != NULL)
								{
									mpdc_logger_write_time_stamped_message(m_agent_application_state.logpath, cmsg, qsc_stringutils_string_size(cmsg));
								}

								mpdc_server_log_write_message(&m_agent_application_state, mpdc_application_log_incremental_failure, (const char*)pras->csock.address, QSC_SOCKET_ADDRESS_MAX_SIZE);
							}
						}
						else if (pkt.flag == mpdc_network_flag_mfk_request)
						{
							/* sent by a client or server, requesting an mfk exchange */

							merr = agent_mfk_response(&pras->csock, &pkt);

							if (merr == mpdc_protocol_error_none)
							{
								mpdc_server_log_write_message(&m_agent_application_state, mpdc_application_log_mfk_exchange_success, (const char*)pras->csock.address, QSC_SOCKET_ADDRESS_MAX_SIZE);
							}
							else
							{
								cmsg = mpdc_protocol_error_to_string(merr);

								if (cmsg != NULL)
								{
									mpdc_logger_write_time_stamped_message(m_agent_application_state.logpath, cmsg, qsc_stringutils_string_size(cmsg));
								}

								mpdc_server_log_write_message(&m_agent_application_state, mpdc_application_log_mfk_exchange_failure, (const char*)pras->csock.address, QSC_SOCKET_ADDRESS_MAX_SIZE);
							}
						}
						else if (pkt.flag == mpdc_network_flag_system_error_condition)
						{
							/* log the error condition */
							cmsg = mpdc_protocol_error_to_string((mpdc_protocol_errors)pkt.pmessage[0]);

							if (cmsg != NULL)
							{
								mpdc_logger_write_time_stamped_message(m_agent_application_state.logpath, cmsg, qsc_stringutils_string_size(cmsg));
							}

							mpdc_server_log_write_message(&m_agent_application_state, mpdc_application_log_remote_reported_error, (const char*)pras->csock.address, QSC_SOCKET_ADDRESS_MAX_SIZE);
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
									mpdc_server_log_write_message(&m_agent_application_state, mpdc_application_log_connection_terminated, (const char*)pras->csock.address, QSC_SOCKET_ADDRESS_MAX_SIZE);
								}
							}
							else
							{
								mpdc_network_send_error(&pras->csock, mpdc_protocol_error_invalid_request);
								mpdc_server_log_write_message(&m_agent_application_state, mpdc_application_log_remote_invalid_request, (const char*)pras->csock.address, QSC_SOCKET_ADDRESS_MAX_SIZE);
							}
						}
					}
				}
			}

			qsc_memutils_alloc_free(buff);
		}

		/* close the connection */
		mpdc_network_socket_dispose(&pras->csock);

		/* free the socket from memory */
		qsc_memutils_alloc_free(pras);
		pras = NULL;
	}
}

#if defined(MPDC_NETWORK_PROTOCOL_IPV6)

static void agent_ipv6_server_start(void)
{
	qsc_socket lsock = { 0 };
	qsc_ipinfo_ipv6_address addt = { 0 };
	qsc_socket_exceptions serr;

	addt = qsc_ipinfo_ipv6_address_from_string(m_agent_application_state.localip);

	if (qsc_ipinfo_ipv6_address_is_valid(&addt) == true)
	{
		qsc_socket_server_initialize(&lsock);
		serr = qsc_socket_create(&lsock, qsc_socket_address_family_ipv6, qsc_socket_transport_stream, qsc_socket_protocol_tcp);

		if (serr == qsc_socket_exception_success)
		{
			serr = qsc_socket_bind_ipv6(&lsock, &addt, MPDC_APPLICATION_AGENT_PORT);

			if (serr == qsc_socket_exception_success)
			{
				serr = qsc_socket_listen(&lsock, QSC_SOCKET_SERVER_LISTEN_BACKLOG);

				if (serr == qsc_socket_exception_success)
				{
					while (true)
					{
						agent_receive_state* ras;

						ras = (agent_receive_state*)qsc_memutils_malloc(sizeof(agent_receive_state));

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
								mpdc_server_log_write_message(&m_agent_application_state, mpdc_application_log_allocation_failure, (const char*)lsock.address, QSC_SOCKET_ADDRESS_MAX_SIZE);
							}

							if (serr == qsc_socket_exception_success)
							{
								qsc_async_thread_create(&agent_receive_loop, ras);
							}
							else
							{
								/* free the resources if connect fails */
								qsc_memutils_alloc_free(ras);
								mpdc_server_log_write_message(&m_agent_application_state, mpdc_application_log_allocation_failure, (const char*)lsock.address, QSC_SOCKET_ADDRESS_MAX_SIZE);
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

static void agent_ipv4_server_start(void)
{
	qsc_socket lsock = { 0 };
	qsc_ipinfo_ipv4_address addt = { 0 };
	qsc_socket_exceptions serr;

	addt = qsc_ipinfo_ipv4_address_from_string(m_agent_application_state.localip);

	if (qsc_ipinfo_ipv4_address_is_valid(&addt) == true)
	{
		qsc_socket_server_initialize(&lsock);
		serr = qsc_socket_create(&lsock, qsc_socket_address_family_ipv4, qsc_socket_transport_stream, qsc_socket_protocol_tcp);

		if (serr == qsc_socket_exception_success)
		{
			serr = qsc_socket_bind_ipv4(&lsock, &addt, MPDC_APPLICATION_AGENT_PORT);

			if (serr == qsc_socket_exception_success)
			{
				serr = qsc_socket_listen(&lsock, QSC_SOCKET_SERVER_LISTEN_BACKLOG);

				if (serr == qsc_socket_exception_success)
				{
					while (true)
					{
						agent_receive_state* ras;

						ras = (agent_receive_state*)qsc_memutils_malloc(sizeof(agent_receive_state));

						if (ras != NULL)
						{
							qsc_memutils_clear(&ras->csock, sizeof(qsc_socket));

							if (serr == qsc_socket_exception_success)
							{
								serr = qsc_socket_accept(&lsock, &ras->csock);
							}

							if (serr == qsc_socket_exception_success)
							{
								qsc_async_thread_create(&agent_receive_loop, ras);
							}
							else
							{
								/* free the resources if connect fails */
								qsc_memutils_alloc_free(ras);
								mpdc_server_log_write_message(&m_agent_application_state, mpdc_application_log_allocation_failure, (const char*)lsock.address, QSC_SOCKET_ADDRESS_MAX_SIZE);
							}
						}
						else
						{
							/* exit on memory allocation failure */
							mpdc_server_log_write_message(&m_agent_application_state, mpdc_application_log_allocation_failure, (const char*)lsock.address, QSC_SOCKET_ADDRESS_MAX_SIZE);
						}
					};
				}
			}
		}
	}
}

#endif

static void agent_server_dispose(void)
{
	m_agent_command_loop_status = mpdc_server_loop_status_stopped;
	mpdc_server_state_unload(&m_agent_application_state);
	mpdc_server_state_initialize(&m_agent_application_state, mpdc_network_designation_agent);
	qsc_collection_dispose(&m_agent_mfk_collection);
	qsc_memutils_clear(&m_agent_application_state.dla, sizeof(mpdc_child_certificate));
	qsc_memutils_clear(&m_agent_local_certificate, sizeof(mpdc_child_certificate));
	m_agent_command_loop_status = mpdc_server_loop_status_stopped;
	m_agent_server_loop_status = mpdc_server_loop_status_stopped;
	m_agent_idle_timer = 0U;
}

static bool agent_server_load_root(void)
{
	bool res;

	res = false;

	/* load the root certificate */
	if (mpdc_server_topology_root_fetch(&m_agent_application_state, &m_agent_application_state.root) == true)
	{
		res = mpdc_topology_node_verify_root(&m_agent_application_state.tlist, &m_agent_application_state.root);
	}

	return res;
}

static bool agent_server_load_dla(void)
{
	bool res;

	res = false;

	/* load the dla certificate */
	if (mpdc_server_topology_dla_fetch(&m_agent_application_state, &m_agent_application_state.dla) == true)
	{
		/* check the dla certificate structure */
		if (mpdc_certificate_child_is_valid(&m_agent_application_state.dla) == true)
		{
			/* verify the root signature */
			if (mpdc_certificate_root_signature_verify(&m_agent_application_state.dla, &m_agent_application_state.root) == true)
			{
				/* verify a hash of the certificate against the hash stored on the topological node */
				res = mpdc_topology_node_verify_dla(&m_agent_application_state.tlist, &m_agent_application_state.dla);
			}
		}
	}

	return res;
}

static bool agent_server_load_local(void)
{
	bool res;

	res = false;

	/* load the local agent certificate */
	if (mpdc_server_topology_local_fetch(&m_agent_application_state, &m_agent_local_certificate) == true)
	{
		/* check the agent certificate format */
		if (mpdc_certificate_child_is_valid(&m_agent_local_certificate) == true)
		{
			/* verify the root certificate */
			if (mpdc_certificate_root_signature_verify(&m_agent_local_certificate, &m_agent_application_state.root) == true)
			{
				/* verify a hash of the certificate against the hash stored on the topological node */
				res = mpdc_topology_node_verify_issuer(&m_agent_application_state.tlist, &m_agent_local_certificate, m_agent_application_state.issuer);
			}
		}
	}

	return res;
}

static bool agent_server_service_start(void)
{
	/* initialize the mfk array */
	qsc_collection_initialize(&m_agent_mfk_collection, MPDC_CRYPTO_SYMMETRIC_KEY_SIZE);
	mpdc_server_mfkcol_from_file(&m_agent_mfk_collection, &m_agent_application_state);

#if defined(MPDC_NETWORK_PROTOCOL_IPV6)
	/* start the main receive loop on a new thread */
	if (qsc_async_thread_create_noargs(&agent_ipv6_server_start))
#else
	if (qsc_async_thread_create_noargs(&agent_ipv4_server_start))
#endif
	{
		m_agent_server_loop_status = mpdc_server_loop_status_started;
	}

	return (m_agent_server_loop_status == mpdc_server_loop_status_started);
}

static bool agent_certificate_export(const char* cmsg)
{
	MPDC_ASSERT(cmsg != NULL);

	bool res;

	res = mpdc_server_child_certificate_export(&m_agent_application_state, cmsg);

	return res;
}

static bool agent_certificate_import(const char* cmsg)
{
	MPDC_ASSERT(cmsg != NULL);

	bool res;

	if (m_agent_server_loop_status == mpdc_server_loop_status_started)
	{
		m_agent_server_loop_status = mpdc_server_loop_status_paused;
	}

	res = mpdc_server_child_certificate_import(&m_agent_local_certificate , &m_agent_application_state, cmsg);

	if (m_agent_server_loop_status == mpdc_server_loop_status_paused)
	{
		res = agent_server_service_start();
	}

	return res;
}

/* application functions */

static void agent_get_command_mode(const char* command)
{
	MPDC_ASSERT(command != NULL);

	mpdc_console_modes nmode;

	nmode = m_agent_application_state.mode;

	switch (m_agent_application_state.mode)
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
				if (qsc_consoleutils_line_equals(command, "show") == false)
				{
					nmode = mpdc_console_mode_config;
				}
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

	m_agent_application_state.mode = nmode;
}

static void agent_set_command_action(const char* command)
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
		if (m_agent_application_state.mode == mpdc_console_mode_config)
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
		else if (m_agent_application_state.mode == mpdc_console_mode_certificate)
		{
			if (qsc_consoleutils_line_equals(command, "exit"))
			{
				res = mpdc_command_action_certificate_exit;
			}
			else if (qsc_consoleutils_line_contains(command, "export "))
			{
				res = mpdc_command_action_certificate_export;
			}
			else if (qsc_consoleutils_line_contains(command, "generate "))
			{
				res = mpdc_command_action_certificate_generate;
			}
			else if (qsc_consoleutils_line_equals(command, "help"))
			{
				res = mpdc_command_action_certificate_help;
			}
			else if (qsc_consoleutils_line_contains(command, "import "))
			{
				res = mpdc_command_action_certificate_import;
			}
			else if (qsc_consoleutils_line_equals(command, "print"))
			{
				res = mpdc_command_action_certificate_print;
			}
		}
		else if (m_agent_application_state.mode == mpdc_console_mode_server)
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
			else if (qsc_consoleutils_line_equals(command, "list"))
			{
				res = mpdc_command_action_server_list;
			}
			else if (qsc_consoleutils_line_contains(command, "register "))
			{
				res = mpdc_command_action_server_register;
			}
			else if (qsc_consoleutils_line_contains(command, "resign "))
			{
				res = mpdc_command_action_server_resign;
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
		else if (m_agent_application_state.mode == mpdc_console_mode_enable)
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
		else if (m_agent_application_state.mode == mpdc_console_mode_user)
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

	m_agent_application_state.action = res;
}

static void agent_command_execute(const char* command)
{
	MPDC_ASSERT(command != NULL);

	const char* cmsg;
	size_t slen;
	mpdc_protocol_errors merr;
	bool res;

	switch (m_agent_application_state.action)
	{
	case mpdc_command_action_config_clear_all:
	{
		if (mpdc_menu_print_predefined_message_confirm(mpdc_application_erase_erase_all, m_agent_application_state.mode, m_agent_application_state.hostname) == true)
		{
			mpdc_server_erase_all(&m_agent_application_state);
			mpdc_menu_print_predefined_message(mpdc_application_system_erased, m_agent_application_state.mode, m_agent_application_state.hostname);
		}
		else
		{
			mpdc_menu_print_predefined_message(mpdc_application_operation_aborted, m_agent_application_state.mode, m_agent_application_state.hostname);
		}

		break;
	}
	case mpdc_command_action_config_clear_config:
	{
		if (mpdc_menu_print_predefined_message_confirm(mpdc_application_erase_config, mpdc_console_mode_config, m_agent_application_state.hostname) == true)
		{
			mpdc_server_log_write_message(&m_agent_application_state, mpdc_application_log_configuration_erased, m_agent_application_state.username, qsc_stringutils_string_size(m_agent_application_state.username));
			mpdc_server_clear_config(&m_agent_application_state);
			mpdc_menu_print_predefined_message(mpdc_application_configuration_erased, m_agent_application_state.mode, m_agent_application_state.hostname);
		}
		else
		{
			mpdc_menu_print_predefined_message(mpdc_application_operation_aborted, m_agent_application_state.mode, m_agent_application_state.hostname);
		}

		break;
	}
	case mpdc_command_action_config_clear_log:
	{
		if (mpdc_menu_print_predefined_message_confirm(mpdc_application_erase_log, mpdc_console_mode_config, m_agent_application_state.hostname) == true)
		{
			mpdc_server_clear_log(&m_agent_application_state);
			mpdc_menu_print_predefined_message(mpdc_application_log_erased, m_agent_application_state.mode, m_agent_application_state.hostname);
		}
		else
		{
			mpdc_menu_print_predefined_message(mpdc_application_operation_aborted, m_agent_application_state.mode, m_agent_application_state.hostname);
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
		mpdc_help_print_mode(m_agent_application_state.cmdprompt, mpdc_console_mode_config, m_agent_application_state.srvtype);
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
				m_agent_application_state.loghost = true;
				mpdc_server_log_host(&m_agent_application_state);
				mpdc_menu_print_predefined_message(mpdc_application_logging_enabled, m_agent_application_state.mode, m_agent_application_state.hostname);
			}
			else if (qsc_stringutils_string_contains(cmsg, "disable"))
			{
				/* disable logging */
				m_agent_application_state.loghost = false;
				mpdc_server_log_host(&m_agent_application_state);
				mpdc_menu_print_predefined_message(mpdc_application_logging_disabled, m_agent_application_state.mode, m_agent_application_state.hostname);
			}
			else
			{
				mpdc_menu_print_predefined_message(mpdc_application_not_recognized, m_agent_application_state.mode, m_agent_application_state.hostname);
				mpdc_help_print_context(m_agent_application_state.cmdprompt, mpdc_command_action_config_log_host);
			}
		}
		else
		{
			mpdc_menu_print_predefined_message(mpdc_application_not_recognized, m_agent_application_state.mode, m_agent_application_state.hostname);
			mpdc_help_print_context(m_agent_application_state.cmdprompt, mpdc_command_action_config_log_host);
		}

		break;
	}
	case mpdc_command_action_config_name_domain:
	{
		cmsg = qsc_stringutils_reverse_sub_string(command, " ");

		if (cmsg != NULL)
		{
			slen = qsc_stringutils_string_size(cmsg);

			if (mpdc_server_set_domain_name(&m_agent_application_state, cmsg, slen) == false)
			{
				mpdc_menu_print_predefined_message(mpdc_application_domain_invalid, m_agent_application_state.mode, m_agent_application_state.hostname);
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

			if (mpdc_server_set_host_name(&m_agent_application_state, cmsg, slen) == false)
			{
				mpdc_menu_print_predefined_message(mpdc_application_hostname_invalid, m_agent_application_state.mode, m_agent_application_state.hostname);
			}
		}

		break;
	}
	case mpdc_command_action_config_retries:
	{
		cmsg = qsc_stringutils_reverse_sub_string(command, " ");

		if (cmsg != NULL)
		{
			slen = qsc_stringutils_string_size(cmsg);

			if (mpdc_server_set_password_retries(&m_agent_application_state, cmsg, slen) == false)
			{
				/* invalid message */
				mpdc_menu_print_predefined_message(mpdc_application_retry_invalid, m_agent_application_state.mode, m_agent_application_state.hostname);
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

			if (mpdc_server_set_console_timeout(&m_agent_application_state, cmsg, slen) == false)
			{
				/* invalid message */
				mpdc_menu_print_predefined_message(mpdc_application_timeout_invalid, m_agent_application_state.mode, m_agent_application_state.hostname);
			}
		}

		break;
	}
	case mpdc_command_action_certificate_exit:
	{
		/* mode change, do nothing */
		break;
	}
	case mpdc_command_action_certificate_generate:
	{
		cmsg = qsc_stringutils_reverse_sub_string(command, " ");

		if (cmsg != NULL)
		{

			res = agent_certificate_generate(cmsg);

			if (res == true)
			{
				char fpath[MPDC_STORAGE_PATH_MAX] = { 0 };

				mpdc_server_child_certificate_path(&m_agent_application_state, fpath, sizeof(fpath));
				slen = qsc_stringutils_string_size(fpath);

				mpdc_menu_print_predefined_message(mpdc_application_generate_key_success, m_agent_application_state.mode, m_agent_application_state.hostname);
				mpdc_menu_print_message(fpath, m_agent_application_state.mode, m_agent_application_state.hostname);

				mpdc_server_log_write_message(&m_agent_application_state, mpdc_application_log_generate_success, fpath, slen);
			}
			else
			{
				mpdc_menu_print_predefined_message(mpdc_application_generate_key_failure, m_agent_application_state.mode, m_agent_application_state.hostname);
				mpdc_server_log_write_message(&m_agent_application_state, mpdc_application_log_generate_failure, NULL, 0U);
			}
		}

		break;
	}
	case mpdc_command_action_certificate_help:
	{
		mpdc_help_print_mode(m_agent_application_state.cmdprompt, mpdc_console_mode_certificate, m_agent_application_state.srvtype);
		break;
	}
	case mpdc_command_action_certificate_import:
	{
		cmsg = qsc_stringutils_reverse_sub_string(command, " ");
		res = false;

		if (cmsg != NULL)
		{
			res = agent_certificate_import(cmsg);
		}

		if (res == true)
		{
			mpdc_menu_print_predefined_message(mpdc_application_import_certificate_success, m_agent_application_state.mode, m_agent_application_state.hostname);
		}
		else
		{
			mpdc_menu_print_predefined_message(mpdc_application_import_certificate_failure, m_agent_application_state.mode, m_agent_application_state.hostname);
		}

		break;
	}
	case mpdc_command_action_certificate_print:
	{
		char fpath[MPDC_STORAGE_PATH_MAX] = { 0 };

		res = false;
		mpdc_server_child_certificate_path(&m_agent_application_state, fpath, sizeof(fpath));

		if (qsc_fileutils_exists(fpath) == true)
		{
			res = mpdc_server_child_certificate_print(fpath, sizeof(fpath));
		}

		if (res == false)
		{
			mpdc_menu_print_predefined_message(mpdc_application_client_pubkey_path_invalid, m_agent_application_state.mode, m_agent_application_state.hostname);
		}

		break;
	}
	case mpdc_command_action_server_backup:
	{
		slen = qsc_stringutils_string_size(m_agent_application_state.hostname);
		mpdc_server_state_backup_save(&m_agent_application_state);
		mpdc_server_log_write_message(&m_agent_application_state, mpdc_application_log_state_backup, m_agent_application_state.hostname, slen);
		mpdc_menu_print_predefined_message(mpdc_application_server_backup_save_confirmation, m_agent_application_state.mode, m_agent_application_state.hostname);

		break;
	}
	case mpdc_command_action_server_exit:
	{
		/* mode change, do nothing */
		break;
	}
	case mpdc_command_action_certificate_export:
	{
		cmsg = qsc_stringutils_reverse_sub_string(command, " ");
		res = false;

		if (cmsg != NULL)
		{
			res = agent_certificate_export(cmsg);
		}

		if (res == true)
		{
			mpdc_menu_print_predefined_message(mpdc_application_export_certificate_success, m_agent_application_state.mode, m_agent_application_state.hostname);
		}
		else
		{
			mpdc_menu_print_predefined_message(mpdc_application_export_certificate_failure, m_agent_application_state.mode, m_agent_application_state.hostname);
		}

		break;
	}
	case mpdc_command_action_server_help:
	{
		/* show config-server help */
		mpdc_help_print_mode(m_agent_application_state.cmdprompt, mpdc_console_mode_server, m_agent_application_state.srvtype);
		break;
	}
	case mpdc_command_action_server_list:
	{
		mpdc_server_topology_print_list(&m_agent_application_state);

		break;
	}
	case mpdc_command_action_server_register:
	{
		/* sends the root signed certificate to the dla and joins the network
		* dla gets request and sends back confirm, and triggers mfk exchange */
		if (m_agent_server_loop_status == mpdc_server_loop_status_started)
		{
			cmsg = qsc_stringutils_reverse_sub_string(command, " ");

			if (cmsg != NULL)
			{
				slen = qsc_stringutils_string_size(cmsg);

				if (slen > 0U)
				{
					merr = agent_register_request(cmsg);

					if (merr == mpdc_protocol_error_none)
					{
						mpdc_menu_print_predefined_message(mpdc_application_register_success, m_agent_application_state.mode, m_agent_application_state.hostname);
						mpdc_server_log_write_message(&m_agent_application_state, mpdc_application_log_register_success, cmsg, slen);
					}
					else
					{
						mpdc_menu_print_predefined_message(mpdc_application_register_failure, m_agent_application_state.mode, m_agent_application_state.hostname);

						cmsg = mpdc_protocol_error_to_string(merr);

						if (cmsg != NULL)
						{
							mpdc_logger_write_time_stamped_message(m_agent_application_state.logpath, cmsg, slen);
							mpdc_server_log_write_message(&m_agent_application_state, mpdc_application_log_register_failure, cmsg, slen);
						}
					}
				}
				else
				{
					mpdc_menu_print_predefined_message(mpdc_application_invalid_input, m_agent_application_state.mode, m_agent_application_state.hostname);
				}
			}
			else
			{
				mpdc_menu_print_predefined_message(mpdc_application_invalid_input, m_agent_application_state.mode, m_agent_application_state.hostname);
			}
		}
		else
		{
			mpdc_menu_print_predefined_message(mpdc_application_server_service_not_started, m_agent_application_state.mode, m_agent_application_state.hostname);
		}

		break;
	}
	case mpdc_command_action_server_resign:
	{
		if (m_agent_server_loop_status == mpdc_server_loop_status_started)
		{
			cmsg = qsc_stringutils_reverse_sub_string(command, " ");

			if (cmsg != NULL)
			{
				slen = qsc_stringutils_string_size(cmsg);

				if (slen > 0U)
				{
					merr = agent_resign_request(cmsg);

					if (merr == mpdc_protocol_error_none)
					{
						m_agent_application_state.joined = false;
						mpdc_menu_print_predefined_message(mpdc_application_network_resign_success, m_agent_application_state.mode, m_agent_application_state.hostname);
						mpdc_server_log_write_message(&m_agent_application_state, mpdc_application_log_local_resign_success, cmsg, slen);
					}
					else
					{
						mpdc_menu_print_predefined_message(mpdc_application_network_resign_failure, m_agent_application_state.mode, m_agent_application_state.hostname);

						cmsg = mpdc_protocol_error_to_string(merr);

						if (cmsg != NULL)
						{
							mpdc_logger_write_time_stamped_message(m_agent_application_state.logpath, cmsg, slen);
							mpdc_server_log_write_message(&m_agent_application_state, mpdc_application_log_local_resign_failure, cmsg, slen);
						}
					}
				}
				else
				{
					mpdc_menu_print_predefined_message(mpdc_application_invalid_input, m_agent_application_state.mode, m_agent_application_state.hostname);
				}
			}
			else
			{
				mpdc_menu_print_predefined_message(mpdc_application_invalid_input, m_agent_application_state.mode, m_agent_application_state.hostname);
			}
		}
		else
		{
			mpdc_menu_print_predefined_message(mpdc_application_server_service_not_started, m_agent_application_state.mode, m_agent_application_state.hostname);
		}

		break;
	}
	case mpdc_command_action_server_restore:
	{
		bool dres;

		/* notify that server is already joined to a network */
		dres = mpdc_menu_print_predefined_message_confirm(mpdc_application_server_backup_restore_challenge, m_agent_application_state.mode, m_agent_application_state.hostname);
			
		if (dres == true)
		{
			mpdc_server_state_backup_restore(&m_agent_application_state);
			slen = qsc_stringutils_string_size(m_agent_application_state.hostname);
			mpdc_server_log_write_message(&m_agent_application_state, mpdc_application_log_state_restore, m_agent_application_state.hostname, slen);
		}

		break;
	}
	case mpdc_command_action_server_service:
	{
		cmsg = qsc_stringutils_reverse_sub_string(command, " ");

		if (cmsg != NULL)
		{
			slen = qsc_stringutils_string_size(m_agent_application_state.hostname);

			if (qsc_stringutils_string_contains(cmsg, "start"))
			{
				if (m_agent_server_loop_status != mpdc_server_loop_status_started)
				{
					if (agent_server_service_start() == true &&
						m_agent_server_loop_status == mpdc_server_loop_status_started)
					{
						mpdc_menu_print_predefined_message(mpdc_application_server_service_start_success, m_agent_application_state.mode, m_agent_application_state.hostname);
						mpdc_server_log_write_message(&m_agent_application_state, mpdc_application_log_service_started, m_agent_application_state.hostname, slen);
					}
					else
					{
						mpdc_menu_print_predefined_message(mpdc_application_server_service_start_failure, m_agent_application_state.mode, m_agent_application_state.hostname);
					}
				}
			}
			else if (qsc_stringutils_string_contains(cmsg, "stop"))
			{
				if (m_agent_server_loop_status == mpdc_server_loop_status_started)
				{
					m_agent_server_loop_status = mpdc_server_loop_status_stopped;
					mpdc_menu_print_predefined_message(mpdc_application_server_service_stopped, m_agent_application_state.mode, m_agent_application_state.hostname);
					mpdc_server_log_write_message(&m_agent_application_state, mpdc_application_log_service_stopped, m_agent_application_state.hostname, slen);
				}
			}
			else if (qsc_stringutils_string_contains(cmsg, "pause"))
			{
				if (m_agent_server_loop_status != mpdc_server_loop_status_paused)
				{
					m_agent_server_loop_status = mpdc_server_loop_status_paused;
					mpdc_menu_print_predefined_message(mpdc_application_server_service_paused, m_agent_application_state.mode, m_agent_application_state.hostname);
					mpdc_server_log_write_message(&m_agent_application_state, mpdc_application_log_service_paused, m_agent_application_state.hostname, slen);
				}
			}
			else if (qsc_stringutils_string_contains(cmsg, "resume"))
			{
				if (m_agent_server_loop_status == mpdc_server_loop_status_paused)
				{
					m_agent_server_loop_status = mpdc_server_loop_status_started;
					mpdc_menu_print_predefined_message(mpdc_application_server_service_resume_success, m_agent_application_state.mode, m_agent_application_state.hostname);
					mpdc_server_log_write_message(&m_agent_application_state, mpdc_application_log_service_resumed, m_agent_application_state.hostname, slen);
				}
				else
				{
					mpdc_menu_print_predefined_message(mpdc_application_server_service_resume_failure, m_agent_application_state.mode, m_agent_application_state.hostname);
				}
			}
			else
			{
				mpdc_menu_print_predefined_message(mpdc_application_not_recognized, m_agent_application_state.mode, m_agent_application_state.hostname);
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
		mpdc_server_user_logout(&m_agent_application_state);

		break;
	}
	case mpdc_command_action_enable_help:
	{
		/* show enable help */
		mpdc_help_print_mode(m_agent_application_state.cmdprompt, mpdc_console_mode_enable, m_agent_application_state.srvtype);

		break;
	}
	case mpdc_command_action_enable_quit:
	case mpdc_command_action_user_quit:
	{
		agent_server_dispose();
		mpdc_menu_print_predefined_message(mpdc_application_application_quit, m_agent_application_state.mode, m_agent_application_state.hostname);
		mpdc_menu_print_prompt(m_agent_application_state.mode, m_agent_application_state.hostname);
		qsc_consoleutils_get_char();

		break;
	}
	case mpdc_command_action_enable_show_config:
	{
		/* show config */
		mpdc_server_print_configuration(&m_agent_application_state);

		break;
	}
	case mpdc_command_action_enable_show_log:
	{
		/* read the user log */
		mpdc_server_log_print(&m_agent_application_state);
		break;
	}
	case mpdc_command_action_user_enable:
	{
		/* user login */
		if (mpdc_server_user_login(&m_agent_application_state) == true)
		{
			/* load certificates */
			if (agent_server_load_root() == true)
			{
				if (agent_server_load_local() == true)
				{
					m_agent_application_state.joined = agent_server_load_dla();
				}
			}
		}
		else
		{
			mpdc_agent_stop_server();
			mpdc_menu_print_predefined_message(mpdc_application_retries_exceeded, m_agent_application_state.mode, m_agent_application_state.hostname);
			mpdc_menu_print_prompt(m_agent_application_state.mode, m_agent_application_state.hostname);
			qsc_consoleutils_get_char();
		}

		break;
	}
	case mpdc_command_action_user_help:
	{
		/* show user help */
		mpdc_help_print_mode(m_agent_application_state.cmdprompt, mpdc_console_mode_user, m_agent_application_state.srvtype);

		break;
	}
	case mpdc_command_action_config_address:
	{
		cmsg = qsc_stringutils_reverse_sub_string(command, " ");

		if (cmsg != NULL)
		{
			slen = qsc_stringutils_string_size(cmsg);
			res = mpdc_server_set_ip_address(&m_agent_application_state, cmsg, slen);

			if (res == true)
			{
				mpdc_menu_print_predefined_message(mpdc_application_address_change_success, m_agent_application_state.mode, m_agent_application_state.hostname);
			}
			else
			{
				mpdc_menu_print_predefined_message(mpdc_application_address_change_failure, m_agent_application_state.mode, m_agent_application_state.hostname);
			}
		}

		break;
	}
	case mpdc_command_action_config_clear:
	{
		/* show clear help */
		mpdc_help_print_context(m_agent_application_state.cmdprompt, mpdc_command_action_config_clear_all);
		mpdc_help_print_context(m_agent_application_state.cmdprompt, mpdc_command_action_config_clear_config);
		mpdc_help_print_context(m_agent_application_state.cmdprompt, mpdc_command_action_config_clear_log);

		break;
	}
	case mpdc_command_action_config_log:
	{
		/* show log help */
		mpdc_help_print_context(m_agent_application_state.cmdprompt, mpdc_command_action_config_log_host);

		break;
	}
	case mpdc_command_action_config_name:
	{
		/* show name help */
		mpdc_help_print_context(m_agent_application_state.cmdprompt, mpdc_command_action_config_name_domain);
		mpdc_help_print_context(m_agent_application_state.cmdprompt, mpdc_command_action_config_name_host);

		break;
	}
	case mpdc_command_action_help_enable_all:
	{
		/* show enable help */
		mpdc_help_print_mode(m_agent_application_state.cmdprompt, mpdc_console_mode_enable, m_agent_application_state.srvtype);

		break;
	}
	case mpdc_command_action_help_enable_show:
	{
		/* show help */
		mpdc_help_print_context(m_agent_application_state.cmdprompt, mpdc_command_action_enable_show_config);
		mpdc_help_print_context(m_agent_application_state.cmdprompt, mpdc_command_action_enable_show_log);

		break;
	}
	case mpdc_command_action_help_enable_user:
	{
		/* show enable user help */
		mpdc_help_print_mode(m_agent_application_state.cmdprompt, mpdc_console_mode_user, m_agent_application_state.srvtype);

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
		mpdc_menu_print_predefined_message(mpdc_application_not_recognized, m_agent_application_state.mode, m_agent_application_state.hostname);
		mpdc_help_print_mode(m_agent_application_state.cmdprompt, m_agent_application_state.mode, m_agent_application_state.srvtype);
		break;
	}
	default:
	{
		mpdc_help_print_mode(m_agent_application_state.cmdprompt, m_agent_application_state.mode, m_agent_application_state.srvtype);
	}
	}
}

static void agent_idle_timer(void)
{
	const uint32_t MMSEC = 60U * 1000U;

	while (true)
	{
		qsc_mutex mtx = qsc_async_mutex_lock_ex();

		qsc_async_thread_sleep(MMSEC);

		if (m_agent_application_state.mode != mpdc_console_mode_user)
		{
			++m_agent_idle_timer;

			if (m_agent_idle_timer >= m_agent_application_state.timeout)
			{
				mpdc_server_user_logout(&m_agent_application_state);
				m_agent_idle_timer = 0U;
				qsc_consoleutils_print_line("");
				mpdc_menu_print_predefined_message(mpdc_application_console_timeout_expired, m_agent_application_state.mode, m_agent_application_state.hostname);
				mpdc_menu_print_prompt(m_agent_application_state.mode, m_agent_application_state.hostname);
			}
		}

		qsc_async_mutex_unlock_ex(mtx);
	};
}

static void agent_command_loop(char* command)
{
	m_agent_command_loop_status = mpdc_server_loop_status_started;

	while (true)
	{
		qsc_consoleutils_get_line(command, QSC_CONSOLE_MAX_LINE);

		/* lock the mutex */
		qsc_mutex mtx = qsc_async_mutex_lock_ex();
		m_agent_idle_timer = 0U;
		qsc_async_mutex_unlock_ex(mtx);

		agent_set_command_action(command);
		agent_command_execute(command);
		agent_get_command_mode(command);

		qsc_stringutils_clear_string(command);
		mpdc_server_set_command_prompt(&m_agent_application_state);
		mpdc_menu_print_prompt(m_agent_application_state.mode, m_agent_application_state.hostname);

		if (m_agent_command_loop_status == mpdc_server_loop_status_paused)
		{
			qsc_async_thread_sleep(MPDC_STORAGE_SERVER_PAUSE_INTERVAL);
			continue;
		}
		else if (m_agent_command_loop_status == mpdc_server_loop_status_stopped)
		{
			break;
		}
	}
}

/* agent functions */

void mpdc_agent_pause_server(void)
{
	m_agent_command_loop_status = mpdc_server_loop_status_paused;
}

int32_t mpdc_agent_start_server(void)
{
	char command[QSC_CONSOLE_MAX_LINE] = { 0 };
	qsc_thread idle;
	int32_t ret;

	/* initialize the server */
	mpdc_server_state_initialize(&m_agent_application_state, mpdc_network_designation_agent);

	/* set the window parameters */
	qsc_consoleutils_set_virtual_terminal();
	qsc_consoleutils_set_window_size(1000U, 600U);
	qsc_consoleutils_set_window_title(m_agent_application_state.wtitle);

	/* application banner */
	mpdc_server_print_banner(&m_agent_application_state);

	/* load the command prompt */
	agent_get_command_mode(command);
	mpdc_menu_print_prompt(m_agent_application_state.mode, m_agent_application_state.hostname);

	/* start the idle timer */
	m_agent_idle_timer = 0U;
	idle = qsc_async_thread_create_noargs(&agent_idle_timer);
	
	if (idle)
	{
		/* command loop */
		agent_command_loop(command);
		ret = 0;
	}
	else
	{
		mpdc_menu_print_predefined_message(mpdc_application_authentication_failure, m_agent_application_state.mode, m_agent_application_state.hostname);
		ret = -1;
	}

	return (ret == 0);
}

void mpdc_agent_stop_server(void)
{
	m_agent_command_loop_status = mpdc_server_loop_status_stopped;
}
