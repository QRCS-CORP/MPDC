#include "dla.h"
#include "certificate.h"
#include "commands.h"
#include "help.h"
#include "menu.h"
#include "mpdc.h"
#include "network.h"
#include "resources.h"
#include "server.h"
#include "topology.h"
#include "acp.h"
#include "async.h"
#include "consoleutils.h"
#include "fileutils.h"
#include "ipinfo.h"
#include "memutils.h"
#include "socketserver.h"
#include "stringutils.h"
#include "timerex.h"
#include "timestamp.h"

/** \cond */
typedef struct dla_receive_state
{
	qsc_socket csock;
} dla_receive_state;
/** \endcond */

static mpdc_server_application_state m_dla_application_state = { 0 };
static mpdc_server_server_loop_status m_dla_command_loop_status;
static mpdc_server_server_loop_status m_dla_server_loop_status;
static uint64_t m_dla_idle_timer;

/* dla network functions */

static bool dla_certificate_generate(const char* cmsg)
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

		mpdc_server_child_certificate_path(&m_dla_application_state, fpath, sizeof(fpath));
		/* extract the days */
		period = qsc_stringutils_string_to_int(cmsg);
		/* convert to seconds */
		period *= MPDC_PERIOD_DAY_TO_SECONDS;

		/* check that the root is installed */
		res = mpdc_server_topology_root_exists(&m_dla_application_state);

		if (res == false)
		{
			res = mpdc_server_root_import_dialogue(&m_dla_application_state);
		}

		if (res == true && period >= MPDC_CERTIFICATE_MINIMUM_PERIOD || period <= MPDC_CERTIFICATE_MAXIMUM_PERIOD)
		{
			char sadd[MPDC_CERTIFICATE_ADDRESS_SIZE] = { 0 };

			mpdc_network_get_local_address(sadd);

			/* the child certificate is invalid once the root certificate expires,
				if the period is longer than the root, change to the root expiration time */
			if (m_dla_application_state.root.expiration.to < period + qsc_timestamp_epochtime_seconds())
			{
				char tsc[QSC_TIMESTAMP_STRING_SIZE] = { 0 };
				int32_t rtme;

				period = m_dla_application_state.root.expiration.to - qsc_timestamp_epochtime_seconds();
				rtme = (int32_t)period / MPDC_PERIOD_DAY_TO_SECONDS;
				qsc_stringutils_int_to_string(rtme, tsc, sizeof(tsc));

				/* notify user of change in duration */
				mpdc_menu_print_predefined_text(mpdc_application_certificate_period_update, m_dla_application_state.mode, m_dla_application_state.hostname);
				mpdc_menu_print_text_line(tsc);
			}

			if (qsc_fileutils_exists(fpath) == true)
			{
				/* file exists, overwrite challenge */
				if (mpdc_menu_print_predefined_message_confirm(mpdc_application_generate_key_overwrite, m_dla_application_state.mode, m_dla_application_state.hostname) == true)
				{
					nlen = qsc_stringutils_string_size(fpath);
					/* create the certificate and copy the signing key to state */
					mpdc_server_child_certificate_generate(&m_dla_application_state, &m_dla_application_state.dla, period);
					/* write the certificate to file */
					mpdc_server_local_certificate_store(&m_dla_application_state, &m_dla_application_state.dla, sadd);
					/* store the state */
					res = mpdc_server_state_store(&m_dla_application_state);
					/* log the key overwrite */
					mpdc_server_log_write_message(&m_dla_application_state, mpdc_application_log_generate_delete, fpath, nlen);
				}
				else
				{
					mpdc_menu_print_predefined_message(mpdc_application_operation_aborted, m_dla_application_state.mode, m_dla_application_state.hostname);
					res = false;
				}
			}
			else
			{
				mpdc_server_child_certificate_generate(&m_dla_application_state, &m_dla_application_state.dla, period);
				mpdc_server_local_certificate_store(&m_dla_application_state, &m_dla_application_state.dla, sadd);
				res = mpdc_server_state_store(&m_dla_application_state);
			}
		}
		else
		{
			mpdc_menu_print_predefined_message(mpdc_application_invalid_input, m_dla_application_state.mode, m_dla_application_state.hostname);
		}
	}
	else
	{
		mpdc_menu_print_predefined_message(mpdc_application_invalid_input, m_dla_application_state.mode, m_dla_application_state.hostname);
	}

	return res;
}

static mpdc_protocol_errors dla_announce_broadcast(const char* fpath, const char* address)
{
	MPDC_ASSERT(fpath != NULL);
	MPDC_ASSERT(address != NULL);

	qsc_mutex mtx;
	mpdc_protocol_errors merr;

	if (qsc_fileutils_exists(fpath) == true)
	{
#if defined(MPDC_NETWORK_PROTOCOL_IPV6)
		qsc_ipinfo_ipv6_address addt = { 0 };

		addt = qsc_ipinfo_ipv6_address_from_string(address);

		if (qsc_ipinfo_ipv6_address_is_valid(&addt) == true)
		{
#else
		qsc_ipinfo_ipv4_address addt = { 0 };

		addt = qsc_ipinfo_ipv4_address_from_string(address);

		if (qsc_ipinfo_ipv4_address_is_valid(&addt) == true)
		{
#endif
			mpdc_child_certificate rcert = { 0 };

			if (mpdc_certificate_child_file_to_struct(fpath, &rcert) == true)
			{
				merr = mpdc_network_certificate_verify(&rcert, &m_dla_application_state.root);

				if (merr == mpdc_protocol_error_none)
				{
					/* validate the certificate type */
					if (rcert.designation == mpdc_network_designation_agent ||
						rcert.designation == mpdc_network_designation_mas)
					{
						mpdc_topology_node_state rnode = { 0 };

						/* remove the old entry */
						mpdc_topology_node_remove(&m_dla_application_state.tlist, rcert.serial);

						mtx = qsc_async_mutex_lock_ex();

						/* register the node and save the database */
						mpdc_topology_child_register(&m_dla_application_state.tlist, &rcert, address);
						mpdc_server_topology_to_file(&m_dla_application_state);

						qsc_async_mutex_unlock_ex(mtx);

						if (mpdc_topology_node_find_issuer(&m_dla_application_state.tlist, &rnode, rcert.issuer) == true)
						{
							mpdc_network_announce_request_state ars = {
								.list = &m_dla_application_state.tlist,
								.rnode = &rnode,
								.sigkey = m_dla_application_state.sigkey
							};

							/* create and send the announce broadcast */
							merr = mpdc_network_announce_broadcast(&ars);
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
				}
			}
			else
			{
				merr = mpdc_protocol_error_decoding_failure;
			}
		}
		else
		{
			merr = mpdc_protocol_error_no_usable_address;
		}
	}
	else
	{
		merr = mpdc_protocol_error_file_not_found;
	}

	return merr;
}

static void dla_converge_reset(mpdc_topology_list_state* list)
{
	MPDC_ASSERT(list != NULL);

	mpdc_topology_list_state clst = { 0 };

	mpdc_topology_list_initialize(&clst);

	for (size_t i = 0; i < list->count; ++i)
	{
		mpdc_topology_node_state node = { 0 };

		if (mpdc_topology_list_item(list, &node, i) == true)
		{
			if (node.designation != mpdc_network_designation_agent &&
				node.designation != mpdc_network_designation_idg &&
				node.designation != mpdc_network_designation_mas)
			{
				mpdc_topology_child_add_item(&clst, &node);
			}
		}
	}

	if (list->count != clst.count)
	{
		mpdc_topology_list_dispose(list);

		for (size_t i = 0; i < clst.count; ++i)
		{
			mpdc_topology_node_state node = { 0 };

			if (mpdc_topology_list_item(&clst, &node, i) == true)
			{
				mpdc_topology_child_add_item(list, &node);
			}
		}
	}

	mpdc_topology_list_dispose(&clst);
}

static void dla_converge_broadcast(void)
{
	mpdc_topology_list_state clst = { 0 };
	qsc_mutex mtx;
	mpdc_protocol_errors merr;
	
	if (m_dla_application_state.tlist.count > 0)
	{
		mpdc_topology_node_state rnode = { 0 };

		mpdc_topology_list_initialize(&clst);

		/* iterate through nodes in the topology list, copying their signed node to the message */
		for (size_t i = 0; i < m_dla_application_state.tlist.count; ++i)
		{
			if (mpdc_topology_list_item(&m_dla_application_state.tlist, &rnode, i) == true)
			{
				if (rnode.designation == mpdc_network_designation_agent ||
					rnode.designation == mpdc_network_designation_idg ||
					rnode.designation == mpdc_network_designation_mas)
				{
					mpdc_child_certificate rcert = { 0 };

					if (mpdc_server_child_certificate_from_issuer(&rcert, &m_dla_application_state, rnode.issuer) == true)
					{
						mpdc_network_converge_request_state crs = {
							.rcert = &rcert,
							.rnode = &rnode,
							.sigkey = m_dla_application_state.sigkey
						};

						/* process the convergence update */
						merr = mpdc_network_converge_request(&crs);

						if (merr == mpdc_protocol_error_none)
						{
							mpdc_topology_child_add_item(&clst, &rnode);
						}
					}
				}
			}
		}

		for (size_t i = 0; i < m_dla_application_state.tlist.count; ++i)
		{
			mpdc_topology_node_state fnode = { 0 };

			mpdc_topology_list_item(&m_dla_application_state.tlist, &rnode, i);

			if (rnode.designation == mpdc_network_designation_agent ||
				rnode.designation == mpdc_network_designation_idg ||
				rnode.designation == mpdc_network_designation_mas)
			{
				if (mpdc_topology_node_find(&clst, &fnode, rnode.serial) == false)
				{
					mpdc_menu_print_prompt(m_dla_application_state.mode, m_dla_application_state.hostname);
					qsc_consoleutils_print_safe("The remote node: ");
					qsc_consoleutils_print_safe(rnode.issuer);
					qsc_consoleutils_print_line(" did not respond.");

					if (mpdc_menu_print_predefined_message_confirm(mpdc_application_log_converge_node_remove_challenge, m_dla_application_state.mode, m_dla_application_state.hostname) == true)
					{
						mpdc_network_revoke_request_state rrs = {
							.designation = rnode.designation,
							.list = &m_dla_application_state.tlist,
							.rnode = &rnode,
							.sigkey = m_dla_application_state.sigkey
						};

						/* create and send the revocation broadcast */
						merr = mpdc_network_revoke_broadcast(&rrs);

						if (merr == mpdc_protocol_error_none)
						{
							mtx = qsc_async_mutex_lock_ex();

							mpdc_server_topology_remove_certificate(&m_dla_application_state, rnode.issuer);
							mpdc_server_topology_remove_node(&m_dla_application_state, rnode.issuer);
							mpdc_server_topology_to_file(&m_dla_application_state);

							qsc_async_mutex_unlock_ex(mtx);
						}
					}
				}
			}
		}
	}

	mpdc_topology_list_dispose(&clst);
}

static mpdc_protocol_errors dla_incremental_update_response(const qsc_socket* csock, const mpdc_network_packet* packetin)
{
	MPDC_ASSERT(csock != NULL);
	MPDC_ASSERT(packetin != NULL);

	mpdc_topology_node_state rnode = { 0 };
	mpdc_protocol_errors merr;

	if (mpdc_topology_node_find(&m_dla_application_state.tlist, &rnode, packetin->pmessage) == true)
	{
		mpdc_child_certificate rcert = { 0 };

		if (mpdc_server_child_certificate_from_issuer(&rcert, &m_dla_application_state, rnode.issuer) == true)
		{
			mpdc_network_incremental_update_response_state urs = { 
				.csock = csock, 
				.rcert = &rcert, 
				.sigkey = m_dla_application_state.sigkey
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

static mpdc_protocol_errors dla_register_response(const qsc_socket* csock, const mpdc_network_packet* packetin)
{
	MPDC_ASSERT(csock != NULL);
	MPDC_ASSERT(packetin != NULL);

	mpdc_child_certificate rcert = { 0 };
	qsc_mutex mtx;
	mpdc_protocol_errors merr;

	merr = mpdc_protocol_error_invalid_request;

	mpdc_network_register_response_state jrs = {
		.csock = csock,
		.lcert = &m_dla_application_state.dla, 
		.rcert = &rcert,
		.root = &m_dla_application_state.root, 
		.sigkey = m_dla_application_state.sigkey
	};

	/* create and send the join response */
	merr = mpdc_network_register_response(&jrs, packetin);

	if (merr == mpdc_protocol_error_none)
	{
		char rpath[MPDC_STORAGE_PATH_MAX] = { 0 };
		
		if (mpdc_topology_node_exists(&m_dla_application_state.tlist, rcert.serial) == true)
		{
			mpdc_topology_node_remove(&m_dla_application_state.tlist, rcert.serial);
		}

		mtx = qsc_async_mutex_lock_ex();

		/* register the remote device in the topology */
		mpdc_topology_child_register(&m_dla_application_state.tlist, &rcert, csock->address);
		mpdc_server_topology_to_file(&m_dla_application_state);

		qsc_async_mutex_unlock_ex(mtx);

		/* get the certificate path and overwrite existing */
		mpdc_server_child_certificate_path_from_issuer(&m_dla_application_state, rpath, sizeof(rpath), rcert.issuer);

		if (qsc_fileutils_exists(rpath) == true)
		{
			qsc_fileutils_delete(rpath);
		}

		/* save the certificate to file */
		if (mpdc_certificate_child_struct_to_file(rpath, &rcert) == false)
		{
			merr = mpdc_protocol_error_file_not_written;
		}
	}
	else
	{
		merr = mpdc_protocol_error_node_not_found;
	}

	return merr;
}

static mpdc_protocol_errors dla_register_update_response(const qsc_socket* csock, const mpdc_network_packet* packetin)
{
	MPDC_ASSERT(csock != NULL);
	MPDC_ASSERT(packetin != NULL);

	mpdc_child_certificate rcert = { 0 };
	qsc_mutex mtx;
	mpdc_protocol_errors merr;

	merr = mpdc_protocol_error_invalid_request;

	mpdc_network_register_update_response_state rst = {
		.csock = csock,
		.lcert = &m_dla_application_state.dla,
		.list = &m_dla_application_state.tlist,
		.rcert = &rcert,
		.root = &m_dla_application_state.root, 
		.sigkey = m_dla_application_state.sigkey
	};

	/* create and send the join-update response */
	merr = mpdc_network_register_update_response(&rst, packetin);

	if (merr == mpdc_protocol_error_none)
	{
		char rpath[MPDC_STORAGE_PATH_MAX] = { 0 };

		mtx = qsc_async_mutex_lock_ex();

		/* register the remote certificate in the topology */
		mpdc_topology_child_register(&m_dla_application_state.tlist, &rcert, csock->address);
		mpdc_server_topology_to_file(&m_dla_application_state);

		qsc_async_mutex_unlock_ex(mtx);

		/* get the remote certificate path */
		mpdc_server_child_certificate_path_from_issuer(&m_dla_application_state, rpath, sizeof(rpath), rcert.issuer);

		/* save the certificate to file */
		if (mpdc_certificate_child_struct_to_file(rpath, &rcert) == false)
		{
			merr = mpdc_protocol_error_file_not_written;
		}
	}
	else
	{
		merr = mpdc_protocol_error_node_not_found;
	}

	return merr;
}

static bool dla_remote_certificate_verify(mpdc_child_certificate* child)
{
	MPDC_ASSERT(child != NULL);

	bool res;

	res = false;

	if (child != NULL)
	{
		if (child->algorithm == MPDC_CONFIGURATION_SET &&
			child->designation != mpdc_network_designation_none &&
			child->version == MPDC_ACTIVE_VERSION &&
			qsc_memutils_zeroed(child->serial, sizeof(child->serial)) == false &&
			qsc_memutils_zeroed(child->verkey, sizeof(child->verkey)) == false)
		{
			uint64_t nsec;

			nsec = qsc_timestamp_datetime_utc();

			if (nsec >= child->expiration.from && nsec <= child->expiration.to)
			{
				res = true;
			}
		}
	}

	return res;
}

static mpdc_protocol_errors dla_remote_signing_request(const char* fpath)
{
	MPDC_ASSERT(fpath != NULL);
	
	mpdc_topology_node_state root = { 0 };
	mpdc_protocol_errors merr;
	
	if (mpdc_topology_node_find_root(&m_dla_application_state.tlist, &root) == true)
	{
		if (qsc_fileutils_exists(fpath) == true)
		{
			mpdc_child_certificate rcert = { 0 };

			if (mpdc_certificate_child_file_to_struct(fpath, &rcert) == true)
			{
				if (dla_remote_certificate_verify(&rcert) == true)
				{
					mpdc_network_remote_signing_request_state rsr = {
						.address = root.address,
						.rcert = &rcert,
						.root = &m_dla_application_state.root,
						.sigkey = m_dla_application_state.sigkey
					};

					merr = mpdc_network_remote_signing_request(&rsr);

					if (merr == mpdc_protocol_error_none)
					{
						if (mpdc_certificate_child_struct_to_file(fpath, &rcert) == false)
						{
							merr = mpdc_protocol_error_file_not_written;
						}
					}
				}
				else
				{
					merr = mpdc_protocol_error_root_signature_invalid;
				}
			}
			else
			{
				merr = mpdc_protocol_error_decoding_failure;
			}
		}
		else
		{
			merr = mpdc_protocol_error_file_not_found;
		}
	}
	else
	{
		merr = mpdc_protocol_error_node_not_found;
	}

	return merr;
}

static void dla_resign_command(void)
{
	/* reset topology, certificates, and signing key */
	mpdc_server_topology_reset(&m_dla_application_state);
	mpdc_server_erase_signature_key(&m_dla_application_state);
	mpdc_server_topology_remove_certificate(&m_dla_application_state, m_dla_application_state.dla.issuer);
	mpdc_server_topology_remove_certificate(&m_dla_application_state, m_dla_application_state.root.issuer);
	qsc_memutils_clear(&m_dla_application_state.dla, sizeof(mpdc_child_certificate));
	qsc_memutils_clear(&m_dla_application_state.root, sizeof(mpdc_root_certificate));
}

static mpdc_protocol_errors dla_resign_response(const qsc_socket* csock, const mpdc_network_packet* packetin)
{
	MPDC_ASSERT(csock != NULL);
	MPDC_ASSERT(packetin != NULL);

	mpdc_topology_node_state rnode = { 0 };
	qsc_mutex mtx;
	const uint8_t* rser;
	mpdc_protocol_errors merr;

	(void)csock;
	rser = packetin->pmessage + MPDC_PACKET_SUBHEADER_SIZE;

	if (mpdc_topology_node_find(&m_dla_application_state.tlist, &rnode, rser) == true)
	{
		mpdc_child_certificate rcert = { 0 };

		if (mpdc_server_child_certificate_from_issuer(&rcert, &m_dla_application_state, rnode.issuer) == true)
		{
			if (mpdc_certificate_child_is_valid(&rcert) == true)
			{
				mpdc_network_resign_response_state rrs = {
					.list = &m_dla_application_state.tlist,
					.rcert = &rcert,
					.rnode = &rnode,
					.sigkey = m_dla_application_state.sigkey
				};

				/* process the resign update */
				merr = mpdc_network_resign_response(&rrs, packetin);

				if (merr == mpdc_protocol_error_none)
				{
					mtx = qsc_async_mutex_lock_ex();

					mpdc_server_topology_remove_certificate(&m_dla_application_state, rnode.issuer);
					mpdc_server_topology_remove_node(&m_dla_application_state, rnode.issuer);
					mpdc_server_topology_to_file(&m_dla_application_state);

					qsc_async_mutex_unlock_ex(mtx);
				}
			}
			else
			{
				merr = mpdc_protocol_error_decoding_failure;
			}
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

static mpdc_protocol_errors dla_revoke_broadcast(const char* cmsg)
{
	MPDC_ASSERT(cmsg != NULL);
	
	qsc_mutex mtx;
	size_t mlen;
	mpdc_protocol_errors merr;

	mlen = qsc_stringutils_string_size(cmsg);

	if (mlen >= MPDC_MINIMUM_PATH_LENGTH)
	{
		if (qsc_fileutils_exists(cmsg) == true)
		{
			mpdc_child_certificate rcert = { 0 };

			if (mpdc_certificate_child_file_to_struct(cmsg, &rcert) == true)
			{
				mpdc_topology_node_state rnode = { 0 };

				/* find the node in the topological list */
				if (mpdc_topology_node_find(&m_dla_application_state.tlist, &rnode, rcert.serial) == true)
				{
					mpdc_network_revoke_request_state rrs = {
						.designation = rcert.designation,
						.list = &m_dla_application_state.tlist,
						.rnode = &rnode,
						.sigkey = m_dla_application_state.sigkey
					};

					/* create and send the revocation broadcast */
					merr = mpdc_network_revoke_broadcast(&rrs);

					if (merr == mpdc_protocol_error_none)
					{
						mtx = qsc_async_mutex_lock_ex();

						mpdc_server_topology_remove_certificate(&m_dla_application_state, rnode.issuer);
						mpdc_server_topology_remove_node(&m_dla_application_state, rnode.issuer);
						mpdc_server_topology_to_file(&m_dla_application_state);

						qsc_async_mutex_unlock_ex(mtx);
					}
				}
				else
				{
					merr = mpdc_protocol_error_node_not_found;
				}
			}
			else
			{
				merr = mpdc_protocol_error_decoding_failure;
			}
		}
		else
		{
			merr = mpdc_protocol_error_file_not_found;
		}
	}
	else
	{
		merr = mpdc_protocol_error_invalid_request;
	}

	return merr;
}

static mpdc_protocol_errors dla_topological_status_request(const mpdc_topology_node_state* rnode)
{
	MPDC_ASSERT(rnode != NULL);

	mpdc_topology_node_state lnode = { 0 };
	mpdc_child_certificate rcert = { 0 };
	mpdc_protocol_errors merr;

	if (mpdc_topology_node_find(&m_dla_application_state.tlist, &lnode, m_dla_application_state.dla.serial) == true)
	{
		if (mpdc_server_child_certificate_from_issuer(&rcert, &m_dla_application_state, rnode->issuer) == true)
		{
			const mpdc_network_topological_status_request_state tsr = {
				.lnode = &lnode,
				.rcert = &rcert,
				.rnode = rnode,
				.sigkey = m_dla_application_state.sigkey
			};

			/* request the remote devices node information */
			merr = mpdc_network_topological_status_request(&tsr);
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

static mpdc_protocol_errors dla_topological_query_response(const qsc_socket* csock, const mpdc_network_packet* packetin)
{
	MPDC_ASSERT(csock != NULL);
	MPDC_ASSERT(packetin != NULL);

	mpdc_topology_node_state cnode = { 0 };
	mpdc_topology_node_state rnode = { 0 };
	const uint8_t* cser;
	const char* riss;
	mpdc_protocol_errors merr;

	cser = packetin->pmessage + MPDC_PACKET_SUBHEADER_SIZE;
	riss = (const char*)packetin->pmessage + MPDC_PACKET_SUBHEADER_SIZE + MPDC_CERTIFICATE_SERIAL_SIZE;

	if (mpdc_topology_node_find_issuer(&m_dla_application_state.tlist, &rnode, riss) == true)
	{
		merr = dla_topological_status_request(&rnode);

		if (merr == mpdc_protocol_error_none)
		{
			if (mpdc_topology_node_find(&m_dla_application_state.tlist, &cnode, cser) == true)
			{
				mpdc_child_certificate ccert = { 0 };

				if (mpdc_server_child_certificate_from_issuer(&ccert, &m_dla_application_state, cnode.issuer) == true)
				{
					mpdc_network_topological_query_response_state tqr = {
						.csock = csock,
						.ccert = &ccert,
						.rnode = &rnode,
						.sigkey = m_dla_application_state.sigkey
					};

					merr = mpdc_network_topological_query_response(&tqr, packetin);
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
			/* if status request fails or is refused send the error */
			mpdc_network_send_error(csock, merr);
		}
	}
	else
	{
		merr = mpdc_protocol_error_node_not_found;
	}

	return merr;
}

static void dla_receive_loop(void* ras)
{
	MPDC_ASSERT(ras != NULL);

	mpdc_network_packet pkt = { 0 };
	uint8_t* buff;
	dla_receive_state* pras;
	const char* cmsg;
	size_t mlen;
	size_t plen;
	size_t slen;
	mpdc_protocol_errors merr;

	merr = mpdc_protocol_error_none;

	if (ras != NULL)
	{
		pras = (dla_receive_state*)ras;
		buff = (uint8_t*)qsc_memutils_malloc(QSC_SOCKET_TERMINATOR_SIZE);

		if (buff != NULL)
		{
			if (pras->csock.connection_status == qsc_socket_state_connected)
			{
				uint8_t hdr[MPDC_PACKET_HEADER_SIZE] = { 0 };

				mlen = 0;
				slen = 0;
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
							mpdc_server_log_write_message(&m_dla_application_state, mpdc_application_log_allocation_failure, (const char*)pras->csock.address, QSC_SOCKET_ADDRESS_MAX_SIZE);
						}
					}
					else
					{
						merr = mpdc_protocol_error_invalid_request;
						mpdc_server_log_write_message(&m_dla_application_state, mpdc_application_log_receive_failure, (const char*)pras->csock.address, QSC_SOCKET_ADDRESS_MAX_SIZE);
					}
			
					if (mlen > 0)
					{
						pkt.pmessage = buff + MPDC_PACKET_HEADER_SIZE;

						if (pkt.flag == mpdc_network_flag_tunnel_connection_terminate)
						{
							mpdc_server_log_write_message(&m_dla_application_state, mpdc_application_log_connection_terminated, (const char*)pras->csock.address, QSC_SOCKET_ADDRESS_MAX_SIZE);
							mpdc_connection_close(&pras->csock, mpdc_protocol_error_none, true);
						}
						else if (pkt.flag == mpdc_network_flag_incremental_update_request)
						{
							/* sent by a client or server, requesting an agents topological info */
							merr = dla_incremental_update_response(&pras->csock, &pkt);

							if (merr == mpdc_protocol_error_none)
							{
								mpdc_server_log_write_message(&m_dla_application_state, mpdc_application_log_incremental_success, (const char*)pras->csock.address, QSC_SOCKET_ADDRESS_MAX_SIZE);
							}
							else
							{
								cmsg = mpdc_protocol_error_to_string(merr);

								if (cmsg != NULL)
								{
									mpdc_logger_write_time_stamped_message(m_dla_application_state.logpath, cmsg, qsc_stringutils_string_size(cmsg));
								}

								mpdc_server_log_write_message(&m_dla_application_state, mpdc_application_log_incremental_failure, (const char*)pras->csock.address, QSC_SOCKET_ADDRESS_MAX_SIZE);
							}
						}
						else if (pkt.flag == mpdc_network_flag_register_request)
						{
							/* sent to the dla requesting to join the network */
							merr = dla_register_response(&pras->csock, &pkt);

							if (merr == mpdc_protocol_error_none)
							{
								mpdc_server_log_write_message(&m_dla_application_state, mpdc_application_log_register_success, (const char*)pras->csock.address, QSC_SOCKET_ADDRESS_MAX_SIZE);
							}
							else
							{
								cmsg = mpdc_protocol_error_to_string(merr);

								if (cmsg != NULL)
								{
									mpdc_logger_write_time_stamped_message(m_dla_application_state.logpath, cmsg, qsc_stringutils_string_size(cmsg));
								}

								mpdc_server_log_write_message(&m_dla_application_state, mpdc_application_log_register_failure, (const char*)pras->csock.address, QSC_SOCKET_ADDRESS_MAX_SIZE);
							}
						}
						else if (pkt.flag == mpdc_network_flag_register_update_request)
						{
							/* sent to the dla from a MAS requesting to register on the network */
							merr = dla_register_update_response(&pras->csock, &pkt);

							if (merr == mpdc_protocol_error_none)
							{
								mpdc_server_log_write_message(&m_dla_application_state, mpdc_application_log_register_success, (const char*)pras->csock.address, QSC_SOCKET_ADDRESS_MAX_SIZE);
							}
							else
							{
								cmsg = mpdc_protocol_error_to_string(merr);

								if (cmsg != NULL)
								{
									mpdc_logger_write_time_stamped_message(m_dla_application_state.logpath, cmsg, qsc_stringutils_string_size(cmsg));
								}

								mpdc_server_log_write_message(&m_dla_application_state, mpdc_application_log_register_failure, (const char*)pras->csock.address, QSC_SOCKET_ADDRESS_MAX_SIZE);
							}
						}
						else if (pkt.flag == mpdc_network_flag_network_resign_request)
						{
							/* sent to the dla from a server or agent requesting a network resignation */
							
							merr = dla_resign_response(&pras->csock, &pkt);

							if (merr == mpdc_protocol_error_none)
							{
								mpdc_server_log_write_message(&m_dla_application_state, mpdc_application_log_remote_resign_success, (const char*)pras->csock.address, QSC_SOCKET_ADDRESS_MAX_SIZE);
							}
							else
							{
								cmsg = mpdc_protocol_error_to_string(merr);

								if (cmsg != NULL)
								{
									mpdc_logger_write_time_stamped_message(m_dla_application_state.logpath, cmsg, qsc_stringutils_string_size(cmsg));
								}

								mpdc_server_log_write_message(&m_dla_application_state, mpdc_application_log_remote_resign_failure, (const char*)pras->csock.address, QSC_SOCKET_ADDRESS_MAX_SIZE);
							}
						}
						else if (pkt.flag == mpdc_network_flag_topology_query_request)
						{
							/* sent to the dla from a server or agent querying for a node */
							
							merr = dla_topological_query_response(&pras->csock, &pkt);

							if (merr == mpdc_protocol_error_none)
							{
								mpdc_server_log_write_message(&m_dla_application_state, mpdc_application_log_topology_node_query_success, (const char*)pras->csock.address, QSC_SOCKET_ADDRESS_MAX_SIZE);
							}
							else
							{
								cmsg = mpdc_protocol_error_to_string(merr);

								if (cmsg != NULL)
								{
									mpdc_logger_write_time_stamped_message(m_dla_application_state.logpath, cmsg, qsc_stringutils_string_size(cmsg));
								}

								mpdc_server_log_write_message(&m_dla_application_state, mpdc_application_log_topology_node_query_failure, (const char*)pras->csock.address, QSC_SOCKET_ADDRESS_MAX_SIZE);
							}
						}
						else if (pkt.flag == mpdc_network_flag_system_error_condition)
						{
							/* log the error condition */
							merr = (mpdc_protocol_errors)pkt.pmessage[0];
							cmsg = mpdc_protocol_error_to_string(merr);

							if (cmsg != NULL)
							{
								mpdc_logger_write_time_stamped_message(m_dla_application_state.logpath, cmsg, qsc_stringutils_string_size(cmsg));
							}

							mpdc_server_log_write_message(&m_dla_application_state, mpdc_application_log_remote_reported_error, (const char*)pras->csock.address, QSC_SOCKET_ADDRESS_MAX_SIZE);
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
									mpdc_server_log_write_message(&m_dla_application_state, mpdc_application_log_connection_terminated, (const char*)pras->csock.address, QSC_SOCKET_ADDRESS_MAX_SIZE);
								}
							}
							else
							{
								mpdc_network_send_error(&pras->csock, mpdc_protocol_error_invalid_request);
								mpdc_server_log_write_message(&m_dla_application_state, mpdc_application_log_remote_invalid_request, (const char*)pras->csock.address, QSC_SOCKET_ADDRESS_MAX_SIZE);
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

static mpdc_protocol_errors dla_ipv4_server_start(void)
{
	qsc_socket lsock = { 0 };
	qsc_ipinfo_ipv4_address addt = { 0 };
	qsc_socket_exceptions serr;
	mpdc_protocol_errors merr;

	merr = mpdc_protocol_error_none;
	addt = qsc_ipinfo_ipv4_address_from_string(m_dla_application_state.localip);

	if (qsc_ipinfo_ipv4_address_is_valid(&addt) == true)
	{
		qsc_socket_server_initialize(&lsock);
		serr = qsc_socket_create(&lsock, qsc_socket_address_family_ipv4, qsc_socket_transport_stream, qsc_socket_protocol_tcp);

		if (serr == qsc_socket_exception_success)
		{
			serr = qsc_socket_bind_ipv4(&lsock, &addt, MPDC_APPLICATION_DLA_PORT);

			if (serr == qsc_socket_exception_success)
			{
				serr = qsc_socket_listen(&lsock, QSC_SOCKET_SERVER_LISTEN_BACKLOG);

				if (serr == qsc_socket_exception_success)
				{
					while (true)
					{
						dla_receive_state* ras;

						ras = (dla_receive_state*)qsc_memutils_malloc(sizeof(dla_receive_state));

						if (ras != NULL)
						{
							qsc_memutils_clear(&ras->csock, sizeof(qsc_socket));
							serr = qsc_socket_accept(&lsock, &ras->csock);

							if (serr == qsc_socket_exception_success)
							{
								qsc_async_thread_create(&dla_receive_loop, ras);
							}
							else
							{
								/* free the resources if connect fails */
								qsc_memutils_alloc_free(ras);
								mpdc_server_log_write_message(&m_dla_application_state, mpdc_application_log_allocation_failure, (const char*)lsock.address, QSC_SOCKET_ADDRESS_MAX_SIZE);
							}
						}
						else
						{
							/* exit on memory allocation failure */
							merr = mpdc_protocol_error_memory_allocation;
							mpdc_server_log_write_message(&m_dla_application_state, mpdc_application_log_allocation_failure, (const char*)lsock.address, QSC_SOCKET_ADDRESS_MAX_SIZE);
						}
					};
				}
				else
				{
					merr = mpdc_protocol_error_listener_fail;
				}
			}
			else
			{
				merr = mpdc_protocol_error_socket_binding;
			}
		}
		else
		{
			merr = mpdc_protocol_error_socket_creation;
		}
	}
	else
	{
		merr = mpdc_protocol_error_no_usable_address;
	}

	return merr;
}

static mpdc_protocol_errors dla_ipv6_server_start(void)
{
	qsc_socket lsock = { 0 };
	qsc_ipinfo_ipv6_address addt = { 0 };
	qsc_socket_exceptions serr;
	mpdc_protocol_errors merr;

	merr = mpdc_protocol_error_none;
	addt = qsc_ipinfo_ipv6_address_from_string(m_dla_application_state.localip);

	if (qsc_ipinfo_ipv6_address_is_valid(&addt) == true)
	{
		qsc_socket_server_initialize(&lsock);
		serr = qsc_socket_create(&lsock, qsc_socket_address_family_ipv6, qsc_socket_transport_stream, qsc_socket_protocol_tcp);

		if (serr == qsc_socket_exception_success)
		{
			serr = qsc_socket_bind_ipv6(&lsock, &addt, MPDC_APPLICATION_DLA_PORT);

			if (serr == qsc_socket_exception_success)
			{
				serr = qsc_socket_listen(&lsock, QSC_SOCKET_SERVER_LISTEN_BACKLOG);

				if (serr == qsc_socket_exception_success)
				{
					while (true)
					{
						dla_receive_state* ras;

						ras = (dla_receive_state*)qsc_memutils_malloc(sizeof(dla_receive_state));

						if (ras != NULL)
						{
							qsc_memutils_clear(&ras->csock, sizeof(qsc_socket));
							serr = qsc_socket_accept(&lsock, &ras->csock);

							if (serr == qsc_socket_exception_success)
							{
								ras->csock.connection_status = qsc_socket_state_connected;
								qsc_async_thread_create(&dla_receive_loop, ras);
							}
							else
							{
								/* free the resources if connect fails */
								qsc_memutils_alloc_free(ras);
								mpdc_server_log_write_message(&m_dla_application_state, mpdc_application_log_allocation_failure, (const char*)lsock.address, QSC_SOCKET_ADDRESS_MAX_SIZE);
							}
						}
						else
						{
							/* exit on memory allocation failure */
							merr = mpdc_protocol_error_memory_allocation;
							break;
						}
					};
				}
				else
				{
					merr = mpdc_protocol_error_listener_fail;
				}
			}
			else
			{
				merr = mpdc_protocol_error_socket_binding;
			}
		}
		else
		{
			merr = mpdc_protocol_error_socket_creation;
		}
	}
	else
	{
		merr = mpdc_protocol_error_no_usable_address;
	}

	return merr;
}

static void dla_server_dispose(void)
{
	m_dla_command_loop_status = mpdc_server_loop_status_stopped;
	mpdc_server_state_unload(&m_dla_application_state);
	mpdc_server_state_initialize(&m_dla_application_state, mpdc_network_designation_dla);
	qsc_memutils_clear(&m_dla_application_state.dla, sizeof(mpdc_child_certificate));
	m_dla_command_loop_status = mpdc_server_loop_status_stopped;
	m_dla_server_loop_status = mpdc_server_loop_status_stopped;
	m_dla_idle_timer = 0;
}

static bool dla_server_load_root(void)
{
	bool res;

	res = false;

	/* load the root certificate */
	if (mpdc_server_topology_root_fetch(&m_dla_application_state, &m_dla_application_state.root) == true)
	{
		res = mpdc_topology_node_verify_root(&m_dla_application_state.tlist, &m_dla_application_state.root);
	}

	return res;
}

static bool dla_server_load_local(void)
{
	bool res;

	res = false;

	/* load the local agent certificate */
	if (mpdc_server_topology_local_fetch(&m_dla_application_state, &m_dla_application_state.dla) == true)
	{
		/* verify the agent certificate */
		if (mpdc_certificate_child_is_valid(&m_dla_application_state.dla) == true &&
			mpdc_certificate_root_signature_verify(&m_dla_application_state.dla, &m_dla_application_state.root) == true)
		{
			res = mpdc_topology_node_verify_issuer(&m_dla_application_state.tlist, &m_dla_application_state.dla, m_dla_application_state.issuer);
		}
	}

	return res;
}

static bool dla_server_start(void)
{
#if defined(MPDC_NETWORK_PROTOCOL_IPV6)
	/* start the main receive loop on a new thread */
	if (qsc_async_thread_create_noargs(&dla_ipv6_server_start) != NULL)
#else
	if (qsc_async_thread_create_noargs(&dla_ipv4_server_start) != NULL)
#endif
	{
		m_dla_server_loop_status = mpdc_server_loop_status_started;
	}

	return (m_dla_server_loop_status == mpdc_server_loop_status_started);
}

static bool dla_certificate_export(const char* cmsg)
{
	MPDC_ASSERT(cmsg != NULL);

	bool res;

	res = mpdc_server_child_certificate_export(&m_dla_application_state, cmsg);

	return res;
}

static bool dla_certificate_import(const char* cmsg)
{
	MPDC_ASSERT(cmsg != NULL);

	qsc_mutex mtx;
	bool res;

	if (m_dla_server_loop_status == mpdc_server_loop_status_started)
	{
		m_dla_server_loop_status = mpdc_server_loop_status_paused;
	}

	res = mpdc_server_child_certificate_import(&m_dla_application_state.dla, &m_dla_application_state, cmsg);

	if (res == true)
	{
		mtx = qsc_async_mutex_lock_ex();

		res = mpdc_certificate_child_file_to_struct(cmsg, &m_dla_application_state.dla);

		/* register the node and save the database */
		mpdc_topology_child_register(&m_dla_application_state.tlist, &m_dla_application_state.dla, m_dla_application_state.localip);
		mpdc_server_topology_to_file(&m_dla_application_state);

		qsc_async_mutex_unlock_ex(mtx);

		if (m_dla_server_loop_status == mpdc_server_loop_status_paused)
		{
			res = dla_server_start();
		}
	}

	return res;
}

/* application functions */

static void dla_get_command_mode(const char* command)
{
	MPDC_ASSERT(command != NULL);

	mpdc_console_modes nmode;

	nmode = m_dla_application_state.mode;

	switch (m_dla_application_state.mode)
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
			else if (qsc_stringutils_string_size(command) > 0)
			{
				nmode = mpdc_console_mode_user;
			}

			break;
		}
		default:
		{
		}
	}

	m_dla_application_state.mode = nmode;
}

static void dla_set_command_action(const char* command)
{
	MPDC_ASSERT(command != NULL);

	mpdc_command_actions res;
	size_t clen;

	res = mpdc_command_action_command_unrecognized;
	clen = qsc_stringutils_string_size(command);

	if (clen == 0 || clen > QSC_CONSOLE_MAX_LINE)
	{
		res = mpdc_command_action_none;
	}
	else
	{
		if (m_dla_application_state.mode == mpdc_console_mode_config)
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
		else if (m_dla_application_state.mode == mpdc_console_mode_certificate)
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
			else if (qsc_consoleutils_line_contains(command, "revoke "))
			{
				res = mpdc_command_action_dla_certificate_revoke;
			}
		}
		else if (m_dla_application_state.mode == mpdc_console_mode_server)
		{
			if (qsc_consoleutils_line_contains(command, "announce "))
			{
				res = mpdc_command_action_dla_server_announce;
			}
			else if (qsc_consoleutils_line_equals(command, "backup"))
			{
				res = mpdc_command_action_server_backup;
			}
			else if (qsc_consoleutils_line_equals(command, "converge"))
			{
				res = mpdc_command_action_dla_server_converge;
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
			else if (qsc_consoleutils_line_equals(command, "resign"))
			{
				res = mpdc_command_action_server_resign;
			}
			else if (qsc_consoleutils_line_equals(command, "restore"))
			{
				res = mpdc_command_action_server_restore;
			}
			else if (qsc_consoleutils_line_contains(command, "revoke "))
			{
				res = mpdc_command_action_dla_server_revoke;
			}
			else if (qsc_consoleutils_line_contains(command, "service "))
			{
				res = mpdc_command_action_server_service;
			}
			else if (qsc_consoleutils_line_contains(command, "sproxy "))
			{
				res = mpdc_command_action_dla_server_sproxy;
			}
		}
		else if (m_dla_application_state.mode == mpdc_console_mode_enable)
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
		else if (m_dla_application_state.mode == mpdc_console_mode_user)
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

	m_dla_application_state.action = res;
}

static void dla_command_execute(const char* command)
{
	MPDC_ASSERT(command != NULL);

	const char* cmsg;
	size_t slen;
	mpdc_protocol_errors merr;
	bool res;

	res = true;

	switch (m_dla_application_state.action)
	{
	case mpdc_command_action_config_clear_all:
	{
		if (mpdc_menu_print_predefined_message_confirm(mpdc_application_erase_erase_all, m_dla_application_state.mode, m_dla_application_state.hostname) == true)
		{
			mpdc_server_erase_all(&m_dla_application_state);
			mpdc_menu_print_predefined_message(mpdc_application_system_erased, m_dla_application_state.mode, m_dla_application_state.hostname);
		}
		else
		{
			mpdc_menu_print_predefined_message(mpdc_application_operation_aborted, m_dla_application_state.mode, m_dla_application_state.hostname);
		}

		break;
	}
	case mpdc_command_action_config_clear_config:
	{
		if (mpdc_menu_print_predefined_message_confirm(mpdc_application_erase_config, mpdc_console_mode_config, m_dla_application_state.hostname) == true)
		{
			slen = qsc_stringutils_string_size(m_dla_application_state.username);
			mpdc_server_log_write_message(&m_dla_application_state, mpdc_application_log_configuration_erased, m_dla_application_state.username, slen);
			mpdc_server_clear_config(&m_dla_application_state);
			mpdc_menu_print_predefined_message(mpdc_application_configuration_erased, m_dla_application_state.mode, m_dla_application_state.hostname);
		}
		else
		{
			mpdc_menu_print_predefined_message(mpdc_application_operation_aborted, m_dla_application_state.mode, m_dla_application_state.hostname);
		}

		break;
	}
	case mpdc_command_action_config_clear_log:
	{
		if (mpdc_menu_print_predefined_message_confirm(mpdc_application_erase_log, mpdc_console_mode_config, m_dla_application_state.hostname) == true)
		{
			mpdc_server_clear_log(&m_dla_application_state);
			mpdc_menu_print_predefined_message(mpdc_application_log_erased, m_dla_application_state.mode, m_dla_application_state.hostname);
		}
		else
		{
			mpdc_menu_print_predefined_message(mpdc_application_operation_aborted, m_dla_application_state.mode, m_dla_application_state.hostname);
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
		mpdc_help_print_mode(m_dla_application_state.cmdprompt, mpdc_console_mode_config, m_dla_application_state.srvtype);
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
				m_dla_application_state.loghost = true;
				mpdc_server_log_host(&m_dla_application_state);
				mpdc_menu_print_predefined_message(mpdc_application_logging_enabled, m_dla_application_state.mode, m_dla_application_state.hostname);
			}
			else if (qsc_stringutils_string_contains(cmsg, "disable"))
			{
				/* disable logging */
				m_dla_application_state.loghost = false;
				mpdc_server_log_host(&m_dla_application_state);
				mpdc_menu_print_predefined_message(mpdc_application_logging_disabled, m_dla_application_state.mode, m_dla_application_state.hostname);
			}
			else
			{
				mpdc_menu_print_predefined_message(mpdc_application_not_recognized, m_dla_application_state.mode, m_dla_application_state.hostname);
				mpdc_help_print_context(m_dla_application_state.cmdprompt, mpdc_command_action_config_log_host);
			}
		}
		else
		{
			mpdc_menu_print_predefined_message(mpdc_application_not_recognized, m_dla_application_state.mode, m_dla_application_state.hostname);
			mpdc_help_print_context(m_dla_application_state.cmdprompt, mpdc_command_action_config_log_host);
		}

		break;
	}
	case mpdc_command_action_config_name_domain:
	{
		cmsg = qsc_stringutils_reverse_sub_string(command, " ");

		if (cmsg != NULL)
		{
			slen = qsc_stringutils_string_size(cmsg);

			if (mpdc_server_set_domain_name(&m_dla_application_state, cmsg, slen) == false)
			{
				mpdc_menu_print_predefined_message(mpdc_application_domain_invalid, m_dla_application_state.mode, m_dla_application_state.hostname);
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

			if (mpdc_server_set_host_name(&m_dla_application_state, cmsg, slen) == false)
			{
				mpdc_menu_print_predefined_message(mpdc_application_hostname_invalid, m_dla_application_state.mode, m_dla_application_state.hostname);
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

			if (mpdc_server_set_password_retries(&m_dla_application_state, cmsg, slen) == false)
			{
				/* invalid message */
				mpdc_menu_print_predefined_message(mpdc_application_retry_invalid, m_dla_application_state.mode, m_dla_application_state.hostname);
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

			if (mpdc_server_set_console_timeout(&m_dla_application_state, cmsg, slen) == false)
			{
				/* invalid message */
				mpdc_menu_print_predefined_message(mpdc_application_timeout_invalid, m_dla_application_state.mode, m_dla_application_state.hostname);
			}
		}

		break;
	}
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
			res = dla_certificate_export(cmsg);
		}

		if (res == true)
		{
			mpdc_menu_print_predefined_message(mpdc_application_export_certificate_success, m_dla_application_state.mode, m_dla_application_state.hostname);
		}
		else
		{
			mpdc_menu_print_predefined_message(mpdc_application_export_certificate_failure, m_dla_application_state.mode, m_dla_application_state.hostname);
		}

		break;
	}
	case mpdc_command_action_certificate_import:
	{
		cmsg = qsc_stringutils_reverse_sub_string(command, " ");

		if (cmsg != NULL)
		{
			res = dla_certificate_import(cmsg);
		}

		if (res == true)
		{
			mpdc_menu_print_predefined_message(mpdc_application_import_certificate_success, m_dla_application_state.mode, m_dla_application_state.hostname);
		}
		else
		{
			mpdc_menu_print_predefined_message(mpdc_application_import_certificate_failure, m_dla_application_state.mode, m_dla_application_state.hostname);
		}

		break;
	}
	case mpdc_command_action_certificate_generate:
	{
		cmsg = qsc_stringutils_reverse_sub_string(command, " ");

		if (cmsg != NULL)
		{
			res = dla_certificate_generate(cmsg);

			if (res == true)
			{
				char fpath[MPDC_STORAGE_PATH_MAX] = { 0 };

				mpdc_server_child_certificate_path(&m_dla_application_state, fpath, sizeof(fpath));
				slen = qsc_stringutils_string_size(fpath);

				mpdc_menu_print_predefined_message(mpdc_application_generate_key_success, m_dla_application_state.mode, m_dla_application_state.hostname);
				mpdc_menu_print_message(fpath, m_dla_application_state.mode, m_dla_application_state.hostname);
				mpdc_server_log_write_message(&m_dla_application_state, mpdc_application_log_generate_success, fpath, slen);
			}
			else
			{
				mpdc_menu_print_predefined_message(mpdc_application_generate_key_failure, m_dla_application_state.mode, m_dla_application_state.hostname);
				mpdc_server_log_write_message(&m_dla_application_state, mpdc_application_log_generate_failure, NULL, 0);
			}
		}

		break;
	}
	case mpdc_command_action_certificate_help:
	{
		mpdc_help_print_mode(m_dla_application_state.cmdprompt, mpdc_console_mode_certificate, m_dla_application_state.srvtype);
		break;
	}
	case mpdc_command_action_certificate_print:
	{
		char fpath[MPDC_STORAGE_PATH_MAX] = { 0 };

		res = false;
		mpdc_server_child_certificate_path(&m_dla_application_state, fpath, sizeof(fpath));

		if (qsc_fileutils_exists(fpath) == true)
		{
			res = mpdc_server_child_certificate_print(fpath, sizeof(fpath));
		}

		if (res == false)
		{
			mpdc_menu_print_predefined_message(mpdc_application_client_pubkey_path_invalid, m_dla_application_state.mode, m_dla_application_state.hostname);
		}

		break;
	}
	case mpdc_command_action_dla_server_announce:
	{
		if (m_dla_server_loop_status == mpdc_server_loop_status_started)
		{
			char sadd[QSC_SOCKET_ADDRESS_MAX_SIZE] = { 0 };
			char fpath[MPDC_STORAGE_PATH_MAX] = { 0 };

			cmsg = qsc_stringutils_sub_string(command, " ");
			qsc_stringutils_split_strings(fpath, sadd, sizeof(fpath), cmsg + 1, ", ");
			slen = qsc_stringutils_string_size(fpath);

			merr = dla_announce_broadcast(fpath, sadd);

			if (merr == mpdc_protocol_error_none)
			{
				mpdc_menu_print_predefined_message(mpdc_application_announce_success, m_dla_application_state.mode, m_dla_application_state.hostname);
				mpdc_server_log_write_message(&m_dla_application_state, mpdc_application_announce_success, cmsg, slen);
			}
			else
			{
				mpdc_menu_print_predefined_message(mpdc_application_announce_failure, m_dla_application_state.mode, m_dla_application_state.hostname);
				mpdc_server_log_write_message(&m_dla_application_state, mpdc_application_announce_failure, cmsg, slen);
				cmsg = mpdc_protocol_error_to_string(merr);

				if (cmsg != NULL)
				{
					mpdc_logger_write_time_stamped_message(m_dla_application_state.logpath, cmsg, qsc_stringutils_string_size(cmsg));
				}
			}
		}
		else
		{
			mpdc_menu_print_predefined_message(mpdc_application_server_service_not_started, m_dla_application_state.mode, m_dla_application_state.hostname);
		}

		break;
	}
	case mpdc_command_action_server_backup:
	{
		slen = qsc_stringutils_string_size(m_dla_application_state.hostname);
		mpdc_server_state_backup_save(&m_dla_application_state);
		mpdc_server_log_write_message(&m_dla_application_state, mpdc_application_log_state_backup, m_dla_application_state.hostname, slen);
		mpdc_menu_print_predefined_message(mpdc_application_server_backup_save_confirmation, m_dla_application_state.mode, m_dla_application_state.hostname);

		break;
	}
	case mpdc_command_action_dla_server_converge:
	{
		if (m_dla_server_loop_status == mpdc_server_loop_status_started)
		{
			dla_converge_broadcast();
			mpdc_menu_print_predefined_message(mpdc_application_converge_success, m_dla_application_state.mode, m_dla_application_state.hostname);
		}
		else
		{
			mpdc_menu_print_predefined_message(mpdc_application_server_service_not_started, m_dla_application_state.mode, m_dla_application_state.hostname);
		}

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
		mpdc_help_print_mode(m_dla_application_state.cmdprompt, mpdc_console_mode_server, m_dla_application_state.srvtype);
		break;
	}
	case mpdc_command_action_server_list:
	{
		mpdc_server_topology_print_list(&m_dla_application_state);

		break;
	}
	case mpdc_command_action_server_resign:
	{
		if (m_dla_server_loop_status == mpdc_server_loop_status_started)
		{
			dla_resign_command();
			slen = qsc_stringutils_string_size(m_dla_application_state.hostname);
			m_dla_application_state.joined = false;
			slen = qsc_stringutils_string_size(m_dla_application_state.hostname);
			mpdc_menu_print_predefined_message(mpdc_application_network_resign_success, m_dla_application_state.mode, m_dla_application_state.hostname);
			mpdc_server_log_write_message(&m_dla_application_state, mpdc_application_log_local_resign_success, m_dla_application_state.hostname, slen);
		}
		else
		{
			mpdc_menu_print_predefined_message(mpdc_application_server_service_not_started, m_dla_application_state.mode, m_dla_application_state.hostname);
		}

		break;
	}
	case mpdc_command_action_server_restore:
	{
		bool dres;

		/* notify that server is already joined to a network */
		dres = mpdc_menu_print_predefined_message_confirm(mpdc_application_server_backup_restore_challenge, m_dla_application_state.mode, m_dla_application_state.hostname);
			
		if (dres == true)
		{
			mpdc_server_state_backup_restore(&m_dla_application_state);
			slen = qsc_stringutils_string_size(m_dla_application_state.hostname);
			mpdc_server_log_write_message(&m_dla_application_state, mpdc_application_log_state_restore, m_dla_application_state.hostname, slen);
		}

		break;
	}
	case mpdc_command_action_dla_server_revoke:
	{
		if (m_dla_server_loop_status == mpdc_server_loop_status_started)
		{
			cmsg = qsc_stringutils_reverse_sub_string(command, " ");

			if (cmsg != NULL)
			{
				slen = qsc_stringutils_string_size(cmsg);
				merr = dla_revoke_broadcast(cmsg);

				if (merr == mpdc_protocol_error_none)
				{
					mpdc_menu_print_predefined_message(mpdc_application_certificate_revoke_success, m_dla_application_state.mode, m_dla_application_state.hostname);
					mpdc_server_log_write_message(&m_dla_application_state, mpdc_application_certificate_revoke_success, cmsg, slen);
				}
				else
				{
					mpdc_menu_print_predefined_message(mpdc_application_certificate_revoke_failure, m_dla_application_state.mode, m_dla_application_state.hostname);
					mpdc_server_log_write_message(&m_dla_application_state, mpdc_application_certificate_revoke_failure, cmsg, slen);
					cmsg = mpdc_protocol_error_to_string(merr);

					if (cmsg != NULL)
					{
						mpdc_logger_write_time_stamped_message(m_dla_application_state.logpath, cmsg, qsc_stringutils_string_size(cmsg));
					}
				}
			}
		}
		else
		{
			mpdc_menu_print_predefined_message(mpdc_application_server_service_not_started, m_dla_application_state.mode, m_dla_application_state.hostname);
		}

		break;
	}
	case mpdc_command_action_server_service:
	{
		res = false;
		cmsg = qsc_stringutils_reverse_sub_string(command, " ");

		if (cmsg != NULL)
		{
			slen = qsc_stringutils_string_size(m_dla_application_state.hostname);

			if (qsc_stringutils_string_contains(cmsg, "start"))
			{
				if (m_dla_server_loop_status != mpdc_server_loop_status_started)
				{
					res = dla_server_start();

					if (res == true)
					{
						mpdc_menu_print_predefined_message(mpdc_application_server_service_start_success, m_dla_application_state.mode, m_dla_application_state.hostname);
						mpdc_server_log_write_message(&m_dla_application_state, mpdc_application_log_service_started, m_dla_application_state.hostname, slen);
					}
					else
					{
						mpdc_menu_print_predefined_message(mpdc_application_server_service_start_failure, m_dla_application_state.mode, m_dla_application_state.hostname);
					}
				}
			}
			else if (qsc_stringutils_string_contains(cmsg, "stop"))
			{
				if (m_dla_server_loop_status == mpdc_server_loop_status_started)
				{
					m_dla_server_loop_status = mpdc_server_loop_status_stopped;
					mpdc_menu_print_predefined_message(mpdc_application_server_service_stopped, m_dla_application_state.mode, m_dla_application_state.hostname);
					mpdc_server_log_write_message(&m_dla_application_state, mpdc_application_log_service_stopped, m_dla_application_state.hostname, slen);
				}
			}
			else if (qsc_stringutils_string_contains(cmsg, "pause"))
			{
				if (m_dla_server_loop_status != mpdc_server_loop_status_paused)
				{
					m_dla_server_loop_status = mpdc_server_loop_status_paused;
					mpdc_menu_print_predefined_message(mpdc_application_server_service_paused, m_dla_application_state.mode, m_dla_application_state.hostname);
					mpdc_server_log_write_message(&m_dla_application_state, mpdc_application_log_service_paused, m_dla_application_state.hostname, slen);
				}
			}
			else if (qsc_stringutils_string_contains(cmsg, "resume"))
			{
				if (m_dla_server_loop_status == mpdc_server_loop_status_paused)
				{
					m_dla_server_loop_status = mpdc_server_loop_status_started;
					mpdc_menu_print_predefined_message(mpdc_application_server_service_resume_success, m_dla_application_state.mode, m_dla_application_state.hostname);
					mpdc_server_log_write_message(&m_dla_application_state, mpdc_application_log_service_resumed, m_dla_application_state.hostname, slen);
				}
				else
				{
					mpdc_menu_print_predefined_message(mpdc_application_server_service_resume_failure, m_dla_application_state.mode, m_dla_application_state.hostname);
				}
			}
			else
			{
				mpdc_menu_print_predefined_message(mpdc_application_not_recognized, m_dla_application_state.mode, m_dla_application_state.hostname);
			}
		}

		break;
	}
	case mpdc_command_action_dla_server_sproxy:
	{
		if (m_dla_server_loop_status == mpdc_server_loop_status_started)
		{
			cmsg = qsc_stringutils_reverse_sub_string(command, " ");

			if (cmsg != NULL)
			{
				merr = dla_remote_signing_request(cmsg);

				slen = qsc_stringutils_string_size(cmsg);
				if (res == true)
				{
					mpdc_menu_print_predefined_message(mpdc_application_certificate_remote_sign_success, m_dla_application_state.mode, m_dla_application_state.hostname);
					mpdc_server_log_write_message(&m_dla_application_state, mpdc_application_log_remote_signing_success, cmsg, slen);
				}
				else
				{
					mpdc_menu_print_predefined_message(mpdc_application_certificate_remote_sign_failure, m_dla_application_state.mode, m_dla_application_state.hostname);
					mpdc_server_log_write_message(&m_dla_application_state, mpdc_application_log_remote_signing_failure, cmsg, slen);
					cmsg = mpdc_protocol_error_to_string(merr);

					if (cmsg != NULL)
					{
						mpdc_logger_write_time_stamped_message(m_dla_application_state.logpath, cmsg, qsc_stringutils_string_size(cmsg));
					}
				}
			}
		}
		else
		{
			mpdc_menu_print_predefined_message(mpdc_application_server_service_not_started, m_dla_application_state.mode, m_dla_application_state.hostname);
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
		mpdc_server_user_logout(&m_dla_application_state);

		break;
	}
	case mpdc_command_action_enable_help:
	{
		/* show enable help */
		mpdc_help_print_mode(m_dla_application_state.cmdprompt, mpdc_console_mode_enable, m_dla_application_state.srvtype);

		break;
	}
	case mpdc_command_action_enable_quit:
	case mpdc_command_action_user_quit:
	{
		dla_server_dispose();
		mpdc_menu_print_predefined_message(mpdc_application_application_quit, m_dla_application_state.mode, m_dla_application_state.hostname);
		mpdc_menu_print_prompt(m_dla_application_state.mode, m_dla_application_state.hostname);
		qsc_consoleutils_get_char();

		break;
	}
	case mpdc_command_action_enable_show_config:
	{
		/* show config */
		mpdc_server_print_configuration(&m_dla_application_state);

		break;
	}
	case mpdc_command_action_enable_show_log:
	{
		/* read the user log */
		mpdc_server_log_print(&m_dla_application_state);
		break;
	}
	case mpdc_command_action_user_enable:
	{
		/* user login */
		if (mpdc_server_user_login(&m_dla_application_state) == true)
		{
			/* load certificates */
			if (dla_server_load_root() == true)
			{
				dla_server_load_local();
			}
		}
		else
		{
			mpdc_dla_stop_server();
			mpdc_menu_print_predefined_message(mpdc_application_retries_exceeded, m_dla_application_state.mode, m_dla_application_state.hostname);
			mpdc_menu_print_prompt(m_dla_application_state.mode, m_dla_application_state.hostname);
			qsc_consoleutils_get_char();
		}

		break;
	}
	case mpdc_command_action_user_help:
	{
		/* show user help */
		mpdc_help_print_mode(m_dla_application_state.cmdprompt, mpdc_console_mode_user, m_dla_application_state.srvtype);

		break;
	}
	case mpdc_command_action_config_address:
	{
		cmsg = qsc_stringutils_reverse_sub_string(command, " ");

		if (cmsg != NULL)
		{
			qsc_ipinfo_address_types tadd;

			slen = qsc_stringutils_string_size(cmsg);
			tadd = qsc_ipinfo_get_address_type(cmsg);

			res = mpdc_server_set_ip_address(&m_dla_application_state, cmsg, slen);

			if (res == true)
			{
				mpdc_menu_print_predefined_message(mpdc_application_address_change_success, m_dla_application_state.mode, m_dla_application_state.hostname);
			}
			else
			{
				mpdc_menu_print_predefined_message(mpdc_application_address_change_failure, m_dla_application_state.mode, m_dla_application_state.hostname);
			}
		}

		break;
	}
	case mpdc_command_action_config_clear:
	{
		/* show clear help */
		mpdc_help_print_context(m_dla_application_state.cmdprompt, mpdc_command_action_config_clear_all);
		mpdc_help_print_context(m_dla_application_state.cmdprompt, mpdc_command_action_config_clear_config);
		mpdc_help_print_context(m_dla_application_state.cmdprompt, mpdc_command_action_config_clear_log);

		break;
	}
	case mpdc_command_action_config_log:
	{
		/* show log help */
		mpdc_help_print_context(m_dla_application_state.cmdprompt, mpdc_command_action_config_log_host);

		break;
	}
	case mpdc_command_action_config_name:
	{
		/* show name help */
		mpdc_help_print_context(m_dla_application_state.cmdprompt, mpdc_command_action_config_name_domain);
		mpdc_help_print_context(m_dla_application_state.cmdprompt, mpdc_command_action_config_name_host);

		break;
	}
	case mpdc_command_action_help_enable_all:
	{
		/* show enable help */
		mpdc_help_print_mode(m_dla_application_state.cmdprompt, mpdc_console_mode_enable, m_dla_application_state.srvtype);

		break;
	}
	case mpdc_command_action_help_enable_show:
	{
		/* show help */
		mpdc_help_print_context(m_dla_application_state.cmdprompt, mpdc_command_action_enable_show_config);
		mpdc_help_print_context(m_dla_application_state.cmdprompt, mpdc_command_action_enable_show_log);

		break;
	}
	case mpdc_command_action_help_enable_user:
	{
		/* show enable user help */
		mpdc_help_print_mode(m_dla_application_state.cmdprompt, mpdc_console_mode_user, m_dla_application_state.srvtype);

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
		mpdc_menu_print_predefined_message(mpdc_application_not_recognized, m_dla_application_state.mode, m_dla_application_state.hostname);
		mpdc_help_print_mode(m_dla_application_state.cmdprompt, m_dla_application_state.mode, m_dla_application_state.srvtype);
		break;
	}
	default:
	{
		mpdc_help_print_mode(m_dla_application_state.cmdprompt, m_dla_application_state.mode, m_dla_application_state.srvtype);
	}
	}
}

static void dla_idle_timer(void)
{
	const uint32_t MMSEC = 60 * 1000;

	while (true)
	{
		qsc_async_thread_sleep(MMSEC);
		qsc_mutex mtx = qsc_async_mutex_lock_ex();

		if (m_dla_application_state.mode != mpdc_console_mode_user)
		{
			++m_dla_idle_timer;

			if (m_dla_idle_timer >= m_dla_application_state.timeout)
			{
				mpdc_server_user_logout(&m_dla_application_state);
				m_dla_idle_timer = 0;
				qsc_consoleutils_print_line("");
				mpdc_menu_print_predefined_message(mpdc_application_console_timeout_expired, m_dla_application_state.mode, m_dla_application_state.hostname);
				mpdc_menu_print_prompt(m_dla_application_state.mode, m_dla_application_state.hostname);
			}
		}

		qsc_async_mutex_unlock_ex(mtx);
	};
}

static void dla_command_loop(char* command)
{
	MPDC_ASSERT(command != NULL);

	m_dla_command_loop_status = mpdc_server_loop_status_started;

	while (true)
	{
		qsc_consoleutils_get_line(command, QSC_CONSOLE_MAX_LINE);

		/* lock the mutex */
		qsc_mutex mtx = qsc_async_mutex_lock_ex();
		m_dla_idle_timer = 0;
		qsc_async_mutex_unlock_ex(mtx);

		dla_set_command_action(command);
		dla_command_execute(command);

		dla_get_command_mode(command);
		mpdc_server_set_command_prompt(&m_dla_application_state);
		mpdc_menu_print_prompt(m_dla_application_state.mode, m_dla_application_state.hostname);
		qsc_stringutils_clear_string(command);

		if (m_dla_command_loop_status == mpdc_server_loop_status_paused)
		{
			qsc_async_thread_sleep(MPDC_STORAGE_SERVER_PAUSE_INTERVAL);
			continue;
		}
		else if (m_dla_command_loop_status == mpdc_server_loop_status_stopped)
		{
			break;
		}
	}
}

/* dla functions */

void mpdc_dla_pause_server(void)
{
	m_dla_command_loop_status = mpdc_server_loop_status_paused;
}

int32_t mpdc_dla_start_server(void)
{
	char command[QSC_CONSOLE_MAX_LINE] = { 0 };
	qsc_thread idle;
	int32_t ret;

	/* initialize the server */
	mpdc_server_state_initialize(&m_dla_application_state, mpdc_network_designation_dla);

	/* set the window parameters */
	qsc_consoleutils_set_virtual_terminal();
	qsc_consoleutils_set_window_size(1000, 600);
	qsc_consoleutils_set_window_title(m_dla_application_state.wtitle);

	/* application banner */
	mpdc_server_print_banner(&m_dla_application_state);

	/* load the command prompt */
	dla_get_command_mode(command);
	mpdc_menu_print_prompt(m_dla_application_state.mode, m_dla_application_state.hostname);
	m_dla_command_loop_status = mpdc_server_loop_status_started;

	/* start the idle timer */
	m_dla_idle_timer = 0;
	idle = qsc_async_thread_create_noargs(&dla_idle_timer);
	
	if (idle != NULL)
	{
		/* command loop */
		dla_command_loop(command);
		ret = 0;
	}
	else
	{
		mpdc_menu_print_predefined_message(mpdc_application_authentication_failure, m_dla_application_state.mode, m_dla_application_state.hostname);
		ret = -1;
	}

	return (ret == 0);
}

void mpdc_dla_stop_server(void)
{
	m_dla_command_loop_status = mpdc_server_loop_status_stopped;
}
