#include "server.h"
#include "crypto.h"
#include "help.h"
#include "logger.h"
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
#include "folderutils.h"
#include "ipinfo.h"
#include "list.h"
#include "memutils.h"
#include "netutils.h"
#include "socketserver.h"
#include "stringutils.h"
#include "timerex.h"
#include "timestamp.h"

#define SERVER_KEYCHAIN_DEPTH 4
#define SERVER_KEYCHAIN_WIDTH 64
#define SERVER_KEYCHAIN_STATE_INDEX 0
#define SERVER_KEYCHAIN_LOG_INDEX 1
#define SERVER_KEYCHAIN_TOPOLOGY_INDEX 2
#define SERVER_KEYCHAIN_MFKCOL_INDEX 3

static const char AGENT_APPLICATION_BANNER[] = "Agent v1.0 \n"
"QRCS Corp. 2024, All rights reserved. \n"
"A quantum safe Agent list server. \n"
"Type Help for command mode options. \n"
"One command per line, press enter to run.";
static const char AGENT_APPLICATION_NAME[] = "Agent";
static const char AGENT_APPLICATION_PATH[] = "\\Agent";
static const char AGENT_FILENAME_CONFIG[] = "\\userconfig.agtcfg";
static const char AGENT_TOPOLOGY_NAME[] = "\\agent_topology";
static const char AGENT_PUBKEY_NAME[] = "agent_public_key.acpkey";
static const char AGENT_PRIKEY_NAME[] = "agent_secret_key.acskey";
static const char AGENT_PROMPT_DEFAULT[] = "Agent> ";
static const char AGENT_ROOT_PATH[] = "\\MPDC";
static const char AGENT_WINDOW_TITLE[] = "Agent v1.0a";

static const char CLIENT_APPLICATION_BANNER[] = "Client v1.0 \n"
"QRCS Corp. 2024, All rights reserved. \n"
"A quantum safe MPDC Network Client. \n"
"Type Help for command mode options. \n"
"One command per line, press enter to run.";
static const char CLIENT_APPLICATION_NAME[] = "Client";
static const char CLIENT_APPLICATION_PATH[] = "\\Client";
static const char CLIENT_FILENAME_CONFIG[] = "\\userconfig.cntcfg";
static const char CLIENT_PROMPT_DEFAULT[] = "Client> ";
static const char CLIENT_PUBKEY_NAME[] = "client_public_key.ccpkey";
static const char CLIENT_PRIKEY_NAME[] = "client_secret_key.ccskey";
static const char CLIENT_TOPOLOGY_NAME[] = "\\client_topology";
static const char CLIENT_WINDOW_TITLE[] = "Client v1.0a";

static const char DLA_APPLICATION_BANNER[] = "DLA v1.0 \n"
"QRCS Corp. 2024, All rights reserved. \n"
"A quantum safe Domain List Agent server. \n"
"Type Help for command mode options. \n"
"One command per line, press enter to run.";
static const char DLA_APPLICATION_NAME[] = "DLA";
static const char DLA_APPLICATION_PATH[] = "\\DLA";
static const char DLA_FILENAME_CONFIG[] = "\\userconfig.dlacfg";
static const char DLA_PUBKEY_NAME[] = "dla_public_key.dcpkey";
static const char DLA_PRIKEY_NAME[] = "dla_secret_key.dcskey";
static const char DLA_PROMPT_DEFAULT[] = "DLA> ";
static const char DLA_TOPOLOGY_NAME[] = "\\dla_topology";
static const char DLA_WINDOW_TITLE[] = "Domain List Agent v1.0a";

static const char IDG_APPLICATION_BANNER[] = "IDG v1.0 \n"
"QRCS Corp. 2024, All rights reserved. \n"
"A quantum safe Inter-Domain Gateway server. \n"
"Type Help for command mode options. \n"
"One command per line, press enter to run.";
static const char IDG_APPLICATION_NAME[] = "IDG";
static const char IDG_APPLICATION_PATH[] = "\\IDG";
static const char IDG_FILENAME_CONFIG[] = "\\userconfig.idgcfg";
static const char IDG_PUBKEY_NAME[] = "idg_public_key.icpkey";
static const char IDG_PRIKEY_NAME[] = "idg_secret_key.icskey";
static const char IDG_PROMPT_DEFAULT[] = "IDG> ";
static const char IDG_TOPOLOGY_NAME[] = "\\idg_topology";
static const char IDG_WINDOW_TITLE[] = "MPDC Inter-Domain Gateway v1.0a";

static const char RDS_APPLICATION_BANNER[] = "RDS v1.0 \n"
"QRCS Corp. 2024, All rights reserved. \n"
"A quantum safe Root Domain Security server. \n"
"Type Help for command mode options. \n"
"One command per line, press enter to run.";
static const char RDS_APPLICATION_NAME[] = "RDS";
static const char RDS_APPLICATION_PATH[] = "\\RDS";
static const char RDS_FILENAME_CONFIG[] = "\\userconfig.rdscfg";
static const char RDS_PUBKEY_NAME[] = "rds_public_key.rcpkey";
static const char RDS_PRIKEY_NAME[] = "rds_secret_key.rcskey";
static const char RDS_PROMPT_DEFAULT[] = "RDS> ";
static const char RDS_TOPOLOGY_NAME[] = "\\rds_topology";
static const char RDS_WINDOW_TITLE[] = "MPDC Root Domain Security Server v1.0a";

static const char MAS_APPLICATION_BANNER[] = "Server v1.0 \n"
"QRCS Corp. 2024, All rights reserved. \n"
"A quantum safe MPDC Application Server. \n"
"Type Help for command mode options. \n"
"One command per line, press enter to run.";
static const char MAS_APPLICATION_NAME[] = "MAS";
static const char MAS_APPLICATION_PATH[] = "\\MAS";
static const char MAS_FILENAME_CONFIG[] = "\\userconfig.mascfg";
static const char MAS_PUBKEY_NAME[] = "server_public_key.mcpkey";
static const char MAS_PRIKEY_NAME[] = "server_secret_key.mcskey";
static const char MAS_PROMPT_DEFAULT[] = "MAS> ";
static const char MAS_TOPOLOGY_NAME[] = "\\mas_topology";
static const char MAS_WINDOW_TITLE[] = "MPDC Application Server v1.0a";

static void server_child_certificate_issuer(mpdc_server_application_state* state)
{
	assert(state != NULL);

	if (state != NULL)
	{
		qsc_memutils_clear(state->issuer, MPDC_CERTIFICATE_ISSUER_SIZE);
		qsc_stringutils_concat_strings(state->issuer, MPDC_CERTIFICATE_ISSUER_SIZE, state->domain);
		qsc_stringutils_concat_strings(state->issuer, MPDC_CERTIFICATE_ISSUER_SIZE, "_");
		qsc_stringutils_concat_strings(state->issuer, MPDC_CERTIFICATE_ISSUER_SIZE, state->hostname);
		qsc_stringutils_concat_strings(state->issuer, MPDC_CERTIFICATE_ISSUER_SIZE, MPDC_CERTIFICATE_CHILD_EXTENSION);
	}
}

static void server_storage_directory(const mpdc_server_application_state* state, char* dpath, size_t pathlen)
{
	assert(state != NULL);
	assert(dpath != NULL);
	assert(pathlen >= MPDC_MINIMUM_PATH_LENGTH);

	if (state != NULL && dpath != NULL && pathlen >= MPDC_MINIMUM_PATH_LENGTH)
	{
		qsc_folderutils_get_directory(qsc_folderutils_directories_user_documents, dpath);

		if (qsc_folderutils_directory_exists(dpath) == true)
		{
			qsc_stringutils_concat_strings(dpath, pathlen, MPDC_APPLICATION_ROOT_PATH);

			if (qsc_folderutils_directory_exists(dpath) == false)
			{
				qsc_folderutils_create_directory(dpath);
			}

			qsc_stringutils_concat_strings(dpath, pathlen, state->aplpath);

			if (qsc_folderutils_directory_exists(dpath) == false)
			{
				qsc_folderutils_create_directory(dpath);
			}
		}
	}
}

static void server_backup_directory(const mpdc_server_application_state* state, char* dpath, size_t pathlen)
{
	assert(state != NULL);
	assert(dpath != NULL);
	assert(pathlen >= MPDC_MINIMUM_PATH_LENGTH);

	if (state != NULL && dpath != NULL && pathlen >= MPDC_MINIMUM_PATH_LENGTH)
	{
		server_storage_directory(state, dpath, pathlen);

		if (qsc_folderutils_directory_exists(dpath) == true)
		{
			qsc_stringutils_concat_strings(dpath, pathlen, MPDC_CERTIFICATE_BACKUP_PATH);

			if (qsc_folderutils_directory_exists(dpath) == false)
			{
				qsc_folderutils_create_directory(dpath);
			}
		}
	}
}

static void server_config_path(const mpdc_server_application_state* state, char* fpath, size_t pathlen)
{
	assert(state != NULL);
	assert(fpath != NULL);
	assert(pathlen >= MPDC_MINIMUM_PATH_LENGTH);

	if (state != NULL && fpath != NULL && pathlen >= MPDC_MINIMUM_PATH_LENGTH)
	{
		server_storage_directory(state, fpath, pathlen);
		qsc_stringutils_concat_strings(fpath, pathlen, state->cfgname);
	}
}

static void server_logging_path(const mpdc_server_application_state* state, char* fpath, size_t pathlen)
{
	assert(state != NULL);
	assert(fpath != NULL);
	assert(pathlen >= MPDC_MINIMUM_PATH_LENGTH);

	if (state != NULL && fpath != NULL && pathlen >= MPDC_MINIMUM_PATH_LENGTH)
	{
		server_storage_directory(state, fpath, pathlen);
		qsc_stringutils_concat_strings(fpath, pathlen, MPDC_LOG_FILENAME);
	}
}

static void server_topology_directory(const mpdc_server_application_state* state, char* dpath, size_t pathlen)
{
	assert(state != NULL);
	assert(dpath != NULL);
	assert(pathlen >= MPDC_MINIMUM_PATH_LENGTH);

	if (state != NULL && dpath != NULL && pathlen >= MPDC_MINIMUM_PATH_LENGTH)
	{
		server_storage_directory(state, dpath, pathlen);
		qsc_stringutils_concat_strings(dpath, pathlen, MPDC_CERTIFICATE_TOPOLOGY_PATH);

		if (qsc_folderutils_directory_exists(dpath) == false)
		{
			qsc_folderutils_create_directory(dpath);
		}
	}
}

static void server_topology_path(const mpdc_server_application_state* state, char* fpath, size_t pathlen)
{
	assert(state != NULL);
	assert(fpath != NULL);
	assert(pathlen >= MPDC_MINIMUM_PATH_LENGTH);

	if (state != NULL && fpath != NULL && pathlen >= MPDC_MINIMUM_PATH_LENGTH)
	{
		server_topology_directory(state, fpath, pathlen);
		qsc_stringutils_concat_strings(fpath, pathlen, state->topname);
		qsc_stringutils_concat_strings(fpath, pathlen, MPDC_CERTIFICATE_TOPOLOGY_EXTENSION);
	}
}

static void server_initialize_key_chain(mpdc_server_application_state* state, const char* password, size_t passlen, const char* username, size_t userlen)
{
	assert(state != NULL);
	assert(password != NULL);
	assert(username != NULL);
	assert(passlen != 0);
	assert(userlen != 0);

	if (state != NULL && password != NULL && username != NULL && passlen != 0 && userlen != 0)
	{
		const size_t klen = (SERVER_KEYCHAIN_DEPTH * SERVER_KEYCHAIN_WIDTH);
		mpdc_crypto_generate_application_keychain(state->kchain, klen, password, passlen, username, userlen);
	}
}

static void server_load_key_chain(mpdc_server_application_state* state)
{
	assert(state != NULL);

	if (state != NULL)
	{
		const size_t klen = (SERVER_KEYCHAIN_DEPTH * SERVER_KEYCHAIN_WIDTH) + MPDC_ASYMMETRIC_SIGNING_KEY_SIZE;

		state->kchain = qsc_memutils_malloc(klen);

		if (state->kchain != NULL)
		{
			state->sigkey = state->kchain + (SERVER_KEYCHAIN_DEPTH * SERVER_KEYCHAIN_WIDTH);
		}
	}
}

static bool server_log_decrypt(mpdc_server_application_state* state)
{
	assert(state != NULL);

	bool res;

	res = false;

	if (state != NULL)
	{
		if (qsc_fileutils_exists(state->logpath) == true)
		{
			size_t flen;

			flen = qsc_fileutils_get_size(state->logpath);

			if (flen > 0)
			{
				uint8_t* pdec;
				uint8_t* penc;

				pdec = (uint8_t*)qsc_memutils_malloc(flen - MPDC_STORAGE_MAC_SIZE);
				penc = (uint8_t*)qsc_memutils_malloc(flen);

				if (penc != NULL && pdec != NULL)
				{
					size_t mlen;

					mlen = qsc_fileutils_copy_file_to_stream(state->logpath, (char*)penc, flen);

					if (mlen > 0)
					{
						const uint8_t* pkey = state->kchain + (SERVER_KEYCHAIN_LOG_INDEX * SERVER_KEYCHAIN_WIDTH);

						assert(qsc_memutils_zeroed(pkey, MPDC_CRYPTO_SYMMETRIC_KEY_SIZE) == false);

						res = mpdc_crypto_decrypt_stream(pdec, pkey, penc, mlen - MPDC_STORAGE_MAC_SIZE);

						if (res == true)
						{
							qsc_fileutils_erase(state->logpath);
							qsc_fileutils_copy_stream_to_file(state->logpath, (const char*)pdec, flen - MPDC_STORAGE_MAC_SIZE);
						}
						else
						{
							/* log is corrupted, delete and create */
							qsc_fileutils_delete(state->logpath);
							mpdc_server_log_host(state);
						}
					}
				}

				if (pdec != NULL)
				{
					qsc_memutils_alloc_free(pdec);
				}

				if (penc != NULL)
				{
					qsc_memutils_alloc_free(penc);
				}
			}
		}
	}

	return res;
}

static void server_log_encrypt(const mpdc_server_application_state* state)
{
	assert(state != NULL);

	if (state != NULL)
	{
		if (qsc_fileutils_exists(state->logpath) == true)
		{
			size_t flen;

			flen = qsc_fileutils_get_size(state->logpath);

			if (flen > 0)
			{
				uint8_t* ptxt;
				uint8_t* penc;

				ptxt = (uint8_t*)qsc_memutils_malloc(flen);
				penc = (uint8_t*)qsc_memutils_malloc(flen + MPDC_STORAGE_MAC_SIZE);

				if (penc != NULL && ptxt != NULL)
				{
					flen = qsc_fileutils_copy_file_to_stream(state->logpath, (char*)ptxt, flen);

					if (flen > 0)
					{
						const uint8_t* pkey = state->kchain + (SERVER_KEYCHAIN_LOG_INDEX * SERVER_KEYCHAIN_WIDTH);

						assert(qsc_memutils_zeroed(pkey, MPDC_CRYPTO_SYMMETRIC_KEY_SIZE) == false);

						mpdc_crypto_encrypt_stream(penc, pkey, ptxt, flen);
						qsc_fileutils_erase(state->logpath);
						qsc_fileutils_copy_stream_to_file(state->logpath, (const char*)penc, flen + MPDC_STORAGE_MAC_SIZE);
					}
				}

				if (ptxt != NULL)
				{
					qsc_memutils_alloc_free(ptxt);
				}

				if (penc != NULL)
				{
					qsc_memutils_alloc_free(penc);
				}
			}
		}
	}
}

static void server_log_initialize(mpdc_server_application_state* state)
{
	assert(state != NULL);

	if (state != NULL)
	{
		if (qsc_fileutils_exists(state->logpath) == false ||
			qsc_fileutils_get_size(state->logpath) == 0)
		{
			size_t slen;

			mpdc_logger_reset(state->logpath);
			slen = qsc_stringutils_string_size(state->hostname);
			mpdc_logger_write_decorated_message(state->logpath, mpdc_application_log_log_header, NULL, 0);
			mpdc_logger_write_decorated_time_stamped_message(state->logpath, mpdc_application_log_log_created, state->hostname, slen);
			server_log_encrypt(state);
		}
	}
}

static void server_root_certificate_issuer(mpdc_server_application_state* state)
{
	assert(state != NULL);

	if (state != NULL)
	{
		qsc_memutils_clear(state->issuer, MPDC_CERTIFICATE_ISSUER_SIZE);
		qsc_stringutils_concat_strings(state->issuer, MPDC_CERTIFICATE_ISSUER_SIZE, state->domain);
		qsc_stringutils_concat_strings(state->issuer, MPDC_CERTIFICATE_ISSUER_SIZE, "_");
		qsc_stringutils_concat_strings(state->issuer, MPDC_CERTIFICATE_ISSUER_SIZE, state->hostname);
		qsc_stringutils_concat_strings(state->issuer, MPDC_CERTIFICATE_ISSUER_SIZE, MPDC_CERTIFICATE_ROOT_EXTENSION);
	}
}

static void server_state_deserialize(mpdc_server_application_state* state, const uint8_t* input, size_t inlen)
{
	assert(state != NULL);
	assert(input != NULL);
	assert(inlen >= MPDC_SERVER_APPLICATION_STATE_SIZE);

	size_t pos;

	if (state != NULL && input != NULL && inlen >= MPDC_SERVER_APPLICATION_STATE_SIZE)
	{
		qsc_memutils_clear(state->cmdprompt, sizeof(state->cmdprompt));
		qsc_memutils_clear(state->domain, sizeof(state->domain));
		qsc_memutils_clear(state->hostname, sizeof(state->hostname));
		qsc_memutils_clear(state->localip, sizeof(state->localip));
		qsc_memutils_clear(state->logpath, sizeof(state->logpath));
		qsc_memutils_clear(&state->tlist, sizeof(state->tlist));
		qsc_memutils_clear(state->username, sizeof(state->username));

		qsc_memutils_copy(state->domain, input, sizeof(state->domain));
		pos = sizeof(state->domain);
		qsc_memutils_copy(state->hostname, ((const char*)input + pos), sizeof(state->hostname));
		pos += sizeof(state->hostname);
		qsc_memutils_copy(state->localip, ((const char*)input + pos), sizeof(state->localip));
		pos += sizeof(state->localip);
		qsc_memutils_copy(state->logpath, ((const char*)input + pos), sizeof(state->logpath));
		pos += sizeof(state->logpath);
		qsc_memutils_copy(state->username, ((const char*)input + pos), sizeof(state->username));
		pos += sizeof(state->username);
		qsc_memutils_copy(state->issuer, ((const char*)input + pos), sizeof(state->issuer));
		pos += sizeof(state->issuer);
		qsc_memutils_copy(&state->port, ((const char*)input + pos), sizeof(uint16_t));
		pos += sizeof(uint16_t);
		qsc_memutils_copy(&state->srvtype, ((const char*)input + pos), sizeof(uint8_t));
		pos += sizeof(uint8_t);
		qsc_memutils_copy(&state->retries, ((const char*)input + pos), sizeof(uint8_t));
		pos += sizeof(uint8_t);
		qsc_memutils_copy(&state->timeout, ((const char*)input + pos), sizeof(uint16_t));
		pos += sizeof(uint16_t);
		qsc_memutils_copy(&state->joined, ((const char*)input + pos), sizeof(bool));
		pos += sizeof(bool);
		qsc_memutils_copy(&state->loghost, ((const char*)input + pos), sizeof(bool));
		pos += sizeof(bool);
		qsc_memutils_copy(state->sigkey, ((const char*)input + pos), MPDC_ASYMMETRIC_SIGNING_KEY_SIZE);

		state->mode = mpdc_console_mode_user;
		state->action = mpdc_command_action_none;
	}
}

static bool mpdc_server_configuration_load(mpdc_server_application_state* state)
{
	assert(state != NULL);

	bool res;

	res = false;

	if (state != NULL)
	{
		char fpath[MPDC_STORAGE_PATH_MAX] = { 0 };

		server_config_path(state, fpath, sizeof(fpath));
		res = qsc_fileutils_exists(fpath);

		if (res == true)
		{
			uint8_t encs[MPDC_SERVER_APPLICATION_STATE_SIZE + MPDC_STORAGE_MAC_SIZE] = { 0 };
			const uint8_t* pkey;

			res = (qsc_fileutils_copy_file_to_stream(fpath, (char*)encs, sizeof(encs)) == sizeof(encs));

			if (res == true)
			{
				uint8_t decs[MPDC_SERVER_APPLICATION_STATE_SIZE] = { 0 };

				pkey = state->kchain + (SERVER_KEYCHAIN_STATE_INDEX * SERVER_KEYCHAIN_WIDTH);

				assert(qsc_memutils_zeroed(pkey, MPDC_CRYPTO_SYMMETRIC_KEY_SIZE) == false);

				res = mpdc_crypto_decrypt_stream(decs, pkey, encs, sizeof(decs));

				if (res == true)
				{
					/* deserialize the state */
					server_state_deserialize(state, decs, sizeof(decs));
				}
			}
		}
	}

	return res;
}

static bool server_state_load(mpdc_server_application_state* state)
{
	assert(state != NULL);

	bool res;

	/* initialize the log */
	server_log_initialize(state);

	res = mpdc_server_configuration_load(state);

	if (res == true)
	{
		res = mpdc_server_topology_load(state);

		/* load the topology */
		if (res == true)
		{
			/* change the prompt status */
			mpdc_server_set_command_prompt(state);
		}
	}

	return res;
}

static bool server_state_reset(const mpdc_server_application_state* state)
{
	assert(state != NULL);

	bool res;

	res = false;

	if (state != NULL)
	{
		char fpath[MPDC_STORAGE_PATH_MAX] = { 0 };

		server_config_path(state, fpath, sizeof(fpath));
		res = qsc_fileutils_exists(fpath);

		if (res == true)
		{
			qsc_fileutils_erase(fpath);
			res = qsc_fileutils_delete(fpath);
		}
	}

	return res;
}

static size_t server_state_serialize(const mpdc_server_application_state* state, uint8_t* output)
{
	assert(state != NULL);
	assert(output != NULL);

	size_t pos;

	if (state != NULL && output != NULL)
	{
		qsc_memutils_copy(output, state->domain, sizeof(state->domain));
		pos = sizeof(state->domain);
		qsc_memutils_copy(((char*)output + pos), state->hostname, sizeof(state->hostname));
		pos += sizeof(state->hostname);
		qsc_memutils_copy(((char*)output + pos), state->localip, sizeof(state->localip));
		pos += sizeof(state->localip);
		qsc_memutils_copy(((char*)output + pos), state->logpath, sizeof(state->logpath));
		pos += sizeof(state->logpath);
		qsc_memutils_copy(((char*)output + pos), state->username, sizeof(state->username));
		pos += sizeof(state->username);
		qsc_memutils_copy(((char*)output + pos), state->issuer, sizeof(state->issuer));
		pos += sizeof(state->issuer);
		qsc_memutils_copy(((char*)output + pos), &state->port, sizeof(uint16_t));
		pos += sizeof(uint16_t);
		qsc_memutils_copy(((char*)output + pos), &state->srvtype, sizeof(uint8_t));
		pos += sizeof(uint8_t);
		qsc_memutils_copy(((char*)output + pos), &state->retries, sizeof(uint8_t));
		pos += sizeof(uint8_t);
		qsc_memutils_copy(((char*)output + pos), &state->timeout, sizeof(uint16_t));
		pos += sizeof(uint16_t);
		qsc_memutils_copy(((char*)output + pos), &state->joined, sizeof(bool));
		pos += sizeof(bool);
		qsc_memutils_copy(((char*)output + pos), &state->loghost, sizeof(bool));
		pos += sizeof(bool);
		qsc_memutils_copy(((char*)output + pos), state->sigkey, MPDC_ASYMMETRIC_SIGNING_KEY_SIZE);
		pos += MPDC_ASYMMETRIC_SIGNING_KEY_SIZE;
	}

	return pos;
}

static void server_unload_key_chain(mpdc_server_application_state* state)
{
	assert(state != NULL);

	if (state != NULL && state->kchain != NULL)
	{
		const size_t klen = (SERVER_KEYCHAIN_DEPTH * SERVER_KEYCHAIN_WIDTH);
		qsc_memutils_clear(state->kchain, klen);
	}
}

static void server_unload_signature_key(mpdc_server_application_state* state)
{
	assert(state != NULL);

	if (state != NULL && state->kchain != NULL)
	{
		const size_t klen = (SERVER_KEYCHAIN_DEPTH * SERVER_KEYCHAIN_WIDTH) + MPDC_ASYMMETRIC_SIGNING_KEY_SIZE;
		qsc_memutils_clear(state->kchain, klen);
		qsc_memutils_alloc_free(state->kchain);
	}
}

void mpdc_server_certificate_directory(const mpdc_server_application_state* state, char* dpath, size_t pathlen)
{
	assert(state != NULL);
	assert(dpath != NULL);
	assert(pathlen >= MPDC_MINIMUM_PATH_LENGTH);

	if (state != NULL && dpath != NULL && pathlen >= MPDC_MINIMUM_PATH_LENGTH)
	{
		server_storage_directory(state, dpath, pathlen);
		qsc_stringutils_concat_strings(dpath, pathlen, MPDC_CERTIFICATE_STORE_PATH);

		if (qsc_folderutils_directory_exists(dpath) == false)
		{
			qsc_folderutils_create_directory(dpath);
		}

		qsc_folderutils_append_delimiter(dpath);
	}
}

void mpdc_server_certificate_path(const mpdc_server_application_state* state, char* fpath, size_t pathlen, const char* issuer)
{
	assert(state != NULL);
	assert(fpath != NULL);
	assert(pathlen >= MPDC_MINIMUM_PATH_LENGTH);
	assert(issuer != NULL);

	if (state != NULL && fpath != NULL && pathlen >= MPDC_MINIMUM_PATH_LENGTH && issuer != NULL)
	{
		mpdc_server_certificate_directory(state, fpath, pathlen);
		qsc_stringutils_concat_strings(fpath, pathlen, issuer);
	}
}

bool mpdc_server_child_certificate_export(const mpdc_server_application_state* state, const char* dpath)
{
	assert(state != NULL);
	assert(dpath != NULL);

	bool res;

	res = false;

	if (state != NULL && dpath != NULL)
	{
		if (qsc_folderutils_directory_exists(dpath) == true &&
			qsc_stringutils_string_size(state->issuer) > 0)
		{
			char cpath[MPDC_STORAGE_PATH_MAX] = { 0 };

			mpdc_server_child_certificate_path(state, cpath, sizeof(cpath));

			if (qsc_fileutils_exists(cpath) == true)
			{
				char opath[MPDC_STORAGE_PATH_MAX] = { 0 };

				qsc_stringutils_copy_string(opath, sizeof(opath), dpath);

				if (qsc_folderutils_directory_has_delimiter(opath) == false)
				{
					qsc_folderutils_append_delimiter(opath);
				}

				qsc_stringutils_concat_strings(opath, sizeof(opath), state->issuer);
				res = qsc_fileutils_file_copy(cpath, opath);
			}
		}
	}

	return res;
}

bool mpdc_server_child_certificate_from_issuer(mpdc_child_certificate* ccert, const mpdc_server_application_state* state, const char* issuer)
{
	char rpath[MPDC_STORAGE_PATH_MAX] = { 0 };
	bool res;

	res = false;

	mpdc_server_child_certificate_path_from_issuer(state, rpath, sizeof(rpath), issuer);

	if (qsc_fileutils_exists(rpath) == true)
	{
		res = mpdc_certificate_child_file_to_struct(rpath, ccert);
	}

	return res;
}

bool mpdc_server_child_certificate_from_serial(mpdc_child_certificate* ccert, const mpdc_server_application_state* state, const uint8_t* serial)
{
	mpdc_topology_node_state cnode = { 0 };
	bool res;

	res = false;

	if (mpdc_topology_node_find(&state->tlist, &cnode, serial) == true)
	{
		char rpath[MPDC_STORAGE_PATH_MAX] = { 0 };

		mpdc_server_child_certificate_path_from_issuer(state, rpath, sizeof(rpath), cnode.issuer);

		if (qsc_fileutils_exists(rpath) == true)
		{
			res = mpdc_certificate_child_file_to_struct(rpath, ccert);
		}
	}

	return res;
}

void mpdc_server_child_certificate_generate(mpdc_server_application_state* state, mpdc_child_certificate* ccert, uint64_t period)
{
	assert(state != NULL);
	assert(ccert != NULL);
	assert(period != 0);

	if (state != NULL && ccert != NULL && period != 0)
	{
		mpdc_certificate_expiration exp = { 0 };
		mpdc_signature_keypair akp = { 0 };

		/* generate the key-pair */
		mpdc_certificate_signature_generate_keypair(&akp);
		exp.from = qsc_timestamp_epochtime_seconds();
		exp.to = exp.from + period;

		/* extrapolate a unique issuer name and store in state; domain_host.ccert */
		server_child_certificate_issuer(state);

		/* create the certificate */
		mpdc_certificate_child_create(ccert, akp.pubkey, &exp, state->issuer, state->srvtype);

		/* write the private key to state */
		qsc_memutils_copy(state->sigkey, akp.prikey, MPDC_ASYMMETRIC_SIGNING_KEY_SIZE);
	}
}

bool mpdc_server_child_certificate_import(mpdc_child_certificate* lcert, mpdc_server_application_state* state, const char* fpath)
{
	assert(lcert != NULL);
	assert(state != NULL);
	assert(fpath != NULL);

	bool res;

	res = false;

	if (lcert != NULL && state != NULL && fpath != NULL)
	{
		char cpath[MPDC_STORAGE_PATH_MAX] = { 0 };

		mpdc_server_child_certificate_path(state, cpath, sizeof(cpath));

		if (mpdc_certificate_child_file_to_struct(fpath, lcert) == true)
		{
			if (mpdc_certificate_child_is_valid(lcert) == true)
			{
				if (mpdc_certificate_root_is_valid(&state->root) == true)
				{
					if (mpdc_certificate_root_signature_verify(lcert, &state->root) == true)
					{
						if (qsc_fileutils_exists(cpath) == true)
						{
							/* overwrite dialogue */
							if (mpdc_menu_print_predefined_message_confirm(mpdc_application_certificate_exists, state->mode, state->hostname) == true)
							{
								mpdc_topology_node_state rnode = { 0 };

								qsc_fileutils_delete(cpath);

								if (mpdc_topology_node_find_issuer(&state->tlist, &rnode, lcert->issuer) == true)
								{
									/* remove the old node and add the update */
									mpdc_topology_node_remove(&state->tlist, rnode.serial);
									mpdc_topology_child_register(&state->tlist, lcert, state->localip);
								}

								res = qsc_fileutils_file_copy(fpath, cpath);
							}
						}
						else
						{
							res = qsc_fileutils_file_copy(fpath, cpath);
						}
					}
				}
			}
		}
	}

	return res;
}

void mpdc_server_child_certificate_path(const mpdc_server_application_state* state, char* fpath, size_t pathlen)
{
	assert(state != NULL);
	assert(fpath != NULL);
	assert(pathlen >= MPDC_MINIMUM_PATH_LENGTH);

	if (state != NULL && fpath != NULL && pathlen >= MPDC_MINIMUM_PATH_LENGTH)
	{
		mpdc_server_certificate_directory(state, fpath, pathlen);
		qsc_stringutils_concat_strings(fpath, pathlen, state->issuer);
	}
}

void mpdc_server_child_certificate_path_from_issuer(const mpdc_server_application_state* state, char* fpath, size_t pathlen, const char* issuer)
{
	assert(state != NULL);
	assert(fpath != NULL);
	assert(pathlen >= MPDC_MINIMUM_PATH_LENGTH);
	assert(issuer != NULL);

	if (state != NULL && fpath != NULL && issuer != NULL && pathlen >= MPDC_MINIMUM_PATH_LENGTH)
	{
		mpdc_server_certificate_directory(state, fpath, pathlen);
		qsc_stringutils_concat_strings(fpath, pathlen, issuer);
	}
}

bool mpdc_server_child_certificate_print(const char* fpath, size_t pathlen)
{
	assert(fpath != NULL);
	assert(pathlen >= MPDC_MINIMUM_PATH_LENGTH);

	bool res;

	res = false;

	if (fpath != NULL && pathlen >= MPDC_MINIMUM_PATH_LENGTH)
	{
		if (pathlen > 0 &&
			qsc_fileutils_exists(fpath) &&
			qsc_stringutils_string_contains(fpath, MPDC_CERTIFICATE_CHILD_EXTENSION) == true)
		{
			mpdc_child_certificate ccert = { 0 };

			if (mpdc_certificate_child_file_to_struct(fpath, &ccert) == true)
			{
				char enck[MPDC_CHILD_CERTIFICATE_STRING_SIZE] = { 0 };
				const size_t SLEN = mpdc_certificate_child_encode(enck, &ccert);

				if (SLEN <= MPDC_CHILD_CERTIFICATE_STRING_SIZE)
				{
					qsc_consoleutils_print_safe(enck);
					qsc_consoleutils_print_line("");
					res = true;
				}
			}
		}
	}

	return res;
}

void mpdc_server_local_certificate_store(mpdc_server_application_state* state, const mpdc_child_certificate* ccert, const char* address)
{
	assert(state != NULL);
	assert(ccert != NULL);
	assert(address != NULL);

	if (state != NULL && ccert != NULL && address != NULL)
	{
		char fpath[MPDC_STORAGE_PATH_MAX] = { 0 };

		/* copy the certificate to file */
		mpdc_server_child_certificate_path(state, fpath, sizeof(fpath));

		if (qsc_fileutils_exists(fpath) == true)
		{
			qsc_fileutils_delete(fpath);
		}

		mpdc_certificate_child_struct_to_file(fpath, ccert);

		if (mpdc_topology_node_exists(&state->tlist, ccert->serial) == true)
		{
			/* delete the old node entry */
			mpdc_topology_node_remove(&state->tlist, ccert->serial);
		}

		/* get the node address and register in the topology */
		mpdc_topology_child_register(&state->tlist, ccert, address);
		mpdc_server_topology_to_file(state);
	}
}

void mpdc_server_clear_config(mpdc_server_application_state* state)
{
	assert(state != NULL);

	if (state != NULL)
	{
		server_state_reset(state);
		mpdc_server_state_initialize(state, state->srvtype);
	}
}

void mpdc_server_clear_log(mpdc_server_application_state* state)
{
	assert(state != NULL);

	if (state != NULL)
	{
		/* erase contents */
		mpdc_logger_erase_all(state->logpath);
		/* reset the log file */
		qsc_fileutils_delete(state->logpath);
		mpdc_server_log_host(state);
	}
}

void mpdc_server_erase_all(mpdc_server_application_state* state)
{
	assert(state != NULL);

	if (state != NULL)
	{
		mpdc_server_clear_log(state);
		server_state_reset(state);
		mpdc_server_state_initialize(state, state->srvtype);
	}
}

void mpdc_server_log_host(mpdc_server_application_state* state)
{
	assert(state != NULL);

	size_t slen;

	if (state != NULL)
	{
		slen = qsc_stringutils_string_size(state->hostname);

		/* initialize the log file */
		server_log_initialize(state);

		if (state->loghost == true)
		{
			/* first log entry */
			mpdc_server_log_write_message(state, mpdc_application_log_log_enabled, state->hostname, slen);
		}
		else
		{
			/* disable and warn */
			mpdc_server_log_write_message(state, mpdc_application_log_log_disabled, state->hostname, slen);
		}

		mpdc_server_state_store(state);
	}
}

void mpdc_server_log_print(mpdc_server_application_state* state)
{
	assert(state != NULL);

	if (state != NULL)
	{
		if (mpdc_logger_exists(state->logpath))
		{
			if (server_log_decrypt(state) == true)
			{
				char buf[MPDC_STORAGE_MESSAGE_MAX] = { 0 };
				int64_t len;
				size_t ctr;

				ctr = 0;

				while (true)
				{
					len = mpdc_logger_read_line(state->logpath, buf, sizeof(buf), ctr);

					if (len > 0)
					{
						mpdc_menu_print_prompt(mpdc_console_mode_enable, state->hostname);
						qsc_consoleutils_print_line(buf);
						qsc_stringutils_clear_string(buf);
					}
					else if (len < 0)
					{
						break;
					}

					++ctr;
				}

				server_log_encrypt(state);
			}
		}
		else
		{
			mpdc_menu_print_predefined_message(mpdc_application_log_empty, mpdc_console_mode_enable, state->hostname);
		}
	}
}

bool mpdc_server_log_write_message(mpdc_server_application_state* state, mpdc_application_messages msgtype, const char* message, size_t msglen)
{
	assert(state != NULL);

	bool res;

	res = false;

	if (state != NULL)
	{
		res = mpdc_logger_exists(state->logpath);

		if (res == true)
		{
			if (qsc_fileutils_get_size(state->logpath) > 0)
			{
				res = server_log_decrypt(state);
			}

			if (res == true)
			{
				mpdc_logger_write_decorated_time_stamped_message(state->logpath, msgtype, message, msglen);
				server_log_encrypt(state);
			}
		}
	}

	return res;
}

void mpdc_server_mfkcol_path(const mpdc_server_application_state* state, char* fpath, size_t pathlen)
{
	assert(state != NULL);
	assert(fpath != NULL);
	assert(pathlen >= MPDC_MINIMUM_PATH_LENGTH);

	if (state != NULL && fpath != NULL && pathlen >= MPDC_MINIMUM_PATH_LENGTH)
	{
		server_topology_directory(state, fpath, pathlen);
		qsc_stringutils_concat_strings(fpath, pathlen, state->topname);
		qsc_stringutils_concat_strings(fpath, pathlen, MPDC_CERTIFICATE_MFCOL_EXTENSION);
	}
}

bool mpdc_server_mfkcol_from_file(qsc_collection_state* mfkcol, const mpdc_server_application_state* state)
{
	assert(mfkcol != NULL);
	assert(state != NULL);

	bool res;

	res = false;

	if (mfkcol != NULL && state != NULL)
	{
		char fpath[MPDC_STORAGE_PATH_MAX] = { 0 };

		mpdc_server_mfkcol_path(state, fpath, sizeof(fpath));

		if (qsc_fileutils_exists(fpath) == true)
		{
			size_t flen;

			flen = qsc_fileutils_get_size(fpath);

			if (flen > 0)
			{
				uint8_t* pdec;
				uint8_t* penc;

				pdec = (uint8_t*)qsc_memutils_malloc(flen - MPDC_STORAGE_MAC_SIZE);
				penc = (uint8_t*)qsc_memutils_malloc(flen);

				if (penc != NULL && pdec != NULL)
				{
					size_t mlen;

					mlen = qsc_fileutils_copy_file_to_stream(fpath, (char*)penc, flen);

					if (mlen > 0)
					{
						const uint8_t* pkey = state->kchain + (SERVER_KEYCHAIN_MFKCOL_INDEX * SERVER_KEYCHAIN_WIDTH);

						assert(qsc_memutils_zeroed(pkey, MPDC_CRYPTO_SYMMETRIC_KEY_SIZE) == false);

						res = mpdc_crypto_decrypt_stream(pdec, pkey, penc, mlen - MPDC_STORAGE_MAC_SIZE);

						if (res == true)
						{
							qsc_collection_deserialize(mfkcol, pdec);
						}
					}
				}

				if (pdec != NULL)
				{
					qsc_memutils_alloc_free(pdec);
				}

				if (penc != NULL)
				{
					qsc_memutils_alloc_free(penc);
				}
			}
		}
	}

	return res;
}

void mpdc_server_mfkcol_to_file(const qsc_collection_state* mfkcol, const mpdc_server_application_state* state)
{
	assert(mfkcol != NULL);
	assert(state != NULL);

	size_t clen;

	if (mfkcol != NULL && state != NULL)
	{
		clen = qsc_collection_size(mfkcol);

		if (clen > 0)
		{
			uint8_t* ptxt;
			uint8_t* penc;

			ptxt = (uint8_t*)qsc_memutils_malloc(clen);
			penc = (uint8_t*)qsc_memutils_malloc(clen + MPDC_STORAGE_MAC_SIZE);

			if (penc != NULL && ptxt != NULL)
			{
				char fpath[MPDC_STORAGE_PATH_MAX] = { 0 };
				const uint8_t* pkey = state->kchain + (SERVER_KEYCHAIN_MFKCOL_INDEX * SERVER_KEYCHAIN_WIDTH);

				assert(qsc_memutils_zeroed(pkey, MPDC_CRYPTO_SYMMETRIC_KEY_SIZE) == false);

				mpdc_server_mfkcol_path(state, fpath, sizeof(fpath));

				if (qsc_fileutils_exists(fpath) == true)
				{
					qsc_fileutils_delete(fpath);
				}

				qsc_collection_serialize(ptxt, mfkcol);
				mpdc_crypto_encrypt_stream(penc, pkey, ptxt, clen);
				qsc_fileutils_copy_stream_to_file(fpath, (const char*)penc, clen + MPDC_STORAGE_MAC_SIZE);

				qsc_memutils_alloc_free(penc);
				qsc_memutils_alloc_free(ptxt);
			}
		}
	}
}

void mpdc_server_print_banner(const mpdc_server_application_state* state)
{
	assert(state != NULL);

	if (state != NULL)
	{
		qsc_consoleutils_print_line(state->banner);
		qsc_consoleutils_print_line("");
	}
}

void mpdc_server_print_error(const mpdc_server_application_state* state, mpdc_application_messages appmsg, const char* message, mpdc_protocol_errors error)
{
	assert(state != NULL);
	assert(message != NULL);

	if (state != NULL && message != NULL)
	{
		qsc_mutex mtx = qsc_async_mutex_lock_ex();
		mpdc_menu_print_predefined_text(appmsg, state->mode, state->hostname);
		mpdc_menu_print_text_line(message);
		mpdc_menu_print_error(error, state->mode, state->hostname);
		qsc_async_mutex_unlock_ex(mtx);
	}
}

void mpdc_server_print_configuration(const mpdc_server_application_state* state)
{
	assert(state != NULL);

	const char DEFVAL[] = "NOT-SET";
	char ib[6] = { 0 };

	if (state != NULL)
	{
		mpdc_menu_print_predefined_message(mpdc_application_configuration, mpdc_console_mode_enable, state->hostname);

		const char* sdom[3] = {
			state->cmdprompt,
			"Domain string: ",
			qsc_stringutils_string_size(state->domain) > 0 ? state->domain : DEFVAL,
		};
		qsc_consoleutils_print_concatenated_line(sdom, 3);

		const char* shost[3] = {
			state->cmdprompt,
			"Host name: ",
			qsc_stringutils_string_size(state->hostname) > 0 ? state->hostname : DEFVAL,
		};
		qsc_consoleutils_print_concatenated_line(shost, 3);

		const char* slip[3] = {
			state->cmdprompt,
			"IP address: ",
			qsc_stringutils_string_size(state->localip) > 0 ? state->localip : DEFVAL,
		};
		qsc_consoleutils_print_concatenated_line(slip, 3);

		const char* slog[3] = {
			state->cmdprompt,
			"Host Logging: ",
			state->loghost == true ? "true" : "false",
		};
		qsc_consoleutils_print_concatenated_line(slog, 3);

		qsc_stringutils_int_to_string(state->port, ib, sizeof(ib));
		const char* tmpport[3] = {
			state->cmdprompt,
			"Port number: ",
			ib,
		};
		qsc_consoleutils_print_concatenated_line(tmpport, 3);

		qsc_memutils_clear(ib, sizeof(ib));
		qsc_stringutils_int_to_string(state->retries, ib, sizeof(ib));
		const char* sretr[3] = {
			state->cmdprompt,
			"Authentication retries: ",
			ib,
		};

		qsc_consoleutils_print_concatenated_line(sretr, 3);
		qsc_stringutils_int_to_string(state->timeout, ib, sizeof(ib));

		const char* stout[3] = {
			state->cmdprompt,
			"Console timeout: ",
			ib,
		};

		qsc_consoleutils_print_concatenated_line(stout, 3);
	}
}

bool mpdc_server_root_certificate_export(const mpdc_server_application_state* state, const char* dpath)
{
	assert(state != NULL);
	assert(dpath != NULL);

	bool res;

	res = false;

	if (state != NULL && dpath != NULL)
	{
		if (qsc_folderutils_directory_exists(dpath) == true &&
			qsc_stringutils_string_size(state->issuer) > 0)
		{
			char cpath[MPDC_STORAGE_PATH_MAX] = { 0 };

			mpdc_server_certificate_path(state, cpath, sizeof(cpath), state->issuer);

			if (qsc_fileutils_exists(cpath) == true)
			{
				char opath[MPDC_STORAGE_PATH_MAX] = { 0 };

				qsc_stringutils_copy_string(opath, sizeof(opath), dpath);

				if (qsc_folderutils_directory_has_delimiter(opath) == false)
				{
					qsc_folderutils_append_delimiter(opath);
				}

				qsc_stringutils_concat_strings(opath, sizeof(opath), state->issuer);
				res = qsc_fileutils_file_copy(cpath, opath);
			}
		}
	}

	return res;
}

bool mpdc_server_root_import_dialogue(mpdc_server_application_state* state)
{
	assert(state != NULL);

	size_t slen;
	bool res;

	res = false;

	if (state != NULL)
	{
		char cmsg[MPDC_STORAGE_PASSWORD_MAX] = { 0 };

		while (true)
		{
			mpdc_menu_print_predefined_message(mpdc_application_challenge_root_path, mpdc_console_mode_certificate, state->hostname);
			mpdc_menu_print_prompt(mpdc_console_mode_certificate, state->hostname);
			slen = qsc_consoleutils_get_line(cmsg, sizeof(cmsg)) - 1;

			if (slen >= MPDC_STORAGE_FILEPATH_MIN &&
				slen <= MPDC_STORAGE_FILEPATH_MAX &&
				qsc_fileutils_exists(cmsg) == true &&
				qsc_stringutils_string_contains(cmsg, MPDC_CERTIFICATE_ROOT_EXTENSION))
			{
				if (mpdc_certificate_root_file_to_struct(cmsg, &state->root) == true)
				{
					mpdc_server_root_certificate_store(state, &state->root);
					mpdc_menu_print_predefined_message(mpdc_application_challenge_root_path_success, mpdc_console_mode_certificate, state->hostname);
					res = true;
					break;
				}
				else
				{
					mpdc_menu_print_predefined_message(mpdc_application_challenge_root_path_failure, mpdc_console_mode_certificate, state->hostname);
				}
			}
			else
			{
				mpdc_menu_print_predefined_message(mpdc_application_challenge_root_path_failure, mpdc_console_mode_certificate, state->hostname);
			}
		}
	}

	return res;
}

void mpdc_server_root_certificate_generate(mpdc_server_application_state* state, mpdc_root_certificate* rcert, uint64_t period)
{
	assert(state != NULL);
	assert(rcert != NULL);
	assert(period != 0);

	if (state != NULL && rcert != NULL && period != 0)
	{
		mpdc_certificate_expiration exp = { 0 };
		mpdc_signature_keypair akp = { 0 };

		/* generate the key-pair*/
		mpdc_certificate_signature_generate_keypair(&akp);
		exp.from = qsc_timestamp_epochtime_seconds();
		exp.to = exp.from + period;

		/* Note: ex. mydomain_rds1.rcert */
		server_root_certificate_issuer(state);

		/* create the certificate */
		mpdc_certificate_root_create(rcert, akp.pubkey, &exp, state->issuer);

		/* write the private key to state */
		qsc_memutils_copy(state->sigkey, akp.prikey, sizeof(akp.prikey));
	}
}

bool mpdc_server_root_certificate_load(const mpdc_server_application_state* state, mpdc_root_certificate* root, const mpdc_topology_list_state* tlist)
{
	assert(state != NULL);
	assert(root != NULL);
	assert(tlist != NULL);

	bool res;

	res = false;

	if (state != NULL && root != NULL && tlist != NULL)
	{
		mpdc_topology_node_state rnode = { 0 };

		if (mpdc_topology_node_find_root(tlist, &rnode) == true)
		{
			char fpath[MPDC_STORAGE_PATH_MAX] = { 0 };

			mpdc_server_certificate_path(state, fpath, sizeof(fpath), rnode.issuer);

			if (qsc_fileutils_exists(fpath) &&
				qsc_stringutils_string_contains(fpath, MPDC_CERTIFICATE_ROOT_EXTENSION) == true)
			{
				if (mpdc_certificate_root_is_valid(root) == true)
				{
					if (mpdc_certificate_root_file_to_struct(fpath, root) == true)
					{
						uint8_t chash[MPDC_CRYPTO_SYMMETRIC_HASH_SIZE];

						mpdc_certificate_root_hash(chash, root);
						res = qsc_memutils_are_equal(chash, rnode.chash, sizeof(chash));

						if (res == false)
						{
							qsc_memutils_clear(root, sizeof(mpdc_root_certificate));
						}
					}
				}
			}
		}
	}

	return res;
}

void mpdc_server_root_certificate_path(const mpdc_server_application_state* state, char* fpath, size_t pathlen)
{
	assert(state != NULL);
	assert(fpath != NULL);
	assert(pathlen >= MPDC_MINIMUM_PATH_LENGTH);

	if (state != NULL && fpath != NULL && pathlen >= MPDC_MINIMUM_PATH_LENGTH)
	{
		mpdc_server_certificate_directory(state, fpath, pathlen);
		qsc_stringutils_concat_strings(fpath, pathlen, state->issuer);
	}
}

bool mpdc_server_root_certificate_print(const char* fpath, size_t pathlen)
{
	assert(fpath != NULL);
	assert(pathlen >= MPDC_MINIMUM_PATH_LENGTH);

	bool res;

	res = false;

	if (fpath != NULL && pathlen >= MPDC_MINIMUM_PATH_LENGTH)
	{
		if (pathlen > 0 &&
			qsc_fileutils_exists(fpath) &&
			qsc_stringutils_string_contains(fpath, MPDC_CERTIFICATE_ROOT_EXTENSION) == true)
		{
			mpdc_root_certificate rcert = { 0 };

			if (mpdc_certificate_root_file_to_struct(fpath, &rcert) == true)
			{
				char enck[MPDC_ROOT_CERTIFICATE_STRING_SIZE] = { 0 };
				const size_t SLEN = mpdc_certificate_root_encode(enck, &rcert);

				if (SLEN <= MPDC_ROOT_CERTIFICATE_STRING_SIZE)
				{
					qsc_consoleutils_print_safe(enck);
					qsc_consoleutils_print_line("");
					res = true;
				}
			}
		}
	}

	return res;
}

void mpdc_server_root_certificate_store(mpdc_server_application_state* state, const mpdc_root_certificate* rcert)
{
	assert(state != NULL);
	assert(rcert != NULL);

	bool res;
	
	if (state != NULL && rcert != NULL)
	{
		char fpath[MPDC_STORAGE_PATH_MAX] = { 0 };
		size_t slen;

		mpdc_server_certificate_path(state, fpath, sizeof(fpath), rcert->issuer);
		res = mpdc_certificate_root_struct_to_file(fpath, rcert);

		if (res == true)
		{
			if (state->srvtype == mpdc_network_designation_dla)
			{
				res = false;

				while (res == false)
				{
					char cmsg[MPDC_STORAGE_PATH_MAX] = { 0 };

					/* get the root address and register in the topology */
					mpdc_menu_print_predefined_message(mpdc_application_rds_certificate_address_challenge, mpdc_console_mode_server, state->hostname);
					mpdc_menu_print_prompt(mpdc_console_mode_server, state->hostname);
					slen = qsc_consoleutils_get_line(cmsg, sizeof(cmsg)) - 1;

					if (slen >= QSC_IPINFO_IPV4_MINLEN)
					{
#if defined(MPDC_NETWORK_PROTOCOL_IPV6)
						if (qsc_ipinfo_ipv6_address_string_is_valid(cmsg) == true)
						{
#else
						if (qsc_ipinfo_ipv4_address_string_is_valid(cmsg) == true)
						{
#endif
							mpdc_topology_root_register(&state->tlist, rcert, cmsg);
							mpdc_server_topology_to_file(state);
							res = true;
						}
					}

					if (res == false)
					{
						mpdc_menu_print_predefined_message(mpdc_application_rds_certificate_address_failure, mpdc_console_mode_server, state->hostname);
					}
				}
			}
			else
			{
				char sadd[MPDC_CERTIFICATE_ADDRESS_SIZE] = "0.0.0.0";

				mpdc_topology_root_register(&state->tlist, rcert, sadd);
				mpdc_server_topology_to_file(state);
			}
		}
	}
}

void mpdc_server_set_command_prompt(mpdc_server_application_state* state)
{
	assert(state != NULL);

	if (state != NULL)
	{
		/* erase the prompt string */
		qsc_stringutils_clear_string(state->cmdprompt);
		/* copy the local host name */
		qsc_stringutils_copy_string(state->cmdprompt, sizeof(state->cmdprompt), state->hostname);

		/* copy the matching mode name to prompt string */
		switch (state->mode)
		{
			case mpdc_console_mode_config:
			{
				qsc_stringutils_concat_strings(state->cmdprompt, sizeof(state->cmdprompt), mpdc_menu_get_prompt(mpdc_console_mode_config));
				break;
			}
			case mpdc_console_mode_certificate:
			{
				qsc_stringutils_concat_strings(state->cmdprompt, sizeof(state->cmdprompt), mpdc_menu_get_prompt(mpdc_console_mode_certificate));
				break;
			}
			case mpdc_console_mode_server:
			{
				qsc_stringutils_concat_strings(state->cmdprompt, sizeof(state->cmdprompt), mpdc_menu_get_prompt(mpdc_console_mode_server));
				break;
			}
			case mpdc_console_mode_client_connected:
			{
				qsc_stringutils_concat_strings(state->cmdprompt, sizeof(state->cmdprompt), mpdc_menu_get_prompt(mpdc_console_mode_client_connected));
				break;
			}
			case mpdc_console_mode_enable:
			{
				qsc_stringutils_concat_strings(state->cmdprompt, sizeof(state->cmdprompt), mpdc_menu_get_prompt(mpdc_console_mode_enable));
				break;
			}
			case mpdc_console_mode_user:
			{
				qsc_stringutils_concat_strings(state->cmdprompt, sizeof(state->cmdprompt), mpdc_menu_get_prompt(mpdc_console_mode_user));
				break;
			}
			default:
			{
				qsc_stringutils_concat_strings(state->cmdprompt, sizeof(state->cmdprompt), mpdc_menu_get_prompt(mpdc_console_mode_user));
			}
		}
	}
}

bool mpdc_server_set_console_timeout(mpdc_server_application_state* state, const char* snum, size_t numlen)
{
	assert(state != NULL);
	assert(snum != NULL);
	assert(numlen != 0);

	bool res;

	res = false;

	if (state != NULL && snum != NULL && numlen != 0)
	{
		if (numlen > 0)
		{
			uint16_t val;

			if (qsc_stringutils_is_numeric(snum, numlen) == true)
			{
				val = (uint16_t)qsc_stringutils_string_to_int(snum);

				if (val >= (uint16_t)MPDC_STORAGE_TIMEOUT_MIN && val <= (uint16_t)MPDC_STORAGE_TIMEOUT_MAX)
				{
					state->timeout = val;
					res = mpdc_server_state_store(state);

					if (res == true)
					{
						mpdc_server_log_write_message(state, mpdc_application_log_timeout_change, snum, numlen);
					}
				}
			}
		}
	}

	return res;
}

bool mpdc_server_set_domain_name(mpdc_server_application_state* state, const char* name, size_t namelen)
{
	assert(state != NULL);
	assert(name != NULL);
	assert(namelen != 0);

	bool res;

	res = true;
	
	if (state != NULL && name != NULL && namelen != 0)
	{
		char fpath[MPDC_STORAGE_PATH_MAX] = { 0 };

		if (state->srvtype == mpdc_network_designation_rds)
		{
			mpdc_server_root_certificate_path(state, fpath, sizeof(fpath));
		}
		else
		{
			mpdc_server_child_certificate_path(state, fpath, sizeof(fpath));
		}

		if (qsc_fileutils_exists(fpath) == true)
		{
			qsc_fileutils_delete(fpath);
		}

		if (namelen >= MPDC_STORAGE_DOMAINNAME_MIN && namelen <= MPDC_STORAGE_DOMAINNAME_MAX)
		{
			qsc_stringutils_clear_string(state->domain);
			qsc_stringutils_copy_substring(state->domain, sizeof(state->domain), name, namelen);

			res = mpdc_server_state_store(state);

			if (res == true)
			{
				size_t slen;

				slen = qsc_stringutils_string_size(state->domain);

				if (state->srvtype == mpdc_network_designation_rds)
				{
					server_root_certificate_issuer(state);
				}
				else
				{
					server_child_certificate_issuer(state);
				}

				mpdc_server_log_write_message(state, mpdc_application_log_domain_change, state->domain, slen);
			}
		}
	}

	return res;
}

bool mpdc_server_set_host_name(mpdc_server_application_state* state, const char* name, size_t namelen)
{
	assert(state != NULL);
	assert(name != NULL);
	assert(namelen != 0);

	bool res;

	res = true;

	if (state != NULL && name != NULL && namelen != 0)
	{
		char fpath[MPDC_STORAGE_PATH_MAX] = { 0 };

		if (state->srvtype == mpdc_network_designation_rds)
		{
			mpdc_server_root_certificate_path(state, fpath, sizeof(fpath));
		}
		else
		{
			mpdc_server_child_certificate_path(state, fpath, sizeof(fpath));
		}

		if (qsc_fileutils_exists(fpath) == true)
		{
			qsc_fileutils_delete(fpath);
		}

		if (namelen >= MPDC_STORAGE_HOSTNAME_MIN && namelen <= MPDC_STORAGE_HOSTNAME_MAX)
		{
			qsc_stringutils_clear_string(state->hostname);
			qsc_stringutils_copy_substring(state->hostname, sizeof(state->hostname), name, namelen);

			res = mpdc_server_state_store(state);

			if (res == true)
			{
				size_t slen;

				if (state->srvtype == mpdc_network_designation_rds)
				{
					server_root_certificate_issuer(state);
				}
				else
				{
					server_child_certificate_issuer(state);
				}

				slen = qsc_stringutils_string_size(state->hostname);
				mpdc_server_log_write_message(state, mpdc_application_log_hostname_change, state->hostname, slen);
			}
		}
	}

	return res;
}

bool mpdc_server_set_ip_address(mpdc_server_application_state* state, const char* address, size_t addlen)
{
	assert(state != NULL);
	assert(address != NULL);
	assert(addlen != 0);

	bool res;

	res = false;

	if (state != NULL && address != NULL && addlen != 0)
	{
		if (addlen >= MPDC_STORAGE_ADDRESS_MIN && addlen <= MPDC_STORAGE_ADDRESS_MAX)
		{
#if defined(MPDC_NETWORK_PROTOCOL_IPV6)
			qsc_ipinfo_ipv6_address add = { 0 };
			add = qsc_ipinfo_ipv6_address_from_string(address);

			if (qsc_ipinfo_ipv6_address_is_valid(&add) == true && qsc_ipinfo_ipv6_address_is_zeroed(&add) == false)
#else
			qsc_ipinfo_ipv4_address add = { 0 };
			add = qsc_ipinfo_ipv4_address_from_string(address);

			if (qsc_ipinfo_ipv4_address_is_valid(&add) == true)
#endif
			{
				qsc_stringutils_clear_string(state->localip);
				qsc_stringutils_copy_substring(state->localip, sizeof(state->localip), address, addlen);
				res = mpdc_server_state_store(state);

				if (res == true)
				{
					mpdc_server_log_write_message(state, mpdc_application_log_address_change, address, addlen);
				}
			}
		}
	}

	return res;
}

bool mpdc_server_set_password_retries(mpdc_server_application_state* state, const char* snum, size_t numlen)
{
	assert(state != NULL);
	assert(snum != NULL);
	assert(numlen != 0);

	uint8_t val;
	bool res;

	res = false;

	if (state != NULL && snum != NULL && numlen != 0)
	{
		if (qsc_stringutils_is_numeric(snum, numlen) == true)
		{
			if (numlen != 0)
			{
				val = (uint8_t)qsc_stringutils_string_to_int(snum);

				if (val >= (uint8_t)MPDC_STORAGE_RETRIES_MIN && val <= (uint8_t)MPDC_STORAGE_RETRIES_MAX)
				{
					state->retries = val;
					res = mpdc_server_state_store(state);

					if (res == true)
					{
						mpdc_server_log_write_message(state, mpdc_application_log_retries_change, snum, numlen);
					}
				}
			}
		}
	}

	return res;
}

void mpdc_server_erase_signature_key(mpdc_server_application_state* state)
{
	assert(state != NULL);

	if (state != NULL && state->kchain != NULL)
	{
		qsc_memutils_clear(state->kchain + (SERVER_KEYCHAIN_DEPTH * SERVER_KEYCHAIN_WIDTH), MPDC_ASYMMETRIC_SIGNING_KEY_SIZE);
	}
}

void mpdc_server_state_backup_restore(const mpdc_server_application_state* state)
{
	if (state != NULL)
	{
		char bcdir[MPDC_STORAGE_PATH_MAX] = { 0 };
		char fpath[MPDC_STORAGE_PATH_MAX] = { 0 };
		char spath[MPDC_STORAGE_PATH_MAX] = { 0 };

		server_config_path(state, fpath, sizeof(fpath));
		server_backup_directory(state, bcdir, sizeof(bcdir));

		/* restore the configuration file */
		if (qsc_fileutils_exists(fpath) == true)
		{
			qsc_stringutils_copy_string(spath, sizeof(spath), bcdir);
			qsc_stringutils_concat_strings(spath, sizeof(spath), state->cfgname);

			if (qsc_fileutils_exists(spath) == true)
			{
				qsc_fileutils_file_copy(spath, fpath);
				qsc_stringutils_clear_string(fpath);
				qsc_stringutils_clear_string(spath);
			}
		}

		server_topology_path(state, fpath, sizeof(fpath));

		/* restore the topology file */
		if (qsc_fileutils_exists(fpath) == true)
		{
			qsc_stringutils_copy_string(spath, sizeof(spath), bcdir);
			qsc_stringutils_concat_strings(spath, sizeof(spath), state->topname);
			qsc_stringutils_concat_strings(spath, sizeof(spath), MPDC_CERTIFICATE_TOPOLOGY_EXTENSION);

			if (qsc_fileutils_exists(spath) == true)
			{
				qsc_fileutils_file_copy(spath, fpath);
				qsc_stringutils_clear_string(fpath);
				qsc_stringutils_clear_string(spath);
			}
		}

		server_logging_path(state, fpath, sizeof(fpath));

		/* restore the log file */
		if (qsc_fileutils_exists(fpath) == true)
		{
			qsc_stringutils_copy_string(spath, sizeof(spath), bcdir);
			qsc_stringutils_concat_strings(spath, sizeof(spath), MPDC_LOG_FILENAME);

			if (qsc_fileutils_exists(spath) == true)
			{
				qsc_fileutils_file_copy(spath, fpath);
			}
		}
	}
}

void mpdc_server_state_backup_save(const mpdc_server_application_state* state)
{
	if (state != NULL)
	{
		char bcdir[MPDC_STORAGE_PATH_MAX] = { 0 };
		char fpath[MPDC_STORAGE_PATH_MAX] = { 0 };
		char spath[MPDC_STORAGE_PATH_MAX] = { 0 };

		server_config_path(state, fpath, sizeof(fpath));
		server_backup_directory(state, bcdir, sizeof(bcdir));

		/* backup the configuration file */
		if (qsc_fileutils_exists(fpath) == true)
		{
			qsc_stringutils_copy_string(spath, sizeof(spath), bcdir);
			qsc_stringutils_concat_strings(spath, sizeof(spath), state->cfgname);
			qsc_fileutils_file_copy(fpath, spath);
			qsc_stringutils_clear_string(fpath);
			qsc_stringutils_clear_string(spath);
		}

		server_topology_path(state, fpath, sizeof(fpath));

		/* backup the topology file */
		if (qsc_fileutils_exists(fpath) == true)
		{
			qsc_stringutils_copy_string(spath, sizeof(spath), bcdir);
			qsc_stringutils_concat_strings(spath, sizeof(spath), state->topname);
			qsc_stringutils_concat_strings(spath, sizeof(spath), MPDC_CERTIFICATE_TOPOLOGY_EXTENSION);
			qsc_fileutils_file_copy(fpath, spath);
			qsc_stringutils_clear_string(fpath);
			qsc_stringutils_clear_string(spath);
		}

		server_logging_path(state, fpath, sizeof(fpath));

		/* backup the log file */
		if (qsc_fileutils_exists(fpath) == true)
		{
			qsc_stringutils_copy_string(spath, sizeof(spath), bcdir);
			qsc_stringutils_concat_strings(spath, sizeof(spath), MPDC_LOG_FILENAME);
			qsc_fileutils_file_copy(fpath, spath);
		}
	}
}

void mpdc_server_state_initialize(mpdc_server_application_state* state, mpdc_network_designations srvtype)
{
	assert(state != NULL);
	assert(srvtype != mpdc_network_designation_none);

	if (state != NULL && srvtype != mpdc_network_designation_none)
	{
		qsc_memutils_clear(state->cmdprompt, sizeof(state->cmdprompt));
		qsc_memutils_clear(state->domain, sizeof(state->domain));
		qsc_memutils_clear(state->hostname, sizeof(state->hostname));
		qsc_memutils_clear(state->localip, sizeof(state->localip));
		qsc_memutils_clear(state->logpath, sizeof(state->logpath));
		qsc_memutils_clear(state->issuer, sizeof(state->issuer));
		qsc_memutils_clear(&state->tlist, sizeof(state->tlist));
		qsc_memutils_clear(state->username, sizeof(state->username));

		if (srvtype == mpdc_network_designation_agent)
		{
			state->aplpath = AGENT_APPLICATION_PATH;
			state->banner = AGENT_APPLICATION_BANNER;
			state->cfgname = AGENT_FILENAME_CONFIG;
			state->srvname = AGENT_APPLICATION_NAME;
			state->prikeyname = AGENT_PRIKEY_NAME;
			state->promptdef = AGENT_PROMPT_DEFAULT;
			state->pubkeyname = AGENT_PUBKEY_NAME;
			state->topname = AGENT_TOPOLOGY_NAME;
			state->wtitle = AGENT_WINDOW_TITLE;
			state->port = MPDC_APPLICATION_AGENT_PORT;
		}
		else if (srvtype == mpdc_network_designation_client)
		{
			state->aplpath = CLIENT_APPLICATION_PATH;
			state->banner = CLIENT_APPLICATION_BANNER;
			state->cfgname = CLIENT_FILENAME_CONFIG;
			state->srvname = CLIENT_APPLICATION_NAME;
			state->prikeyname = CLIENT_PRIKEY_NAME;
			state->promptdef = CLIENT_PROMPT_DEFAULT;
			state->pubkeyname = CLIENT_PUBKEY_NAME;
			state->topname = CLIENT_TOPOLOGY_NAME;
			state->wtitle = CLIENT_WINDOW_TITLE;
			state->port = MPDC_APPLICATION_CLIENT_PORT;
		}
		else if (srvtype == mpdc_network_designation_dla)
		{
			state->aplpath = DLA_APPLICATION_PATH;
			state->banner = DLA_APPLICATION_BANNER;
			state->cfgname = DLA_FILENAME_CONFIG;
			state->srvname = DLA_APPLICATION_NAME;
			state->prikeyname = DLA_PRIKEY_NAME;
			state->promptdef = DLA_PROMPT_DEFAULT;
			state->pubkeyname = DLA_PUBKEY_NAME;
			state->topname = DLA_TOPOLOGY_NAME;
			state->wtitle = DLA_WINDOW_TITLE;
			state->port = MPDC_APPLICATION_DLA_PORT;
		}
		else if (srvtype == mpdc_network_designation_idg)
		{
			state->aplpath = IDG_APPLICATION_PATH;
			state->banner = IDG_APPLICATION_BANNER;
			state->cfgname = IDG_FILENAME_CONFIG;
			state->srvname = IDG_APPLICATION_NAME;
			state->prikeyname = IDG_PRIKEY_NAME;
			state->promptdef = IDG_PROMPT_DEFAULT;
			state->pubkeyname = IDG_PUBKEY_NAME;
			state->topname = IDG_TOPOLOGY_NAME;
			state->wtitle = IDG_WINDOW_TITLE;
			state->port = MPDC_APPLICATION_IDG_PORT;
		}
		else if (srvtype == mpdc_network_designation_rds)
		{
			state->aplpath = RDS_APPLICATION_PATH;
			state->banner = RDS_APPLICATION_BANNER;
			state->cfgname = RDS_FILENAME_CONFIG;
			state->srvname = RDS_APPLICATION_NAME;
			state->prikeyname = RDS_PRIKEY_NAME;
			state->promptdef = RDS_PROMPT_DEFAULT;
			state->pubkeyname = RDS_PUBKEY_NAME;
			state->topname = RDS_TOPOLOGY_NAME;
			state->wtitle = RDS_WINDOW_TITLE;
			state->port = MPDC_APPLICATION_RDS_PORT;
		}
		else if (srvtype == mpdc_network_designation_mas)
		{
			state->aplpath = MAS_APPLICATION_PATH;
			state->banner = MAS_APPLICATION_BANNER;
			state->cfgname = MAS_FILENAME_CONFIG;
			state->srvname = MAS_APPLICATION_NAME;
			state->prikeyname = MAS_PRIKEY_NAME;
			state->promptdef = MAS_PROMPT_DEFAULT;
			state->pubkeyname = MAS_PUBKEY_NAME;
			state->topname = MAS_TOPOLOGY_NAME;
			state->wtitle = MAS_WINDOW_TITLE;
			state->port = MPDC_APPLICATION_MAS_PORT;
		}

		server_logging_path(state, state->logpath, sizeof(state->logpath));
		qsc_stringutils_copy_string(state->cmdprompt, sizeof(state->cmdprompt), state->promptdef);
		qsc_stringutils_copy_string(state->hostname, sizeof(state->hostname), state->srvname);

		/* default server ip address */
#if defined(MPDC_NETWORK_PROTOCOL_IPV6)
		qsc_ipinfo_ipv6_address ipv6 = { 0 };

		ipv6 = qsc_netutils_get_ipv6_address();
		qsc_ipinfo_ipv6_address_to_string(state->localip, &ipv6);
#else
		qsc_ipinfo_ipv4_address ipv4 = { 0 };

		qsc_netutils_get_ipv4_address(&ipv4);
		qsc_ipinfo_ipv4_address_to_string(state->localip, &ipv4);
#endif

		qsc_netutils_get_domain_name(state->domain);
		state->srvtype = srvtype;
		state->timeout = MPDC_DEFAULT_SESSION_TIMEOUT;
		state->retries = MPDC_DEFAULT_AUTH_RETRIES;
		state->action = mpdc_command_action_none;
		state->mode = mpdc_console_mode_user;
		state->joined = false;
		state->loghost = true;
	}
}

bool mpdc_server_state_store(mpdc_server_application_state* state)
{
	assert(state != NULL);

	bool res;

	res = false;

	if (state != NULL)
	{
		char fpath[MPDC_STORAGE_PATH_MAX] = { 0 };
		uint8_t encs[MPDC_SERVER_APPLICATION_STATE_SIZE + MPDC_STORAGE_MAC_SIZE] = { 0 };
		uint8_t tmps[MPDC_SERVER_APPLICATION_STATE_SIZE] = { 0 };

		server_config_path(state, fpath, sizeof(fpath));
		server_state_serialize(state, tmps);
		const uint8_t* pkey = state->kchain + (SERVER_KEYCHAIN_STATE_INDEX * SERVER_KEYCHAIN_WIDTH);

		assert(qsc_memutils_zeroed(pkey, MPDC_CRYPTO_SYMMETRIC_KEY_SIZE) == false);

		res = qsc_memutils_zeroed(pkey, SERVER_KEYCHAIN_WIDTH);

		if (res == false)
		{
			mpdc_crypto_encrypt_stream(encs, pkey, tmps, sizeof(tmps));
			res = qsc_fileutils_copy_stream_to_file(fpath, (const char*)encs, sizeof(encs));
		}
	}

	return res;
}

void mpdc_server_state_unload(mpdc_server_application_state* state)
{
	assert(state != NULL);

	if (state != NULL)
	{
		server_unload_signature_key(state);
		mpdc_topology_list_dispose(&state->tlist);
		mpdc_server_state_initialize(state, state->srvtype);
	}
}

bool mpdc_server_topology_dla_fetch(const mpdc_server_application_state* state, mpdc_child_certificate* dcert)
{
	assert(state != NULL);
	assert(dcert != NULL);

	bool res;

	res = false;

	if (state != NULL && dcert != NULL)
	{
		mpdc_topology_node_state node = { 0 };

		if (mpdc_topology_node_find_dla(&state->tlist, &node) == true)
		{
			char fpath[MPDC_STORAGE_PATH_MAX] = { 0 };

			mpdc_server_certificate_directory(state, fpath, sizeof(fpath));
			qsc_stringutils_concat_strings(fpath, sizeof(fpath), node.issuer);

			if (qsc_fileutils_exists(fpath))
			{
				res = mpdc_certificate_child_file_to_struct(fpath, dcert);
			}
		}
	}

	return res;
}

bool mpdc_server_topology_load(mpdc_server_application_state* state)
{
	assert(state != NULL);

	bool res;

	res = false;

	if (state != NULL)
	{
		char fpath[MPDC_STORAGE_PATH_MAX] = { 0 };

		server_topology_path(state, fpath, sizeof(fpath));

		if (qsc_fileutils_exists(fpath) == true)
		{
			size_t flen;

			flen = qsc_fileutils_get_size(fpath);

			if (flen > 0)
			{
				uint8_t* pdec;
				uint8_t* penc;

				pdec = (uint8_t*)qsc_memutils_malloc(flen - MPDC_STORAGE_MAC_SIZE);
				penc = (uint8_t*)qsc_memutils_malloc(flen);

				if (penc != NULL && pdec != NULL)
				{
					size_t mlen;

					mlen = qsc_fileutils_copy_file_to_stream(fpath, (char*)penc, flen);

					if (mlen > 0)
					{
						const uint8_t* pkey = state->kchain + (SERVER_KEYCHAIN_TOPOLOGY_INDEX * SERVER_KEYCHAIN_WIDTH);

						assert(qsc_memutils_zeroed(pkey, MPDC_CRYPTO_SYMMETRIC_KEY_SIZE) == false);

						res = mpdc_crypto_decrypt_stream(pdec, pkey, penc, mlen - MPDC_STORAGE_MAC_SIZE);

						if (res == true)
						{
							mpdc_topology_list_deserialize(&state->tlist, pdec, flen - MPDC_STORAGE_MAC_SIZE);
						}
					}
				}

				if (pdec != NULL)
				{
					qsc_memutils_alloc_free(pdec);
				}

				if (penc != NULL)
				{
					qsc_memutils_alloc_free(penc);
				}
			}
		}
	}

	return res;
}

bool mpdc_server_topology_local_fetch(const mpdc_server_application_state* state, mpdc_child_certificate* ccert)
{
	assert(state != NULL);
	assert(ccert != NULL);

	bool res;

	res = false;

	if (state != NULL && ccert != NULL)
	{
		mpdc_topology_node_state node = { 0 };

		if (mpdc_topology_node_find_issuer(&state->tlist, &node, state->issuer) == true)
		{
			char fpath[MPDC_STORAGE_PATH_MAX] = { 0 };

			mpdc_server_certificate_directory(state, fpath, sizeof(fpath));
			qsc_stringutils_concat_strings(fpath, sizeof(fpath), node.issuer);

			if (qsc_fileutils_exists(fpath))
			{
				res = mpdc_certificate_child_file_to_struct(fpath, ccert);
			}
		}
	}

	return res;
}

void mpdc_server_topology_print_list(mpdc_server_application_state* state)
{
	assert(state != NULL);

	char* lstr;
	size_t rlen;
	size_t slen;

	if (state != NULL)
	{
		slen = (state->tlist.count * MPDC_TOPOLOGY_NODE_ENCODED_SIZE);

		if (slen > 0)
		{
			lstr = qsc_memutils_malloc(slen);

			if (lstr != NULL)
			{
				qsc_memutils_clear(lstr, slen);
				rlen = mpdc_topology_list_to_string(&state->tlist, lstr, slen);

				if (rlen != 0)
				{
					qsc_consoleutils_print_safe(lstr);
				}

				qsc_memutils_alloc_free(lstr);
			}
		}
	}
}

void mpdc_server_topology_purge_externals(mpdc_server_application_state* state)
{
	mpdc_topology_list_state tcopy = { 0 };

	mpdc_topology_list_clone(&state->tlist, &tcopy);

	for (size_t i = 0; i < tcopy.count; ++i)
	{
		mpdc_topology_node_state node = { 0 };

		if (mpdc_topology_list_item(&tcopy, &node, i) == true)
		{
			if (qsc_memutils_are_equal((const uint8_t*)node.issuer, (const uint8_t*)state->issuer, MPDC_CERTIFICATE_ISSUER_SIZE) == false)
			{
				if (node.designation != mpdc_network_designation_rds)
				{
					mpdc_topology_node_remove(&state->tlist, node.serial);
				}
			}
		}
	}

	mpdc_topology_list_dispose(&tcopy);
}

void mpdc_server_topology_remove_certificate(mpdc_server_application_state* state, const char* issuer)
{
	assert(state != NULL);
	assert(issuer != NULL);

	if (state != NULL && issuer != NULL)
	{
		mpdc_topology_node_state rnode = { 0 };

		if (mpdc_topology_node_find_issuer(&state->tlist, &rnode, issuer) == true)
		{
			char fpath[MPDC_STORAGE_PATH_MAX] = { 0 };

			mpdc_server_child_certificate_path_from_issuer(state, fpath, sizeof(fpath), rnode.issuer);

			/* delete the certificate */
			if (qsc_fileutils_exists(fpath) == true)
			{
				qsc_fileutils_delete(fpath);
			}
		}
	}
}

void mpdc_server_topology_remove_node(mpdc_server_application_state* state, const char* issuer)
{
	assert(state != NULL);
	assert(issuer != NULL);

	if (state != NULL && issuer != NULL)
	{
		mpdc_topology_node_state rnode = { 0 };

		if (mpdc_topology_node_find_issuer(&state->tlist, &rnode, issuer) == true)
		{
			/* delete the node from the database */
			mpdc_topology_node_remove(&state->tlist, rnode.serial);
		}
	}
}

void mpdc_server_topology_reset(mpdc_server_application_state* state)
{
	assert(state != NULL);

	if (state != NULL)
	{
		char fpath[MPDC_STORAGE_PATH_MAX] = { 0 };

		mpdc_topology_list_dispose(&state->tlist);
		server_topology_path(state, fpath, sizeof(fpath));

		if (qsc_fileutils_exists(fpath) == true)
		{
			qsc_fileutils_delete(fpath);
		}
	}
}

bool mpdc_server_topology_root_exists(const mpdc_server_application_state* state)
{
	assert(state != NULL);

	bool res;

	res = false;

	if (state != NULL)
	{
		mpdc_topology_node_state node = { 0 };

		res = mpdc_topology_node_find_root(&state->tlist, &node);
	}

	return res;
}

bool mpdc_server_topology_root_fetch(const mpdc_server_application_state* state, mpdc_root_certificate* rcert)
{
	assert(state != NULL);
	assert(rcert != NULL);

	bool res;

	res = false;

	if (state != NULL && rcert != NULL)
	{
		mpdc_topology_node_state node = { 0 };

		if (mpdc_topology_node_find_root(&state->tlist, &node) == true)
		{
			char fpath[MPDC_STORAGE_PATH_MAX] = { 0 };

			mpdc_server_certificate_directory(state, fpath, sizeof(fpath));
			qsc_stringutils_concat_strings(fpath, sizeof(fpath), node.issuer);

			if (qsc_fileutils_exists(fpath))
			{
				res = mpdc_certificate_root_file_to_struct(fpath, rcert);
			}
		}
	}

	return res;
}

void mpdc_server_topology_to_file(mpdc_server_application_state* state)
{
	assert(state != NULL);

	size_t tlen;
	qsc_mutex mtx;

	if (state != NULL)
	{
		mtx = qsc_async_mutex_lock_ex();

		tlen = mpdc_topology_list_size(&state->tlist);

		if (tlen > 0)
		{
			uint8_t* ptxt;
			uint8_t* penc;

			ptxt = (uint8_t*)qsc_memutils_malloc(tlen);
			penc = (uint8_t*)qsc_memutils_malloc(tlen + MPDC_STORAGE_MAC_SIZE);

			if (penc != NULL && ptxt != NULL)
			{
				char fpath[MPDC_STORAGE_PATH_MAX] = { 0 };
				const uint8_t* pkey = state->kchain + (SERVER_KEYCHAIN_TOPOLOGY_INDEX * SERVER_KEYCHAIN_WIDTH);

				assert(qsc_memutils_zeroed(pkey, MPDC_CRYPTO_SYMMETRIC_KEY_SIZE) == false);

				server_topology_path(state, fpath, sizeof(fpath));

				if (qsc_fileutils_exists(fpath) == true)
				{
					qsc_fileutils_delete(fpath);
				}

				qsc_memutils_clear(ptxt, tlen);
				qsc_memutils_clear(penc, tlen + MPDC_STORAGE_MAC_SIZE);
				mpdc_topology_list_serialize(ptxt, &state->tlist);
				mpdc_crypto_encrypt_stream(penc, pkey, ptxt, tlen);
				qsc_fileutils_copy_stream_to_file(fpath, (const char*)penc, tlen + MPDC_STORAGE_MAC_SIZE);

				qsc_memutils_alloc_free(penc);
				qsc_memutils_alloc_free(ptxt);
			}
		}

		qsc_async_mutex_unlock_ex(mtx);
	}
}

bool mpdc_server_user_login(mpdc_server_application_state* state)
{
	assert(state != NULL);

	size_t plen;
	size_t slen;
	bool res;

	res = false;

	if (state != NULL)
	{
		char cmsg[MPDC_STORAGE_PASSWORD_MAX] = { 0 };
		char fpath[MPDC_STORAGE_PATH_MAX] = { 0 };

		server_config_path(state, fpath, sizeof(fpath));
		res = qsc_fileutils_exists(fpath);
		server_load_key_chain(state);

		/* first run */

		if (res == false)
		{
			/* print the intro message */
			mpdc_menu_print_predefined_message(mpdc_application_first_login, mpdc_console_mode_login_message, state->hostname);

			/* get the user name and store in state */

			while (true)
			{
				mpdc_menu_print_predefined_message(mpdc_application_choose_name, mpdc_console_mode_login_message, state->hostname);
				mpdc_menu_print_prompt(mpdc_console_mode_login_user, state->hostname);
				slen = qsc_consoleutils_get_line(cmsg, sizeof(cmsg)) - 1;

				if (slen >= MPDC_STORAGE_USERNAME_MIN && slen <= MPDC_STORAGE_USERNAME_MAX)
				{
					qsc_stringutils_copy_substring(state->username, MPDC_STORAGE_USERNAME_MAX, cmsg, slen);
					break;
				}
			}

			/* get the password and generate the keychain */

			while (true)
			{
				mpdc_menu_print_predefined_message(mpdc_application_choose_password, mpdc_console_mode_login_message, state->hostname);
				mpdc_menu_print_prompt(mpdc_console_mode_login_password, state->hostname);
				qsc_stringutils_clear_string(cmsg);
				plen = qsc_consoleutils_masked_password(cmsg, sizeof(cmsg));

				if (mpdc_crypto_password_minimum_check(cmsg, plen) == true)
				{
					break;
				}
			}

			server_initialize_key_chain(state, cmsg, plen, state->username, slen);
			mpdc_menu_print_predefined_message(mpdc_application_password_set, mpdc_console_mode_login_message, state->hostname);

			if (mpdc_logger_exists(state->logpath) == false)
			{
				mpdc_server_log_host(state);
			}

			/* get the device name and store in state */

			while (true)
			{
				mpdc_menu_print_predefined_message(mpdc_application_challenge_device_name, mpdc_console_mode_login_message, state->hostname);
				mpdc_menu_print_prompt(mpdc_console_mode_login_hostname, state->hostname);
				slen = qsc_consoleutils_get_line(cmsg, sizeof(cmsg)) - 1;

				if (slen >= MPDC_STORAGE_DEVICENAME_MIN && slen <= MPDC_STORAGE_DEVICENAME_MAX)
				{
					qsc_stringutils_clear_substring(state->hostname, MPDC_STORAGE_USERNAME_MAX);
					qsc_stringutils_copy_substring(state->hostname, MPDC_STORAGE_USERNAME_MAX, cmsg, slen);
					break;
				}
			}

#if defined(MPDC_SERVER_IP_CHANGE_DIALOG)
			/* conditionally change the servers local ip address */

			mpdc_menu_print_predefined_text(mpdc_application_address_change_current, mpdc_console_mode_login_message, state->hostname);
			mpdc_menu_print_text_line(state->localip);
			res = mpdc_menu_print_predefined_message_confirm(mpdc_application_address_change_challenge, mpdc_console_mode_login_message, state->hostname);

			if (res == true)
			{
				while (true)
				{
					mpdc_menu_print_predefined_message(mpdc_application_address_change_message, mpdc_console_mode_login_message, state->hostname);
					mpdc_menu_print_prompt(mpdc_console_mode_login_address, state->hostname);
					slen = qsc_consoleutils_get_line(cmsg, sizeof(cmsg)) - 1;

					if (slen >= MPDC_STORAGE_ADDRESS_MIN && slen <= MPDC_STORAGE_ADDRESS_MAX)
					{
						res = mpdc_server_set_ip_address(state, cmsg, slen);

						if (res == true)
						{
							mpdc_menu_print_predefined_message(mpdc_application_address_change_success, mpdc_console_mode_login_message, state->hostname);
							break;
						}
						else
						{
							mpdc_menu_print_predefined_message(mpdc_application_address_change_failure, mpdc_console_mode_login_message, state->hostname);
						}
					}
				}
			}
#endif

			/* conditionally change the servers domain name */

			mpdc_menu_print_predefined_text(mpdc_application_server_domain_change_current, mpdc_console_mode_login_message, state->hostname);
			mpdc_menu_print_text_line(state->domain);
			res = mpdc_menu_print_predefined_message_confirm(mpdc_application_server_domain_change_challenge, mpdc_console_mode_login_message, state->hostname);

			if (res == true)
			{
				while (true)
				{
					mpdc_menu_print_prompt(mpdc_console_mode_login_domain, state->hostname);
					slen = qsc_consoleutils_get_line(cmsg, sizeof(cmsg)) - 1;

					if (slen >= MPDC_STORAGE_DOMAINNAME_MIN && slen <= MPDC_STORAGE_DOMAINNAME_MAX)
					{
						res = mpdc_server_set_domain_name(state, cmsg, slen);

						if (res == true)
						{
							mpdc_menu_print_predefined_message(mpdc_application_server_domain_change_success, mpdc_console_mode_login_message, state->hostname);
							break;
						}
						else
						{
							mpdc_menu_print_predefined_message(mpdc_application_server_domain_change_failure, mpdc_console_mode_login_message, state->hostname);
						}
					}
				}
			}
			else
			{
				/* set the default issuer */
				if (state->srvtype == mpdc_network_designation_rds)
				{
					server_root_certificate_issuer(state);
				}
				else
				{
					server_child_certificate_issuer(state);
				}
			}

			if (state->srvtype != mpdc_network_designation_rds)
			{
				while (true)
				{
					mpdc_menu_print_predefined_message(mpdc_application_challenge_root_path, mpdc_console_mode_login_message, state->hostname);
					mpdc_menu_print_prompt(mpdc_console_mode_login_rootpath, state->hostname);
					slen = qsc_consoleutils_get_line(cmsg, sizeof(cmsg)) - 1;

					if (slen >= MPDC_STORAGE_FILEPATH_MIN &&
						slen <= MPDC_STORAGE_FILEPATH_MAX &&
						qsc_fileutils_exists(cmsg) == true &&
						qsc_stringutils_string_contains(cmsg, MPDC_CERTIFICATE_ROOT_EXTENSION))
					{
						if (mpdc_certificate_root_file_to_struct(cmsg, &state->root) == true)
						{
							mpdc_server_root_certificate_store(state, &state->root);
							mpdc_menu_print_predefined_message(mpdc_application_challenge_root_path_success, mpdc_console_mode_login_message, state->hostname);

							break;
						}
						else
						{
							mpdc_menu_print_predefined_message(mpdc_application_challenge_root_path_failure, mpdc_console_mode_login_message, state->hostname);
						}
					}
					else
					{
						mpdc_menu_print_predefined_message(mpdc_application_challenge_root_path_failure, mpdc_console_mode_login_message, state->hostname);
					}
				}
			}

			/* store the state to file */
			res = mpdc_server_state_store(state);

			if (state->loghost == true)
			{
				slen = qsc_stringutils_string_size(state->username);
				mpdc_server_log_write_message(state, mpdc_application_log_user_added, state->username, slen);
			}
		}
		else
		{
			/* password was set */
			size_t rctr;

			res = false;
			slen = 0;
			rctr = 0;

			while (true)
			{
				if (rctr >= state->retries)
				{
					break;
				}

				++rctr;
				mpdc_menu_print_predefined_message(mpdc_application_challenge_user, mpdc_console_mode_login_message, state->hostname);
				mpdc_menu_print_prompt(mpdc_console_mode_login_user, state->hostname);
				slen = qsc_consoleutils_get_line(cmsg, sizeof(cmsg)) - 1;

				if (slen >= MPDC_STORAGE_USERNAME_MIN && slen <= MPDC_STORAGE_USERNAME_MAX)
				{
					qsc_memutils_copy(state->username, cmsg, slen);
					res = true;
					break;
				}
				else
				{
					qsc_memutils_clear(cmsg, sizeof(cmsg));
					mpdc_menu_print_predefined_message(mpdc_application_challenge_user_failure, mpdc_console_mode_login_user, state->hostname);
				}
			}

			if (res == true)
			{
				rctr = 0;

				while (true)
				{
					qsc_stringutils_clear_string(cmsg);

					if (rctr >= state->retries)
					{
						res = false;
						break;
					}

					++rctr;
					mpdc_menu_print_predefined_message(mpdc_application_challenge_password, mpdc_console_mode_login_message, state->hostname);
					mpdc_menu_print_prompt(mpdc_console_mode_login_password, state->hostname);
					plen = qsc_consoleutils_masked_password(cmsg, sizeof(cmsg));

					if (plen >= MPDC_STORAGE_PASSWORD_MIN && plen <= MPDC_STORAGE_PASSWORD_MAX)
					{
						/* load the key chain */
						server_initialize_key_chain(state, cmsg, plen, state->username, slen);
						/* decrypt the state file and load into memory */
						res = server_state_load(state);

						if (res == true)
						{
							if (state->loghost == true)
							{
								slen = qsc_stringutils_string_size(state->username);
								mpdc_server_log_write_message(state, mpdc_application_log_user_logged_in, state->username, slen);
							}

							break;
						}
						else
						{
							qsc_memutils_clear(state->kchain, SERVER_KEYCHAIN_DEPTH * SERVER_KEYCHAIN_WIDTH);
							mpdc_menu_print_predefined_message(mpdc_application_challenge_password_failure, mpdc_console_mode_login_message, state->hostname);
						}
					}
					else
					{
						mpdc_menu_print_predefined_message(mpdc_application_challenge_password_failure, mpdc_console_mode_login_message, state->hostname);
					}
				}
			}
		}
	}

	return res;
}

void mpdc_server_user_logout(mpdc_server_application_state* state)
{
	assert(state != NULL);

	if (state != NULL)
	{
		server_unload_key_chain(state);
		qsc_memutils_clear(state->username, MPDC_STORAGE_USERNAME_MAX);
		state->mode = mpdc_console_mode_user;
	}
}
