#include "network.h"
#include "mpdc.h"
#include "certificate.h"
#include "topology.h"
#include "acp.h"
#include "intutils.h"
#include "ipinfo.h"
#include "memutils.h"
#include "netutils.h"
#include "socketclient.h"
#include "timestamp.h"

#define NETWORK_NODE_COMPRESSED_SIZE (MPDC_CERTIFICATE_ISSUER_SIZE + MPDC_CERTIFICATE_SERIAL_SIZE + MPDC_CERTIFICATE_HASH_SIZE)
#define NETWORK_CERTIFICATE_UPDATE_SIZE (MPDC_PACKET_SUBHEADER_SIZE + MPDC_CERTIFICATE_CHILD_SIZE)

#define NETWORK_ANNOUNCE_REQUEST_SEQUENCE 0xFFFFFF00UL
#define NETWORK_ANNOUNCE_REQUEST_MESSAGE_SIZE (MPDC_PACKET_SUBHEADER_SIZE + MPDC_NETWORK_TOPOLOGY_NODE_SIZE + MPDC_CERTIFICATE_SIGNED_HASH_SIZE)
#define NETWORK_ANNOUNCE_REQUEST_PACKET_SIZE (MPDC_PACKET_HEADER_SIZE + NETWORK_ANNOUNCE_REQUEST_MESSAGE_SIZE)

#define NETWORK_CONVERGE_REQUEST_SEQUENCE 0xFFFFFF01UL
#define NETWORK_CONVERGE_REQUEST_MESSAGE_SIZE (MPDC_PACKET_SUBHEADER_SIZE + MPDC_NETWORK_TOPOLOGY_NODE_SIZE + MPDC_CERTIFICATE_SIGNED_HASH_SIZE)
#define NETWORK_CONVERGE_REQUEST_PACKET_SIZE (MPDC_PACKET_HEADER_SIZE + NETWORK_CONVERGE_REQUEST_MESSAGE_SIZE)
#define NETWORK_CONVERGE_RESPONSE_SEQUENCE 0xFFFFFF02UL
#define NETWORK_CONVERGE_RESPONSE_MESSAGE_SIZE (MPDC_PACKET_SUBHEADER_SIZE + MPDC_NETWORK_TOPOLOGY_NODE_SIZE + MPDC_CERTIFICATE_SIGNED_HASH_SIZE)
#define NETWORK_CONVERGE_RESPONSE_PACKET_SIZE (MPDC_PACKET_HEADER_SIZE + NETWORK_CONVERGE_RESPONSE_MESSAGE_SIZE)
#define NETWORK_CONVERGE_UPDATE_MESSAGE_SIZE (MPDC_PACKET_SUBHEADER_SIZE + MPDC_NETWORK_TOPOLOGY_NODE_SIZE + MPDC_CERTIFICATE_SIGNED_HASH_SIZE)
#define NETWORK_CONVERGE_UPDATE_PACKET_SIZE (MPDC_PACKET_HEADER_SIZE + NETWORK_CONVERGE_UPDATE_MESSAGE_SIZE)

#define NETWORK_ERROR_MESSAGE_SIZE 1U
#define NETWORK_ERROR_PACKET_SIZE (MPDC_PACKET_HEADER_SIZE + NETWORK_ERROR_MESSAGE_SIZE)

#define NETWORK_FRAGMENT_FKEY_REQUEST_SEQUENCE 0xFFFFFF03UL
#define NETWORK_FRAGMENT_FKEY_REQUEST_MESSAGE_SIZE (MPDC_CERTIFICATE_SERIAL_SIZE + MPDC_CRYPTO_SYMMETRIC_TOKEN_SIZE)
#define NETWORK_FRAGMENT_FKEY_REQUEST_PACKET_SIZE (MPDC_PACKET_HEADER_SIZE + NETWORK_FRAGMENT_FKEY_REQUEST_MESSAGE_SIZE)
#define NETWORK_FRAGMENT_FKEY_RESPONSE_SEQUENCE 0xFFFFFF04UL
#define NETWORK_FRAGMENT_FKEY_RESPONSE_MESSAGE_SIZE (MPDC_CRYPTO_SYMMETRIC_KEY_SIZE + MPDC_CRYPTO_SYMMETRIC_HASH_SIZE)
#define NETWORK_FRAGMENT_FKEY_RESPONSE_PACKET_SIZE (MPDC_PACKET_HEADER_SIZE + NETWORK_FRAGMENT_FKEY_RESPONSE_MESSAGE_SIZE)

#define NETWORK_FRAGMENT_COLLECTION_REQUEST_SEQUENCE 0xFFFFFF05UL
#define NETWORK_FRAGMENT_COLLECTION_REQUEST_SIZE (MPDC_CERTIFICATE_SERIAL_SIZE + MPDC_CRYPTO_SYMMETRIC_TOKEN_SIZE)
#define NETWORK_FRAGMENT_COLLECTION_REQUEST_MESSAGE_SIZE (NETWORK_FRAGMENT_COLLECTION_REQUEST_SIZE + MPDC_CRYPTO_SYMMETRIC_HASH_SIZE)
#define NETWORK_FRAGMENT_COLLECTION_REQUEST_PACKET_SIZE (MPDC_PACKET_HEADER_SIZE + NETWORK_FRAGMENT_COLLECTION_REQUEST_MESSAGE_SIZE)
#define NETWORK_FRAGMENT_QUERY_REQUEST_SEQUENCE 0xFFFFFF06UL
#define NETWORK_FRAGMENT_QUERY_REQUEST_SIZE (MPDC_CERTIFICATE_SERIAL_SIZE + MPDC_CRYPTO_SYMMETRIC_TOKEN_SIZE)
#define NETWORK_FRAGMENT_QUERY_REQUEST_MESSAGE_SIZE (MPDC_CERTIFICATE_SERIAL_SIZE + MPDC_CRYPTO_SYMMETRIC_TOKEN_SIZE + MPDC_CERTIFICATE_SERIAL_SIZE + MPDC_CRYPTO_SYMMETRIC_TOKEN_SIZE + MPDC_CRYPTO_SYMMETRIC_HASH_SIZE)
#define NETWORK_FRAGMENT_QUERY_REQUEST_PACKET_SIZE (MPDC_PACKET_HEADER_SIZE + NETWORK_FRAGMENT_QUERY_REQUEST_MESSAGE_SIZE)

#define NETWORK_FRAGMENT_QUERY_RESPONSE_SIZE (MPDC_CERTIFICATE_SERIAL_SIZE + MPDC_CRYPTO_SYMMETRIC_KEY_SIZE)
#define NETWORK_FRAGMENT_QUERY_RESPONSE_SEQUENCE 0xFFFFFF07UL
#define NETWORK_FRAGMENT_QUERY_RESPONSE_MESSAGE_SIZE (MPDC_CERTIFICATE_SERIAL_SIZE + MPDC_CRYPTO_SYMMETRIC_KEY_SIZE + MPDC_CERTIFICATE_SERIAL_SIZE + MPDC_CRYPTO_SYMMETRIC_KEY_SIZE + MPDC_CRYPTO_SYMMETRIC_HASH_SIZE)
#define NETWORK_FRAGMENT_QUERY_RESPONSE_PACKET_SIZE (MPDC_PACKET_HEADER_SIZE + NETWORK_FRAGMENT_QUERY_RESPONSE_MESSAGE_SIZE)
#define NETWORK_FRAGMENT_COLLECTION_RESPONSE_SEQUENCE 0xFFFFFF08UL
#define NETWORK_FRAGMENT_COLLECTION_RESPONSE_MESSAGE_SIZE (MPDC_CRYPTO_SYMMETRIC_KEY_SIZE + MPDC_CRYPTO_SYMMETRIC_HASH_SIZE)
#define NETWORK_FRAGMENT_COLLECTION_RESPONSE_PACKET_SIZE (MPDC_PACKET_HEADER_SIZE + NETWORK_FRAGMENT_COLLECTION_RESPONSE_MESSAGE_SIZE)

#define NETWORK_INCREMENTAL_UPDATE_REQUEST_SEQUENCE 0xFFFFFF09UL
#define NETWORK_INCREMENTAL_UPDATE_REQUEST_MESSAGE_SIZE (MPDC_CERTIFICATE_SERIAL_SIZE)
#define NETWORK_INCREMENTAL_UPDATE_REQUEST_PACKET_SIZE (MPDC_PACKET_HEADER_SIZE + NETWORK_INCREMENTAL_UPDATE_REQUEST_MESSAGE_SIZE)
#define NETWORK_INCREMENTAL_UPDATE_RESPONSE_SEQUENCE 0xFFFFFF0AUL
#define NETWORK_INCREMENTAL_UPDATE_RESPONSE_MESSAGE_SIZE (MPDC_PACKET_SUBHEADER_SIZE + MPDC_CERTIFICATE_CHILD_SIZE + MPDC_CERTIFICATE_SIGNED_HASH_SIZE)
#define NETWORK_INCREMENTAL_UPDATE_RESPONSE_PACKET_SIZE (MPDC_PACKET_HEADER_SIZE + NETWORK_INCREMENTAL_UPDATE_RESPONSE_MESSAGE_SIZE)

#define NETWORK_JOIN_REQUEST_SEQUENCE 0xFFFFFF0BUL
#define NETWORK_JOIN_REQUEST_MESSAGE_SIZE (MPDC_PACKET_SUBHEADER_SIZE + MPDC_CERTIFICATE_CHILD_SIZE + MPDC_CERTIFICATE_SIGNED_HASH_SIZE)
#define NETWORK_JOIN_REQUEST_PACKET_SIZE (MPDC_PACKET_HEADER_SIZE + NETWORK_JOIN_REQUEST_MESSAGE_SIZE)
#define NETWORK_JOIN_RESPONSE_SEQUENCE 0xFFFFFF0CUL
#define NETWORK_JOIN_RESPONSE_MESSAGE_SIZE (MPDC_PACKET_SUBHEADER_SIZE + MPDC_CERTIFICATE_CHILD_SIZE + MPDC_CERTIFICATE_SIGNED_HASH_SIZE)
#define NETWORK_JOIN_RESPONSE_PACKET_SIZE (MPDC_PACKET_HEADER_SIZE + NETWORK_JOIN_RESPONSE_MESSAGE_SIZE)

#define NETWORK_JOIN_UPDATE_REQUEST_SEQUENCE 0xFFFFFF0DUL
#define NETWORK_JOIN_UPDATE_REQUEST_MESSAGE_SIZE (MPDC_PACKET_SUBHEADER_SIZE + MPDC_CERTIFICATE_CHILD_SIZE + MPDC_CERTIFICATE_SIGNED_HASH_SIZE)
#define NETWORK_JOIN_UPDATE_REQUEST_PACKET_SIZE (MPDC_PACKET_HEADER_SIZE + NETWORK_JOIN_REQUEST_MESSAGE_SIZE)
#define NETWORK_JOIN_UPDATE_RESPONSE_SEQUENCE 0xFFFFFF0EUL
#define NETWORK_JOIN_UPDATE_RESPONSE_MESSAGE_SIZE (MPDC_PACKET_SUBHEADER_SIZE + MPDC_CERTIFICATE_CHILD_SIZE + MPDC_CERTIFICATE_SIGNED_HASH_SIZE)
#define NETWORK_JOIN_UPDATE_RESPONSE_PACKET_SIZE (MPDC_PACKET_HEADER_SIZE + NETWORK_JOIN_UPDATE_RESPONSE_MESSAGE_SIZE)

#define NETWORK_MFK_REQUEST_SEQUENCE 0xFFFFFF0FUL
#define NETWORK_MFK_REQUEST_MESSAGE_SIZE (MPDC_PACKET_SUBHEADER_SIZE + MPDC_CERTIFICATE_CHILD_SIZE + MPDC_CERTIFICATE_SIGNED_HASH_SIZE)
#define NETWORK_MFK_REQUEST_PACKET_SIZE (MPDC_PACKET_HEADER_SIZE + NETWORK_MFK_REQUEST_MESSAGE_SIZE)
#define NETWORK_MFK_RESPONSE_SEQUENCE 0xFFFFFF10UL
#define NETWORK_MFK_RESPONSE_MESSAGE_SIZE (MPDC_PACKET_SUBHEADER_SIZE + MPDC_ASYMMETRIC_PUBLIC_KEY_SIZE + MPDC_CERTIFICATE_SIGNED_HASH_SIZE)
#define NETWORK_MFK_RESPONSE_PACKET_SIZE (MPDC_PACKET_HEADER_SIZE + NETWORK_MFK_RESPONSE_MESSAGE_SIZE)
#define NETWORK_MFK_ESTABLISH_SEQUENCE 0xFFFFFF11UL
#define NETWORK_MFK_ESTABLISH_MESSAGE_SIZE (MPDC_PACKET_SUBHEADER_SIZE + MPDC_ASYMMETRIC_CIPHERTEXT_SIZE + MPDC_CERTIFICATE_SIGNED_HASH_SIZE)
#define NETWORK_MFK_ESTABLISH_PACKET_SIZE (MPDC_PACKET_HEADER_SIZE + NETWORK_MFK_ESTABLISH_MESSAGE_SIZE)

#define NETWORK_REMOTE_SIGNING_REQUEST_SEQUENCE 0xFFFFFF12UL
#define NETWORK_REMOTE_SIGNING_REQUEST_MESSAGE_SIZE (MPDC_PACKET_SUBHEADER_SIZE + MPDC_CERTIFICATE_CHILD_SIZE + MPDC_CERTIFICATE_SIGNED_HASH_SIZE)
#define NETWORK_REMOTE_SIGNING_REQUEST_PACKET_SIZE (MPDC_PACKET_HEADER_SIZE + NETWORK_REMOTE_SIGNING_REQUEST_MESSAGE_SIZE)
#define NETWORK_REMOTE_SIGNING_RESPONSE_SEQUENCE 0xFFFFFF13UL
#define NETWORK_REMOTE_SIGNING_RESPONSE_MESSAGE_SIZE (MPDC_PACKET_SUBHEADER_SIZE + MPDC_CERTIFICATE_CHILD_SIZE + MPDC_CERTIFICATE_SIGNED_HASH_SIZE)
#define NETWORK_REMOTE_SIGNING_RESPONSE_PACKET_SIZE (MPDC_PACKET_HEADER_SIZE + NETWORK_REMOTE_SIGNING_RESPONSE_MESSAGE_SIZE)

#define NETWORK_RESIGN_REQUEST_SEQUENCE 0xFFFFFF14UL
#define NETWORK_RESIGN_REQUEST_MESSAGE_SIZE (MPDC_PACKET_SUBHEADER_SIZE + MPDC_CERTIFICATE_SERIAL_SIZE + MPDC_CERTIFICATE_SIGNED_HASH_SIZE)
#define NETWORK_RESIGN_REQUEST_PACKET_SIZE (MPDC_PACKET_HEADER_SIZE + NETWORK_RESIGN_REQUEST_MESSAGE_SIZE)

#define NETWORK_REVOKE_REQUEST_SEQUENCE 0xFFFFFF15UL
#define NETWORK_REVOKE_REQUEST_MESSAGE_SIZE (MPDC_PACKET_SUBHEADER_SIZE + MPDC_CERTIFICATE_SERIAL_SIZE + MPDC_CERTIFICATE_SIGNED_HASH_SIZE)
#define NETWORK_REVOKE_REQUEST_PACKET_SIZE (MPDC_PACKET_HEADER_SIZE + NETWORK_REVOKE_REQUEST_MESSAGE_SIZE)

#define NETWORK_TOPOLOGY_QUERY_SIZE (MPDC_CERTIFICATE_SERIAL_SIZE + MPDC_CERTIFICATE_ISSUER_SIZE)
#define NETWORK_TOPOLOGY_QUERY_REQUEST_SEQUENCE 0xFFFFFF16UL
#define NETWORK_TOPOLOGY_QUERY_REQUEST_SIZE (MPDC_PACKET_SUBHEADER_SIZE + MPDC_CERTIFICATE_SERIAL_SIZE)
#define NETWORK_TOPOLOGY_QUERY_REQUEST_MESSAGE_SIZE (MPDC_PACKET_SUBHEADER_SIZE + NETWORK_TOPOLOGY_QUERY_SIZE + MPDC_CERTIFICATE_SIGNED_HASH_SIZE)
#define NETWORK_TOPOLOGY_QUERY_REQUEST_PACKET_SIZE (MPDC_PACKET_HEADER_SIZE + NETWORK_TOPOLOGY_QUERY_REQUEST_MESSAGE_SIZE)
#define NETWORK_TOPOLOGY_QUERY_RESPONSE_SEQUENCE 0xFFFFFF17UL
#define NETWORK_TOPOLOGY_QUERY_RESPONSE_MESSAGE_SIZE (MPDC_PACKET_SUBHEADER_SIZE + MPDC_NETWORK_TOPOLOGY_NODE_SIZE + MPDC_CERTIFICATE_SIGNED_HASH_SIZE)
#define NETWORK_TOPOLOGY_QUERY_RESPONSE_PACKET_SIZE (MPDC_PACKET_HEADER_SIZE + NETWORK_TOPOLOGY_QUERY_RESPONSE_MESSAGE_SIZE)

#define NETWORK_TOPOLOGY_STATUS_REQUEST_SEQUENCE 0xFFFFFF18UL
#define NETWORK_TOPOLOGY_STATUS_REQUEST_MESSAGE_SIZE (MPDC_PACKET_SUBHEADER_SIZE + MPDC_CERTIFICATE_SERIAL_SIZE + MPDC_CERTIFICATE_SIGNED_HASH_SIZE)
#define NETWORK_TOPOLOGY_STATUS_REQUEST_PACKET_SIZE (MPDC_PACKET_HEADER_SIZE + NETWORK_TOPOLOGY_STATUS_REQUEST_MESSAGE_SIZE)
#define NETWORK_TOPOLOGY_STATUS_RESPONSE_SEQUENCE 0xFFFFFF19UL
#define NETWORK_TOPOLOGY_STATUS_RESPONSE_MESSAGE_SIZE (MPDC_PACKET_SUBHEADER_SIZE + MPDC_CERTIFICATE_SERIAL_SIZE + MPDC_CERTIFICATE_SIGNED_HASH_SIZE)
#define NETWORK_TOPOLOGY_STATUS_RESPONSE_PACKET_SIZE (MPDC_PACKET_HEADER_SIZE + NETWORK_TOPOLOGY_STATUS_RESPONSE_MESSAGE_SIZE)

static size_t network_compress_node(uint8_t* snode, const mpdc_topology_node_state* lnode)
{
	MPDC_ASSERT(snode != NULL);
	MPDC_ASSERT(lnode != NULL);

	size_t pos;

	qsc_memutils_copy(snode, lnode->issuer, MPDC_CERTIFICATE_ISSUER_SIZE);
	pos = MPDC_CERTIFICATE_ISSUER_SIZE;
	qsc_memutils_copy(snode + pos, lnode->serial, MPDC_CERTIFICATE_SERIAL_SIZE);
	pos += MPDC_CERTIFICATE_SERIAL_SIZE;
	qsc_memutils_copy(snode + pos, lnode->chash, MPDC_CERTIFICATE_HASH_SIZE);
	pos += MPDC_CERTIFICATE_HASH_SIZE;

	return pos;
}

static void network_header_create(mpdc_network_packet* packetout, mpdc_network_flags flag, uint64_t sequence, uint32_t msglen)
{
	MPDC_ASSERT(packetout != NULL);

	packetout->flag = flag;
	packetout->sequence = sequence;
	packetout->msglen = msglen;
	/* set the packet creation time */
	mpdc_packet_set_utc_time(packetout);
}

static mpdc_protocol_errors network_header_validate(const mpdc_network_packet* packetin, mpdc_network_flags flag, uint64_t sequence, uint32_t msglen)
{
	MPDC_ASSERT(packetin != NULL);

	mpdc_protocol_errors merr;

	if (packetin->flag == mpdc_network_flag_system_error_condition)
	{
		merr = (mpdc_protocol_errors)packetin->pmessage[0];
	}
	else
	{
		if (mpdc_packet_time_valid(packetin) == true)
		{
			if (packetin->msglen == msglen)
			{
				if (packetin->sequence == sequence)
				{
					if (packetin->flag == flag)
					{
						merr = mpdc_protocol_error_none;
					}
					else
					{
						merr = mpdc_protocol_error_invalid_request;
					}
				}
				else
				{
					merr = mpdc_protocol_error_packet_unsequenced;
				}
			}
			else
			{
				merr = mpdc_protocol_error_receive_failure;
			}
		}
		else
		{
			merr = mpdc_protocol_error_message_time_invalid;
		}
	}

	return merr;
}

static void network_subheader_serialize(uint8_t* pstream, const mpdc_network_packet* packetin)
{
	MPDC_ASSERT(pstream != NULL);
	MPDC_ASSERT(packetin != NULL);

	qsc_intutils_le64to8(pstream, packetin->sequence);
	qsc_intutils_le64to8(pstream + sizeof(uint64_t), packetin->utctime);
}

static mpdc_protocol_errors network_unpack_error(uint8_t* pmsg)
{
	MPDC_ASSERT(pmsg != NULL);

	mpdc_protocol_errors merr;

	merr = mpdc_protocol_error_receive_failure;

	if (pmsg != NULL)
	{
		mpdc_network_packet resp = { 0 };

		/* get the server error message */
		mpdc_packet_header_deserialize(pmsg, &resp);
		resp.pmessage = pmsg + MPDC_PACKET_HEADER_SIZE;

		if (resp.flag == mpdc_network_flag_system_error_condition && resp.pmessage != NULL)
		{
			merr = (mpdc_protocol_errors)resp.pmessage[0];
		}
	}

	return merr;
}

static mpdc_protocol_errors network_certificate_hash_sign(const mpdc_network_packet* packetout, const uint8_t* sigkey, const mpdc_child_certificate* ccert)
{
	MPDC_ASSERT(packetout != NULL);
	MPDC_ASSERT(sigkey != NULL);
	MPDC_ASSERT(ccert != NULL);

	size_t mlen;
	size_t mpos;
	mpdc_protocol_errors merr;

	/* serialize the packet time-stamp and sequence number and copy it to the message */
	network_subheader_serialize(packetout->pmessage, packetout);
	mpos = MPDC_PACKET_SUBHEADER_SIZE;

	/* copy the certificate to the message */
	mpdc_certificate_child_serialize(packetout->pmessage + mpos, ccert);
	mpos += MPDC_CERTIFICATE_CHILD_SIZE;

	/* sign the message */
	mlen = mpdc_certificate_message_hash_sign(packetout->pmessage + mpos, sigkey, packetout->pmessage, mpos);

	if (mlen == MPDC_CERTIFICATE_SIGNED_HASH_SIZE)
	{
		merr = mpdc_protocol_error_none;
	}
	else
	{
		merr = mpdc_protocol_error_signing_failure;
	}

	return merr;
}

static mpdc_protocol_errors network_certificate_signed_hash_verify(mpdc_child_certificate* ccert, const mpdc_network_packet* packetin, const mpdc_child_certificate* rcert, const mpdc_root_certificate* root)
{
	MPDC_ASSERT(ccert != NULL);
	MPDC_ASSERT(packetin != NULL);
	MPDC_ASSERT(rcert != NULL);
	MPDC_ASSERT(root != NULL);

	mpdc_protocol_errors merr;

	/* verify the message signature */
	if (mpdc_certificate_signature_hash_verify(packetin->pmessage + NETWORK_CERTIFICATE_UPDATE_SIZE, MPDC_CERTIFICATE_SIGNED_HASH_SIZE, packetin->pmessage, NETWORK_CERTIFICATE_UPDATE_SIZE, rcert) == true)
	{
		uint8_t shdr[MPDC_PACKET_SUBHEADER_SIZE] = { 0 };

		network_subheader_serialize(shdr, packetin);

		/* compare the sub-header time and sequence values with the signed values */
		if (qsc_memutils_are_equal(shdr, packetin->pmessage, MPDC_PACKET_SUBHEADER_SIZE) == true)
		{
			mpdc_certificate_child_deserialize(ccert, packetin->pmessage + MPDC_PACKET_SUBHEADER_SIZE);

			/* validate the certificate format */
			merr = mpdc_network_certificate_verify(ccert, root);

			if (merr != mpdc_protocol_error_none)
			{
				qsc_memutils_clear(ccert, sizeof(mpdc_child_certificate));
			}
		}
		else
		{
			merr = mpdc_protocol_error_message_time_invalid;
		}
	}
	else
	{
		merr = mpdc_protocol_error_authentication_failure;
	}

	return merr;
}

static void network_hash_cycle_mfk(const uint8_t* serial, qsc_collection_state* mfkcol)
{
	MPDC_ASSERT(serial != NULL);
	MPDC_ASSERT(mfkcol != NULL);

	uint8_t mfkey[MPDC_CRYPTO_SYMMETRIC_KEY_SIZE] = { 0 };

	if (qsc_collection_find(mfkcol, mfkey, serial) == true)
	{
		uint8_t ckey[MPDC_CRYPTO_SYMMETRIC_KEY_SIZE] = { 0 };

		qsc_shake256_compute(ckey, MPDC_CRYPTO_SYMMETRIC_KEY_SIZE, mfkey, MPDC_CRYPTO_SYMMETRIC_KEY_SIZE);
		qsc_collection_remove(mfkcol, serial);
		qsc_collection_add(mfkcol, ckey, serial);
	}
}

static void network_derive_fkey(uint8_t* ckey, const uint8_t* mfk, const uint8_t* lhash, const uint8_t* rhash, const uint8_t* token)
{
	MPDC_ASSERT(ckey != NULL);
	MPDC_ASSERT(mfk != NULL);
	MPDC_ASSERT(lhash != NULL);
	MPDC_ASSERT(rhash != NULL);
	MPDC_ASSERT(token != NULL);

	qsc_keccak_state fks = { 0 };

	/* derive the fragment encryption key */
	qsc_sha3_initialize(&fks);
	qsc_sha3_update(&fks, qsc_keccak_rate_512, mfk, MPDC_CRYPTO_SYMMETRIC_KEY_SIZE);
	qsc_sha3_update(&fks, qsc_keccak_rate_512, lhash, MPDC_CRYPTO_SYMMETRIC_HASH_SIZE);
	qsc_sha3_update(&fks, qsc_keccak_rate_512, rhash, MPDC_CRYPTO_SYMMETRIC_HASH_SIZE);
	qsc_sha3_update(&fks, qsc_keccak_rate_512, token, MPDC_CRYPTO_SYMMETRIC_TOKEN_SIZE);
	qsc_sha3_finalize(&fks, qsc_keccak_rate_512, ckey);
}

static void network_derive_mkey(uint8_t* mkey, const uint8_t* mfk, const uint8_t* lhash, const uint8_t* rhash, const uint8_t* token)
{
	MPDC_ASSERT(mkey != NULL);
	MPDC_ASSERT(mfk != NULL);
	MPDC_ASSERT(lhash != NULL);
	MPDC_ASSERT(rhash != NULL);
	MPDC_ASSERT(token != NULL);

	qsc_keccak_state fks = { 0 };

	/* derive the fragment encryption key */
	qsc_sha3_initialize(&fks);
	qsc_sha3_update(&fks, qsc_keccak_rate_256, mfk, MPDC_CRYPTO_SYMMETRIC_KEY_SIZE);
	qsc_sha3_update(&fks, qsc_keccak_rate_256, lhash, MPDC_CRYPTO_SYMMETRIC_HASH_SIZE);
	qsc_sha3_update(&fks, qsc_keccak_rate_256, rhash, MPDC_CRYPTO_SYMMETRIC_HASH_SIZE);
	qsc_sha3_update(&fks, qsc_keccak_rate_256, token, MPDC_CRYPTO_SYMMETRIC_TOKEN_SIZE);
	qsc_sha3_finalize(&fks, qsc_keccak_rate_256, mkey);
}

static void network_mac_message(uint8_t* mtag, const uint8_t* ckey, const uint8_t* ctxt, size_t ctxlen, const uint8_t* adata)
{
	MPDC_ASSERT(mtag != NULL);
	MPDC_ASSERT(ckey != NULL);
	MPDC_ASSERT(ctxt != NULL);
	MPDC_ASSERT(ctxlen != 0);
	MPDC_ASSERT(adata != NULL);

	qsc_keccak_state fks = { 0 };

	/* derive the mac tag */
	qsc_sha3_initialize(&fks);
	qsc_sha3_update(&fks, qsc_keccak_rate_256, ckey, MPDC_CRYPTO_SYMMETRIC_KEY_SIZE);
	qsc_sha3_update(&fks, qsc_keccak_rate_256, adata, MPDC_PACKET_SUBHEADER_SIZE);
	qsc_sha3_update(&fks, qsc_keccak_rate_256, ctxt, ctxlen);
	qsc_sha3_finalize(&fks, qsc_keccak_rate_256, mtag);
}

static mpdc_protocol_errors network_message_hash_sign(const mpdc_network_packet* packetout, const uint8_t* sigkey, const uint8_t* message, size_t msglen)
{
	MPDC_ASSERT(packetout != NULL);
	MPDC_ASSERT(sigkey != NULL);
	MPDC_ASSERT(message != NULL);
	MPDC_ASSERT(msglen != 0);

	size_t mlen;
	size_t mpos;
	mpdc_protocol_errors merr;

	/* serialize the packet time-stamp and sequence number and copy it to the packet */
	network_subheader_serialize(packetout->pmessage, packetout);
	mpos = MPDC_PACKET_SUBHEADER_SIZE;

	/* copy the message to the packet */
	qsc_memutils_copy(packetout->pmessage + mpos, message, msglen);
	mpos += msglen;

	/* hash the message and time-stamp and sign the hash */
	mlen = mpdc_certificate_message_hash_sign(packetout->pmessage + mpos, sigkey, packetout->pmessage, mpos);

	if (mlen == MPDC_CERTIFICATE_SIGNED_HASH_SIZE)
	{
		merr = mpdc_protocol_error_none;
	}
	else
	{
		merr = mpdc_protocol_error_signing_failure;
	}

	return merr;
}

static mpdc_protocol_errors network_message_signed_hash_verify(uint8_t* message, const mpdc_network_packet* packetin, const mpdc_child_certificate* rcert)
{
	MPDC_ASSERT(message != NULL);
	MPDC_ASSERT(packetin != NULL);
	MPDC_ASSERT(rcert != NULL);

	mpdc_protocol_errors merr;
	size_t mlen;

	merr = mpdc_protocol_error_none;
	mlen = packetin->msglen - MPDC_CERTIFICATE_SIGNED_HASH_SIZE;

	/* verify the message signature */
	if (mpdc_certificate_signature_hash_verify(packetin->pmessage + mlen, MPDC_CERTIFICATE_SIGNED_HASH_SIZE, packetin->pmessage, mlen, rcert) == true)
	{
		uint8_t shdr[MPDC_PACKET_SUBHEADER_SIZE] = { 0 };
		
		network_subheader_serialize(shdr, packetin);

		/* compare the sub-header time and sequence values with the signed values */
		if (qsc_memutils_are_equal(shdr, packetin->pmessage, MPDC_PACKET_SUBHEADER_SIZE) == true)
		{
			qsc_memutils_copy(message, packetin->pmessage + MPDC_PACKET_SUBHEADER_SIZE, mlen - MPDC_PACKET_SUBHEADER_SIZE);
		}
		else
		{
			merr = mpdc_protocol_error_message_time_invalid;
		}
	}
	else
	{
		merr = mpdc_protocol_error_authentication_failure;
	}

	return merr;
}

/* DLA Announce Request: 
* The DLA broadcasts a hashed and signed certificate of a new Agent or IDG to MAS servers and Clients.
* sig = Sign(H(ts | rcert)
* D(rcert | sig)->M
*/

static mpdc_protocol_errors network_announce_broadcast_packet(mpdc_network_packet* packetout, const mpdc_network_announce_request_state* state)
{
	MPDC_ASSERT(packetout != NULL);
	MPDC_ASSERT(state != NULL);

	uint8_t snode[MPDC_NETWORK_TOPOLOGY_NODE_SIZE] = { 0 };
	mpdc_protocol_errors merr;

	/* serialize the node structure */
	mpdc_topology_node_serialize(snode, state->rnode);

	/* create the packet header */
	network_header_create(packetout, mpdc_network_flag_network_announce_broadcast, NETWORK_ANNOUNCE_REQUEST_SEQUENCE, NETWORK_ANNOUNCE_REQUEST_MESSAGE_SIZE);

	/* sign the serialized node and add it to the message */
	merr = network_message_hash_sign(packetout, state->sigkey, snode, MPDC_NETWORK_TOPOLOGY_NODE_SIZE);

	return merr;
}

mpdc_protocol_errors mpdc_network_announce_broadcast(mpdc_network_announce_request_state* state)
{
	MPDC_ASSERT(state != NULL);

	mpdc_protocol_errors merr;

	if (state != NULL)
	{
		mpdc_network_packet reqt = { 0 };
		uint8_t sbuf[NETWORK_ANNOUNCE_REQUEST_PACKET_SIZE] = { 0 };

		/* create the packet */
		reqt.pmessage = sbuf + MPDC_PACKET_HEADER_SIZE;
		merr = network_announce_broadcast_packet(&reqt, state);

		/* serialize the header */
		mpdc_packet_header_serialize(&reqt, sbuf);

		if (merr == mpdc_protocol_error_none)
		{
			if (state->rnode->designation == mpdc_network_designation_agent)
			{
				/* broadcast a new agent to clients and mas servers */
				mpdc_network_broadcast_message(state->list, sbuf, NETWORK_ANNOUNCE_REQUEST_PACKET_SIZE, mpdc_network_designation_mas);
				mpdc_network_broadcast_message(state->list, sbuf, NETWORK_ANNOUNCE_REQUEST_PACKET_SIZE, mpdc_network_designation_client);
			}
			else if (state->rnode->designation == mpdc_network_designation_mas)
			{
				/* broadcast a new mas to clients */
				mpdc_network_broadcast_message(state->list, sbuf, NETWORK_ANNOUNCE_REQUEST_PACKET_SIZE, mpdc_network_designation_client);
			}
		}
	}
	else
	{
		merr = mpdc_protocol_error_invalid_request;
	}

	return merr;
}

/* Device Announce Response: 
* Verifies the signature of the announce message.
* Performs a packet valid-time check, and compares that time with the signed hash
* of the serialized certificate, time-stamp, and sequence number.
* If the signature and time-stamp checks pass, the certificate is deserialized and passed back to the caller in the function state.
* rcert = (Vroot(rcert), Vrcert(H(ts | rcert)))
*/

mpdc_protocol_errors mpdc_network_announce_response(mpdc_network_announce_response_state* state, const mpdc_network_packet* packetin)
{
	MPDC_ASSERT(state != NULL);
	MPDC_ASSERT(packetin != NULL);

	mpdc_protocol_errors merr;

	if (state != NULL && packetin != NULL)
	{
		merr = network_header_validate(packetin, mpdc_network_flag_network_announce_broadcast, NETWORK_ANNOUNCE_REQUEST_SEQUENCE, NETWORK_ANNOUNCE_REQUEST_MESSAGE_SIZE);

		if (merr == mpdc_protocol_error_none)
		{
			uint8_t snode[MPDC_NETWORK_TOPOLOGY_NODE_SIZE] = { 0 };

			/* verify the certificate update */
			merr = network_message_signed_hash_verify(snode, packetin, state->dcert);

			if (merr == mpdc_protocol_error_none)
			{
				/* serialize the node structure */
				mpdc_topology_node_deserialize(state->rnode, snode);
			}
		}
	}
	else
	{
		merr = mpdc_protocol_error_invalid_request;
	}

	return merr;
}

/* DLA Convergence Broadcast:
* Network convergence is an administrative event called from the DLA console.
* Each MAS server and Agent on the network is sent a copy of their topological node database entry.
* The serialized node entry for the remote device is hashed, and the hash signed by the DLA, and sent to the device.
* The signature is verified by the device using the DLA's public certificate, the local node entry is serialized and hashed,
* and compared with the signed hash. If the hashes match, the entry in the DLA topological database is synchronized, 
* if the entries do not match, the device serializes the current database entry and the certificate, signs them with the current
* signature key, which is signed by the root (RDS), and sends it back to the DLA.
* The DLA verifies the new certificate using the Root public certificate.
* The old entry is purged, a new topological entry is added to the database, and the new certificate is stored.
* Note that the proper proceedure after a certificate update on a MAS or Agent, is to resign from the network,
* and then rejoin with the new certificate.
* sig = Sign(H(ts | node)
* D(node | sig)->A,M,I
*/

static mpdc_protocol_errors network_converge_request_packet(mpdc_network_packet* packetout, const mpdc_network_converge_request_state* state, const uint8_t* snode)
{
	MPDC_ASSERT(packetout != NULL);
	MPDC_ASSERT(state != NULL);
	MPDC_ASSERT(snode != NULL);

	mpdc_protocol_errors merr;

	if (packetout != NULL && state != NULL && snode != NULL)
	{
		/* create the packet header */
		network_header_create(packetout, mpdc_network_flag_network_converge_request, NETWORK_CONVERGE_REQUEST_SEQUENCE, NETWORK_CONVERGE_REQUEST_MESSAGE_SIZE);

		/* hash the message and sign the hash */
		merr = network_message_hash_sign(packetout, state->sigkey, snode, MPDC_NETWORK_TOPOLOGY_NODE_SIZE);
	}
	else
	{
		merr = mpdc_protocol_error_invalid_request;
	}

	return merr;
}

static mpdc_protocol_errors network_converge_response_verify(const mpdc_network_converge_request_state* state, const mpdc_network_packet* packetin)
{
	MPDC_ASSERT(state != NULL);
	MPDC_ASSERT(packetin != NULL);

	mpdc_protocol_errors merr;

	if (state != NULL && packetin != NULL)
	{
		/* inspect the response packet parameters */
		merr = network_header_validate(packetin, mpdc_network_flag_network_converge_response, NETWORK_CONVERGE_RESPONSE_SEQUENCE, NETWORK_CONVERGE_RESPONSE_MESSAGE_SIZE);

		if (merr == mpdc_protocol_error_none)
		{
			uint8_t rnode[MPDC_NETWORK_TOPOLOGY_NODE_SIZE] = { 0 };

			/* verify the hash and signature */
			merr = network_message_signed_hash_verify(rnode, packetin, state->rcert);

			/* check that the node descriptions are the same */
			if (merr == mpdc_protocol_error_none)
			{
				uint8_t snode[MPDC_NETWORK_TOPOLOGY_NODE_SIZE] = { 0 };

				/* serialize the local node copy */
				mpdc_topology_node_serialize(snode, state->rnode);

				/* compare nodes for equality */
				if (qsc_memutils_are_equal(snode, rnode, MPDC_NETWORK_TOPOLOGY_NODE_SIZE) == true)
				{
					merr = mpdc_protocol_error_none;
				}
				else
				{
					merr = mpdc_protocol_error_node_not_found;
				}
			}
		}
	}
	else
	{
		merr = mpdc_protocol_error_invalid_request;
	}

	return merr;
}

mpdc_protocol_errors mpdc_network_converge_request(const mpdc_network_converge_request_state* state)
{
	MPDC_ASSERT(state != NULL);

	/* the dla loops through MAS and Agent nodes in the topology, 
	sending them the signed topological node entry of that device for verification */

	mpdc_protocol_errors merr;

	merr = mpdc_protocol_error_memory_allocation;

	if (state != NULL)
	{
		mpdc_network_packet reqt = { 0 };

		uint8_t snode[MPDC_NETWORK_TOPOLOGY_NODE_SIZE] = { 0 };

		/* add the serialized topological node to the message */
		if (mpdc_topology_node_serialize(snode, state->rnode) == MPDC_NETWORK_TOPOLOGY_NODE_SIZE)
		{
			uint8_t sbuf[NETWORK_CONVERGE_REQUEST_PACKET_SIZE] = { 0 };

			reqt.pmessage = sbuf + MPDC_PACKET_HEADER_SIZE;
			/* create a node-specific request packet */
			merr = network_converge_request_packet(&reqt, state, snode);

			if (merr == mpdc_protocol_error_none)
			{
				qsc_socket csock = { 0 };
				size_t slen;

				mpdc_packet_header_serialize(&reqt, sbuf);

				/* connect to the remote agent */
				if (mpdc_network_connect_to_device(&csock, state->rnode->address, state->rnode->designation) == qsc_socket_exception_success)
				{
					/* send the converge request */
					slen = qsc_socket_send(&csock, sbuf, NETWORK_CONVERGE_REQUEST_PACKET_SIZE, qsc_socket_send_flag_none);
			
					if (slen == NETWORK_CONVERGE_REQUEST_PACKET_SIZE)
					{
						mpdc_network_packet resp = { 0 };
						uint8_t rbuf[NETWORK_CONVERGE_RESPONSE_PACKET_SIZE] = { 0 };
						size_t rlen;

						/* wait for the reply */
						rlen = qsc_socket_receive(&csock, rbuf, sizeof(rbuf), qsc_socket_receive_flag_wait_all);

						if (rlen == NETWORK_CONVERGE_RESPONSE_PACKET_SIZE)
						{
							mpdc_packet_header_deserialize(rbuf, &resp);
							resp.pmessage = rbuf + MPDC_PACKET_HEADER_SIZE;

							/* verify the response */
							merr = network_converge_response_verify(state, &resp);
						}
						else
						{
							merr = mpdc_protocol_error_receive_failure;
						}
					}
					else
					{
						merr = mpdc_protocol_error_transmit_failure;
					}

					/* shut down the socket */
					mpdc_network_socket_dispose(&csock);
				}
				else
				{
					merr = mpdc_protocol_error_connection_failure;
				}
			}
		}
		else
		{
			merr = mpdc_protocol_error_serialization_failure;
		}
	}

	return merr;
}

/* Convergence Response:
* If the node entry sent from the DLA matches the local node entry in the devices topology list,
* the device signs the serialized node and sends it back to the DLA.
* If the node entries do not match, the device serializes its certificate, hashes the time-stamp and certificate, 
* signs the hash and sends the updated certificate back to the DLA.
* rcert = (Vroot(rcert), Vrcert(H(ts | rcert)))
* rnode = node ? M(node, Sign(H(ts | node))->D : M(cert, Sign(H(ts | cert))->D
*/

static mpdc_protocol_errors network_converge_response_packet(mpdc_network_packet* packetout, const mpdc_network_converge_response_state* state)
{
	MPDC_ASSERT(packetout != NULL);
	MPDC_ASSERT(state != NULL);

	mpdc_protocol_errors merr;

	if (packetout != NULL && state != NULL)
	{
		uint8_t snode[MPDC_NETWORK_TOPOLOGY_NODE_SIZE] = { 0 };

		/* create the packet header */
		network_header_create(packetout, mpdc_network_flag_network_converge_response, NETWORK_CONVERGE_RESPONSE_SEQUENCE, NETWORK_CONVERGE_RESPONSE_MESSAGE_SIZE);

		/* serialize the node structure */
		mpdc_topology_node_serialize(snode, state->lnode);

		/* hash the message and sign the hash */
		merr = network_message_hash_sign(packetout, state->sigkey, snode, MPDC_NETWORK_TOPOLOGY_NODE_SIZE);
	}
	else
	{
		merr = mpdc_protocol_error_invalid_request;
	}

	return merr;
}


/* Convergence Response Verify:
* When a node value is identical to the one on the DLA, the database entry is considered to be synchronized.
* The device will serialize its topological node entry, add the time-stamp and sequence number to the message, 
* hash the message, and sign the hash. The message is sent back to the DLA, which verifies the message.
* sig = Sign(H(ts | node)
* A,M,I(node | sig)->D
* rnode = (Vroot(rcert), Vrcert(H(ts | rnode)))
*/

static mpdc_protocol_errors network_converge_request_verify(const mpdc_network_converge_response_state* state, const mpdc_network_packet* packetin)
{
	uint8_t rnode[MPDC_NETWORK_TOPOLOGY_NODE_SIZE] = { 0 };
	mpdc_protocol_errors merr;

	/* inspect the request packet parameters */
	merr = network_header_validate(packetin, mpdc_network_flag_network_converge_request, NETWORK_CONVERGE_REQUEST_SEQUENCE, NETWORK_CONVERGE_REQUEST_MESSAGE_SIZE);

	if (merr == mpdc_protocol_error_none)
	{
		/* verify the dla certificates signature */
		merr = network_message_signed_hash_verify(rnode, packetin, state->rcert);

		if (merr == mpdc_protocol_error_none)
		{
			uint8_t snode[MPDC_NETWORK_TOPOLOGY_NODE_SIZE] = { 0 };

			/* serialize the node structure */
			mpdc_topology_node_serialize(snode, state->lnode);

			/* compare nodes, if they match, send a confirmation */
			if (qsc_memutils_are_equal(snode, rnode, MPDC_NETWORK_TOPOLOGY_NODE_SIZE) == true)
			{
				merr = mpdc_protocol_error_none;
			}
			else
			{
				merr = mpdc_protocol_error_none;
			}
		}
	}

	return merr;
}

mpdc_protocol_errors mpdc_network_converge_response(const mpdc_network_converge_response_state* state, const mpdc_network_packet* packetin)
{
	MPDC_ASSERT(state != NULL);
	MPDC_ASSERT(packetin != NULL);

	/* the MAS, Client, or Agent response to a converge request */

	size_t slen;
	mpdc_protocol_errors merr;

	if (state != NULL && packetin != NULL)
	{
		merr = network_converge_request_verify(state, packetin);

		if (merr == mpdc_protocol_error_none)
		{
			mpdc_network_packet resp = { 0 };
			uint8_t sbuf[NETWORK_CONVERGE_RESPONSE_PACKET_SIZE] = { 0 };

			resp.pmessage = sbuf + MPDC_PACKET_HEADER_SIZE;

			/* no update required, just verify */
			merr = network_converge_response_packet(&resp, state);

			if (merr == mpdc_protocol_error_none)
			{
				mpdc_packet_header_serialize(&resp, sbuf);

				/* send the request */
				slen = qsc_socket_send(state->csock, sbuf, NETWORK_CONVERGE_RESPONSE_PACKET_SIZE, qsc_socket_send_flag_none);

				if (slen == NETWORK_CONVERGE_RESPONSE_PACKET_SIZE)
				{
					merr = mpdc_protocol_error_none;
				}
				else
				{
					merr = mpdc_protocol_error_transmit_failure;
				}
			}
		}
	}
	else
	{
		merr = mpdc_protocol_error_invalid_request;
	}

	return merr;
}

/* Key Fragment Exchange Request: 
* Key fragments are exchanged between devices that share master fragment keys.
* The requestor sends the node serial number and a random token to the remote device.
* A(ser, tok)->B
* The responder generates an fkey, encrypts and Macs the fkey, and sends the ciphertext and Mac tag back to the requestor.
* The requestor hashes the shared mfk, the local and remote certificate hashes, and the token to create a key.
* The key is used to verify the Mac code and decrypt the ciphertext.
* k1,k2 = H(mfk | lhash | rhash | tok)
* fkey = Mk2(cpt), Dk1(cpt)
*/

static void network_fkey_request_packet(mpdc_network_packet* packetout, mpdc_network_fkey_request_state* state)
{
	MPDC_ASSERT(packetout != NULL);
	MPDC_ASSERT(state != NULL);

	/* the MAS/Client sends the local serial number and a random token */

	network_header_create(packetout, mpdc_network_flag_fragment_request, NETWORK_FRAGMENT_FKEY_REQUEST_SEQUENCE, NETWORK_FRAGMENT_FKEY_REQUEST_MESSAGE_SIZE);

	/* generate the token */
	qsc_acp_generate(state->token, MPDC_CRYPTO_SYMMETRIC_TOKEN_SIZE);

	/* add the local certificate serial number and token to the message */
	qsc_memutils_copy(packetout->pmessage, state->lnode->serial, MPDC_CERTIFICATE_SERIAL_SIZE);
	qsc_memutils_copy(packetout->pmessage + MPDC_CERTIFICATE_SERIAL_SIZE, state->token, MPDC_CRYPTO_SYMMETRIC_TOKEN_SIZE);
}

static mpdc_protocol_errors network_fkey_response_verify(mpdc_network_fkey_request_state* state, const mpdc_network_packet* packetin)
{
	MPDC_ASSERT(state != NULL);
	MPDC_ASSERT(packetin != NULL);

	mpdc_protocol_errors merr;

	merr = network_header_validate(packetin, mpdc_network_flag_fragment_response, NETWORK_FRAGMENT_FKEY_RESPONSE_SEQUENCE, NETWORK_FRAGMENT_FKEY_RESPONSE_MESSAGE_SIZE);

	/* verify the packet parameters */
	if (merr == mpdc_protocol_error_none)
	{
		uint8_t ckey[QSC_SHA3_512_HASH_SIZE] = { 0 };
		uint8_t shdr[MPDC_PACKET_SUBHEADER_SIZE] = { 0 };
		uint8_t mtag[MPDC_CRYPTO_SYMMETRIC_HASH_SIZE] = { 0 };

		/* derive the session keys k = H(mfk | lhash | rhash | tok ) */
		network_derive_fkey(ckey, state->mfk, state->lnode->chash, state->rnode->chash, state->token);

		/* serialize the packet header */
		network_subheader_serialize(shdr, packetin);

		/* mac the ciphertext and check it against the packet tag */
		network_mac_message(mtag, ckey + MPDC_CRYPTO_SYMMETRIC_KEY_SIZE, packetin->pmessage, packetin->msglen - MPDC_CRYPTO_SYMMETRIC_HASH_SIZE, shdr);

		if (qsc_memutils_are_equal(mtag, packetin->pmessage + MPDC_CRYPTO_SYMMETRIC_KEY_SIZE, MPDC_CRYPTO_SYMMETRIC_HASH_SIZE) == true)
		{
			/* decrypt the cipher-text and copy to the fragment key */
			qsc_memutils_xor(ckey, packetin->pmessage, MPDC_CRYPTO_SYMMETRIC_KEY_SIZE);
			qsc_memutils_copy(state->frag, ckey, MPDC_CRYPTO_SYMMETRIC_KEY_SIZE);
			qsc_memutils_clear(ckey, sizeof(ckey));
			merr = mpdc_protocol_error_none;
		}
		else
		{
			merr = mpdc_protocol_error_authentication_failure;
		}
	}
	else
	{
		merr = mpdc_protocol_error_invalid_request;
	}

	return merr;
}

mpdc_protocol_errors mpdc_network_fkey_request(mpdc_network_fkey_request_state* state)
{
	MPDC_ASSERT(state != NULL);
	
	qsc_socket csock = { 0 };
	mpdc_protocol_errors merr;

	if (state != NULL)
	{
		/* connect to the remote agent */
		if (mpdc_network_connect_to_device(&csock, state->rnode->address, mpdc_network_designation_agent) == qsc_socket_exception_success)
		{
			mpdc_network_packet reqt = { 0 };
			uint8_t sbuf[NETWORK_FRAGMENT_FKEY_REQUEST_PACKET_SIZE] = { 0 };
			size_t slen;

			/* create the request packet */
			reqt.pmessage = sbuf + MPDC_PACKET_HEADER_SIZE;
			network_fkey_request_packet(&reqt, state);
			mpdc_packet_header_serialize(&reqt, sbuf);

			/* send the request */
			slen = qsc_socket_send(&csock, sbuf, NETWORK_FRAGMENT_FKEY_REQUEST_PACKET_SIZE, qsc_socket_send_flag_none);
			qsc_memutils_clear(sbuf, NETWORK_FRAGMENT_FKEY_REQUEST_PACKET_SIZE);

			if (slen == NETWORK_FRAGMENT_FKEY_REQUEST_PACKET_SIZE)
			{
				mpdc_network_packet resp = { 0 };
				uint8_t rbuf[NETWORK_FRAGMENT_FKEY_RESPONSE_PACKET_SIZE] = { 0 };
				size_t rlen;

				/* wait for the reply */
				rlen = qsc_socket_receive(&csock, rbuf, sizeof(rbuf), qsc_socket_receive_flag_wait_all);

				if (rlen == NETWORK_FRAGMENT_FKEY_RESPONSE_PACKET_SIZE)
				{
					mpdc_packet_header_deserialize(rbuf, &resp);
					resp.pmessage = rbuf + MPDC_PACKET_HEADER_SIZE;

					/* verify the message and store the key */
					merr = network_fkey_response_verify(state, &resp);
				}
				else if (rlen == NETWORK_ERROR_PACKET_SIZE)
				{
					/* get the server error from the packet */
					merr = network_unpack_error(rbuf);
				}
				else
				{
					merr = mpdc_protocol_error_receive_failure;
				}
			}
			else
			{
				merr = mpdc_protocol_error_transmit_failure;
			}

			mpdc_network_socket_dispose(&csock);
		}
		else
		{
			merr = mpdc_protocol_error_connect_failure;
		}
	}
	else
	{
		merr = mpdc_protocol_error_invalid_request;
	}

	return merr;
}

/* Key Fragment Exchange Response: 
* The device uses the node serial number to load the requestors certificate, hashes the master fragment key, the token, 
* local and remote certificates hashes, to produce a symmetric cipher key.
* The hash function derives a keystream, used to mac and xor encrypt a random fragment key.
* fkey = Gen()
* k1,k2 = H(mfk | rhash | lhash | tok)
* cpt = Mk2(Ek1(fkey))
* A(cpt | tag)->M
*/

static mpdc_protocol_errors network_fkey_response_packet(mpdc_network_packet* packetout, const mpdc_network_packet* packetin, mpdc_network_fkey_response_state* state)
{
	MPDC_ASSERT(packetout != NULL);
	MPDC_ASSERT(packetin != NULL);
	MPDC_ASSERT(state != NULL);

	mpdc_protocol_errors merr;

	/* The device hashes the token, local and remote certificate hashes, and the master fragment key.
	   The hash function derives a keystream, used to mac and xor encrypt a random fragmant key. */

	merr = network_header_validate(packetin, mpdc_network_flag_fragment_request, NETWORK_FRAGMENT_FKEY_REQUEST_SEQUENCE, NETWORK_FRAGMENT_FKEY_REQUEST_MESSAGE_SIZE);

	if (merr == mpdc_protocol_error_none)
	{
		uint8_t ckey[QSC_SHA3_512_HASH_SIZE] = { 0 };
		uint8_t shdr[MPDC_PACKET_SUBHEADER_SIZE] = { 0 };
		uint8_t* ptok;

		ptok = packetin->pmessage + MPDC_CERTIFICATE_SERIAL_SIZE;

		/* create the packet header */
		network_header_create(packetout, mpdc_network_flag_fragment_response, NETWORK_FRAGMENT_FKEY_RESPONSE_SEQUENCE, NETWORK_FRAGMENT_FKEY_RESPONSE_MESSAGE_SIZE);

		/* generate the random fragment */
		qsc_acp_generate(state->frag, MPDC_CRYPTO_SYMMETRIC_KEY_SIZE);

		/* derive the session keys k = H(mfk | lhash | rhash | tok ) */
		network_derive_fkey(ckey, state->mfk, state->rnode->chash, state->lnode->chash, ptok);
			
		/* encrypt the fragment key and copy the cipher-text to the message */
		qsc_memutils_xor(ckey, state->frag, MPDC_CRYPTO_SYMMETRIC_KEY_SIZE);
		qsc_memutils_copy(packetout->pmessage, ckey, MPDC_CRYPTO_SYMMETRIC_KEY_SIZE);

		network_subheader_serialize(shdr, packetout);

		/* mac the ciphertext and check it against the packet tag */
		network_mac_message(packetout->pmessage + MPDC_CRYPTO_SYMMETRIC_KEY_SIZE, ckey + MPDC_CRYPTO_SYMMETRIC_KEY_SIZE, packetout->pmessage, packetout->msglen - MPDC_CRYPTO_SYMMETRIC_HASH_SIZE, shdr);

		merr = mpdc_protocol_error_none;
	}
	else
	{
		merr = mpdc_protocol_error_packet_header_invalid;
	}

	return merr;
}

mpdc_protocol_errors mpdc_network_fkey_response(mpdc_network_fkey_response_state* state, const mpdc_network_packet* packetin)
{
	MPDC_ASSERT(state != NULL);
	MPDC_ASSERT(packetin != NULL);

	mpdc_protocol_errors merr;

	if (state != NULL && packetin != NULL)
	{
		uint8_t sbuf[NETWORK_FRAGMENT_FKEY_RESPONSE_PACKET_SIZE] = { 0 };
		mpdc_network_packet resp = { 0 };

		/* create the response packet */
		resp.pmessage = sbuf + MPDC_PACKET_HEADER_SIZE;
		merr = network_fkey_response_packet(&resp, packetin, state);
		mpdc_packet_header_serialize(&resp, sbuf);

		if (merr == mpdc_protocol_error_none)
		{
			size_t slen;

			/* send the response message */
			slen = qsc_socket_send(state->csock, sbuf, NETWORK_FRAGMENT_FKEY_RESPONSE_PACKET_SIZE, qsc_socket_send_flag_none);
			qsc_memutils_clear(sbuf, NETWORK_FRAGMENT_FKEY_RESPONSE_PACKET_SIZE);

			if (slen == NETWORK_FRAGMENT_FKEY_RESPONSE_PACKET_SIZE)
			{
				merr = mpdc_protocol_error_none;
			}
			else
			{
				merr = mpdc_protocol_error_transmit_failure;
			}
		}
	}
	else
	{
		merr = mpdc_protocol_error_invalid_request;
	}

	/* notify of failure with error message */
	if (merr != mpdc_protocol_error_none)
	{
		mpdc_network_send_error(state->csock, merr);
	}

	return merr;
}

/* Fragment collection and master key derivation:
* The Client sends an fkey collection request to the MAS C(ser | tok)->M,
* containing the Client's certificate serial number and a random token.
* The MAS generates its own random token and sends fragment queries to available agents M(cser | ctok, mser | mtok)->a1, a2, a3....
* The Agents sends back a random fragment key, encrypted twice, once using the MAS master fragment key, 
* the other using the Clients mfk; k = H(mfk, rhash, lhash, tok), cpt = Ek(frag),
* and a second encrypted set with a key derived from the MAS mfk and token.
* The ciphertext from both encrypted keys sets are mac'd and the mac tag is added to the message.
* A(cpt1, cpt2, Mk(cpt1, cpt2))->M.
* The MAS verifies the mac tag against the ciphertext, and decrypts its portion of the key-set.
* The MAS copies the encrypted client keys and agent serial numbers to a key-set. 
* Once the MAS has collected keys from every Agent, it sends the set of encrypted agent keys back to the client,
* with each fragment encrypted with the Agent/Client mfk.
* fset = { aser1|fcpt1, aser2|fcpt2, ... n }.
* The key-set is sent to the Client, where like the MAS, the serial number is used to look up the corresponding Agent mfk,
* verify and decrypt the fkey sent by each agent, along with a key fragment shared between the MAS and the Client, 
* All fragments are hashed to create a session key used between the MAS and the Client to establish an encrypted tunnel.
* The fkeys are compressed ifk = H(fkey1, fkey2, ... fkeyn), and injected into the session key derivation function, 
* creating the fragment key hash, which is used to derive symmetric cipher keys for the send/receive channels of an encrypted tunnel.
* Future Design Upgrade:
* Make each token unique between MAS and Client and Agents.
* The Client has to send a unique agent(ser, tok) pairing for each agent in an ordered agents list.
* The MAS creates a set as well, and uses all the assigned pairings i.e. 
* ({ ser1, tokc1, tokm1 }-->agent 1, 2, 3..., n) in the ordered agents list.
* MAS, Client, and each Agent then calculate the efk for each response with a unique token assigned to each efk derivation,
*/

/* Client - Fragment Collection Request:
* The Client sends its certificate serial number and a random token to the MAS server.
* C(ser, tok)->M
* The Client then waits for a response from the server, containing a set of encrypted fragments,
* Mac'd by the MAS.
* M(Mk(Ek(frag1)), Ek(frag2)), ...))->C
* The Client verifies the message and adds the Mas/Client fragment to the key hash, then decrypts each
* agent fragment, adding them to the fragment hash key.
*/

static mpdc_protocol_errors network_fragment_collection_request_packet(mpdc_network_packet* packetout, mpdc_network_fragment_collection_request_state* state)
{
	MPDC_ASSERT(packetout != NULL);
	MPDC_ASSERT(state != NULL);

	uint8_t mfk[MPDC_CRYPTO_SYMMETRIC_KEY_SIZE] = { 0 };
	size_t mpos;
	mpdc_protocol_errors merr;

	/* the client sends the serial number and a random token to the MAS */

	merr = mpdc_protocol_error_none;

	/* get the client/mas shared mfk */
	if (qsc_collection_find(state->lmfk, mfk, state->rnode->serial) == true)
	{
		uint8_t shdr[MPDC_PACKET_SUBHEADER_SIZE] = { 0 };
		uint8_t mkey[MPDC_CRYPTO_SYMMETRIC_KEY_SIZE] = { 0 };
		uint8_t mtok[MPDC_CRYPTO_SYMMETRIC_TOKEN_SIZE] = { 0 };

		network_header_create(packetout, mpdc_network_flag_fragment_collection_request, NETWORK_FRAGMENT_COLLECTION_REQUEST_SEQUENCE, NETWORK_FRAGMENT_COLLECTION_REQUEST_MESSAGE_SIZE);

		/* generate the session token */
		qsc_acp_generate(state->token, MPDC_CRYPTO_SYMMETRIC_TOKEN_SIZE);

		/* add the local certificate serial number and token to the message */
		qsc_memutils_copy(packetout->pmessage, state->lnode->serial, MPDC_CERTIFICATE_SERIAL_SIZE);
		mpos = MPDC_CERTIFICATE_SERIAL_SIZE;
		qsc_memutils_copy(packetout->pmessage + mpos, state->token, MPDC_CRYPTO_SYMMETRIC_TOKEN_SIZE);
		mpos += MPDC_CRYPTO_SYMMETRIC_TOKEN_SIZE;

		/* use the hashed message to generate a unique token */
		qsc_shake256_compute(mtok, MPDC_CRYPTO_SYMMETRIC_TOKEN_SIZE, packetout->pmessage, NETWORK_FRAGMENT_COLLECTION_REQUEST_SIZE);
		/* combine the client-mas mfkey, token, and certificate hashes to generate a mac key */
		network_derive_mkey(mkey, mfk, state->rnode->chash, state->lnode->chash, mtok);

		/* mac the message and timestamp, and add the tag to the message */
		network_subheader_serialize(shdr, packetout);
		network_mac_message(packetout->pmessage + mpos, mkey, packetout->pmessage, packetout->msglen - MPDC_CRYPTO_SYMMETRIC_HASH_SIZE, shdr);
	}
	else
	{
		merr = mpdc_protocol_error_key_unrecognized;
	}

	return merr;
}

static mpdc_protocol_errors network_fragment_collection_request_derive(mpdc_network_fragment_collection_request_state* state, const mpdc_network_packet* packetin)
{
	MPDC_ASSERT(state != NULL);
	MPDC_ASSERT(packetin != NULL);

	qsc_keccak_state fkhs = { 0 };
	uint8_t mmfk[MPDC_CRYPTO_SYMMETRIC_KEY_SIZE] = { 0 };
	uint8_t* rcpt;
	uint8_t* rser;
	uint8_t* rtag;
	size_t fcnt;
	size_t mpos;
	mpdc_protocol_errors merr;

	fcnt = packetin->msglen / NETWORK_FRAGMENT_QUERY_RESPONSE_SIZE;
	merr = mpdc_protocol_error_none;

	/* initialize the fragment hash */
	qsc_sha3_initialize(&fkhs);

	/* inject mas-client fragment first */
	if (qsc_collection_find(state->lmfk, mmfk, state->rnode->serial) == true)
	{
		uint8_t ckey[QSC_SHA3_512_HASH_SIZE] = { 0 };
		uint8_t mtag[MPDC_CRYPTO_SYMMETRIC_HASH_SIZE] = { 0 };
		uint8_t shdr[MPDC_PACKET_SUBHEADER_SIZE] = { 0 };

		/* derive the client-mas fkey */
		network_derive_fkey(ckey, mmfk, state->lnode->chash, state->rnode->chash, state->token);

		/* mac the ciphertexts */
		rtag = packetin->pmessage + (packetin->msglen - MPDC_CRYPTO_SYMMETRIC_HASH_SIZE);
		network_subheader_serialize(shdr, packetin);
		network_mac_message(mtag, ckey + MPDC_CRYPTO_SYMMETRIC_KEY_SIZE, packetin->pmessage, packetin->msglen - MPDC_CRYPTO_SYMMETRIC_HASH_SIZE, shdr);

		/* verify the mac, decrypt the fragment key, and add the fragment to the fragment key hash */
		if (qsc_memutils_are_equal_256(mtag, rtag) == true)
		{
			/* decrypt the mas key fragment */
			qsc_memutils_xor(ckey, packetin->pmessage + MPDC_CERTIFICATE_SERIAL_SIZE, MPDC_CRYPTO_SYMMETRIC_KEY_SIZE);
			mpos = NETWORK_FRAGMENT_QUERY_RESPONSE_SIZE;
			/* add the fragment to the hkey hash */
			qsc_sha3_update(&fkhs, qsc_keccak_rate_256, ckey, MPDC_CRYPTO_SYMMETRIC_KEY_SIZE);
			
			/* decrypt each fragment, and add them to the key hash */
			for (size_t i = 0; i < fcnt - 1; ++i)
			{
				mpdc_topology_node_state node = { 0 };

				rser = packetin->pmessage + mpos;
				rcpt = packetin->pmessage + mpos + MPDC_CERTIFICATE_SERIAL_SIZE;
				mpos += NETWORK_FRAGMENT_QUERY_RESPONSE_SIZE;

				if (mpdc_topology_node_find(state->list, &node, rser) == true)
				{
					uint8_t cmfk[MPDC_CRYPTO_SYMMETRIC_KEY_SIZE] = { 0 };

					if (qsc_collection_find(state->lmfk, cmfk, node.serial) == true)
					{
						qsc_memutils_clear(ckey, sizeof(ckey));
						/* generate the client-agent fkey */
						network_derive_fkey(ckey, cmfk, state->lnode->chash, node.chash, state->token);
						/* decrypt the key fragment */
						qsc_memutils_xor(ckey, rcpt, MPDC_CRYPTO_SYMMETRIC_KEY_SIZE);
						/* update the fragment hash key */
						qsc_sha3_update(&fkhs, qsc_keccak_rate_256, ckey, MPDC_CRYPTO_SYMMETRIC_KEY_SIZE);
					}
					else
					{
						/* abort; agent portion of exchange has failed */
						merr = mpdc_protocol_error_key_unrecognized;
						break;
					}
				}
				else
				{
					/* abort; agent portion of exchange has failed */
					merr = mpdc_protocol_error_node_not_found;
					break;
				}
			}
		}
		else
		{
			/* abort; mas portion of exchange has failed */
			merr = mpdc_protocol_error_authentication_failure;
		}
	}
	else
	{
		/* abort; mas portion of exchange has failed */
		merr = mpdc_protocol_error_key_unrecognized;
	}

	if (merr == mpdc_protocol_error_none)
	{
#if defined(MPDC_NETWORK_MFK_HASH_CYCLED)
		/* client cycles mfk for agents and mas here */
		
		network_hash_cycle_mfk(state->rnode->serial, state->lmfk);
		mpos = NETWORK_FRAGMENT_QUERY_RESPONSE_SIZE;

		for (size_t i = 0; i < fcnt - 1; ++i)
		{
			rser = packetin->pmessage + mpos;
			mpos += NETWORK_FRAGMENT_QUERY_RESPONSE_SIZE;
			network_hash_cycle_mfk(rser, state->lmfk);
		}
#endif

#if defined(MPDC_EXTENDED_SESSION_SECURITY)
		/* create the fragment hash key and store in state */
		qsc_sha3_finalize(&fkhs, qsc_keccak_rate_512, state->hfkey);
#else
		/* create the fragment hash key and store in state */
		qsc_sha3_finalize(&fkhs, qsc_keccak_rate_256, state->hfkey);
#endif
	}

	qsc_keccak_dispose(&fkhs);

	return merr;
}

mpdc_protocol_errors mpdc_network_fragment_collection_request(mpdc_network_fragment_collection_request_state* state)
{
	MPDC_ASSERT(state != NULL);

	mpdc_protocol_errors merr;
	mpdc_network_packet reqt = { 0 };
	uint8_t sbuf[NETWORK_FRAGMENT_COLLECTION_REQUEST_PACKET_SIZE] = { 0 };
	size_t slen;
	
	if (state != NULL)
	{
		/* connect to the server */
		if (mpdc_network_connect_to_device(state->csock, state->rnode->address, state->rnode->designation) == qsc_socket_exception_success)
		{
			/* create the packet header */
			reqt.pmessage = sbuf + MPDC_PACKET_HEADER_SIZE;
			network_fragment_collection_request_packet(&reqt, state);
			mpdc_packet_header_serialize(&reqt, sbuf);

			slen = qsc_socket_client_send(state->csock, sbuf, NETWORK_FRAGMENT_COLLECTION_REQUEST_PACKET_SIZE, qsc_socket_send_flag_none);

			if (slen == NETWORK_FRAGMENT_COLLECTION_REQUEST_PACKET_SIZE)
			{
				mpdc_network_packet resp = { 0 };
				uint8_t hdr[MPDC_PACKET_HEADER_SIZE] = { 0 };
				uint8_t* rbuf;
				size_t mlen;
				size_t rlen;

				rlen = qsc_socket_peek(state->csock, hdr, MPDC_PACKET_HEADER_SIZE);

				if (rlen == MPDC_PACKET_HEADER_SIZE)
				{
					mpdc_packet_header_deserialize(hdr, &resp);
					mlen = resp.msglen + MPDC_PACKET_HEADER_SIZE;
					rbuf = (uint8_t*)qsc_memutils_malloc(mlen);

					if (rbuf != NULL)
					{
						/* wait for the reply */
						rlen = qsc_socket_receive(state->csock, rbuf, mlen, qsc_socket_receive_flag_wait_all);

						if (rlen >= NETWORK_FRAGMENT_COLLECTION_RESPONSE_PACKET_SIZE)
						{
							resp.pmessage = rbuf + MPDC_PACKET_HEADER_SIZE;

							/* derive the fragment hash key and store in state */
							merr = network_fragment_collection_request_derive(state, &resp);
						}
						else if (rlen == NETWORK_ERROR_PACKET_SIZE)
						{
							/* get the server error from the packet */
							merr = network_unpack_error(rbuf);
						}
						else
						{
							merr = mpdc_protocol_error_receive_failure;
						}

						qsc_memutils_alloc_free(rbuf);
					}
					else
					{
						merr = mpdc_protocol_error_memory_allocation;
					}
				}
				else
				{
					merr = mpdc_protocol_error_receive_failure;
				}
			}
			else
			{
				merr = mpdc_protocol_error_transmit_failure;
			}
		}
		else
		{
			merr = mpdc_protocol_error_connection_failure;
		}
	}
	else
	{
		merr = mpdc_protocol_error_invalid_request;
	}

	return merr;
}

/* MAS: Fkey Collection Response:
* The MAS sends a copy of the Client and MAS serial numbers, and unique tokens to the Agent.
* M(cser | ctok | mser | mtok)->A
* The Agent creates a key fragment and encrypts two copies, one with the Client's master fragment key,
* and one with the MAS mfk. The Agent Macs the ciphertext and sends it to the MAS.
* k1 = H(mfkm, serm, sera, tokm)
* k2 = H(mfkc, serc, sera, tokc)
* fkey = G()
* cpt = Ek1(fkey), Ek2(fkey)
* A(Mk(cpt))->M
*/

static mpdc_protocol_errors network_fragment_collection_query_request_packet(mpdc_network_packet* packetout, const mpdc_network_packet* packetin, const mpdc_network_fragment_query_request_state* state)
{
	MPDC_ASSERT(packetout != NULL);
	MPDC_ASSERT(packetin != NULL);
	MPDC_ASSERT(state != NULL);

	uint8_t mmfk[MPDC_CRYPTO_SYMMETRIC_KEY_SIZE] = { 0 };
	const uint8_t* cser;
	const uint8_t* ctok;
	size_t mpos;
	mpdc_protocol_errors merr;

	/* The mas creates a fragment request for an agent */

	merr = mpdc_protocol_error_none;

	if (qsc_collection_find(state->lmfk, mmfk, state->rnode->serial) == true)
	{
		mpdc_topology_node_state cnode = { 0 };

		network_header_create(packetout, mpdc_network_flag_fragment_query_request, NETWORK_FRAGMENT_QUERY_REQUEST_SEQUENCE, NETWORK_FRAGMENT_QUERY_REQUEST_MESSAGE_SIZE);

		cser = packetin->pmessage;
		ctok = packetin->pmessage + MPDC_CERTIFICATE_SERIAL_SIZE;

		if (mpdc_topology_node_find(state->list, &cnode, cser) == true)
		{
			uint8_t mkey[MPDC_CRYPTO_SYMMETRIC_KEY_SIZE] = { 0 };
			uint8_t mtok[MPDC_CRYPTO_SYMMETRIC_TOKEN_SIZE] = { 0 };
			uint8_t shdr[MPDC_PACKET_SUBHEADER_SIZE] = { 0 };

			/* copy the clients serial number and session token to the message */
			qsc_memutils_copy(packetout->pmessage, cnode.serial, MPDC_CERTIFICATE_SERIAL_SIZE);
			qsc_memutils_copy(packetout->pmessage + MPDC_CERTIFICATE_SERIAL_SIZE, ctok, MPDC_CRYPTO_SYMMETRIC_TOKEN_SIZE);
			mpos = NETWORK_FRAGMENT_COLLECTION_REQUEST_SIZE;
			/* copy the servers serial number and session token to the message */
			qsc_memutils_copy(packetout->pmessage + MPDC_CERTIFICATE_SERIAL_SIZE + MPDC_CRYPTO_SYMMETRIC_TOKEN_SIZE, state->lnode->serial, MPDC_CERTIFICATE_SERIAL_SIZE);
			qsc_memutils_copy(packetout->pmessage + MPDC_CERTIFICATE_SERIAL_SIZE + MPDC_CRYPTO_SYMMETRIC_TOKEN_SIZE + MPDC_CERTIFICATE_SERIAL_SIZE, state->token, MPDC_CRYPTO_SYMMETRIC_TOKEN_SIZE);
			mpos += NETWORK_FRAGMENT_COLLECTION_REQUEST_SIZE;

			/* use the hashed message to generate a unique token */
			qsc_shake256_compute(mtok, MPDC_CRYPTO_SYMMETRIC_KEY_SIZE, packetout->pmessage, NETWORK_FRAGMENT_COLLECTION_REQUEST_SIZE * 2);
			/* combine the client-mas mfkey, token, and certificate hashes to generate a mac key */
			network_derive_mkey(mkey, mmfk, state->rnode->chash, state->lnode->chash, mtok);

			/* mac the message and timestamp, and add the tag to the message */
			network_subheader_serialize(shdr, packetout);
			network_mac_message(packetout->pmessage + mpos, mkey, packetout->pmessage, NETWORK_FRAGMENT_COLLECTION_REQUEST_SIZE * 2, shdr);
		}
		else
		{
			merr = mpdc_protocol_error_node_not_found;
		}
	}
	else
	{
		merr = mpdc_protocol_error_key_unrecognized;
	}

	return merr;
}

static mpdc_protocol_errors network_fragment_collection_response_packet(mpdc_network_packet* packetout, const qsc_list_state* flist, const mpdc_network_fragment_collection_response_state* state)
{
	MPDC_ASSERT(packetout != NULL);
	MPDC_ASSERT(flist != NULL);
	MPDC_ASSERT(state != NULL);

	uint8_t mmfk[MPDC_CRYPTO_SYMMETRIC_KEY_SIZE] = { 0 };
	size_t mlen;
	size_t mpos;
	mpdc_protocol_errors merr;

	mlen = ((flist->count + 1) * NETWORK_FRAGMENT_QUERY_RESPONSE_SIZE) + MPDC_CRYPTO_SYMMETRIC_HASH_SIZE;
	network_header_create(packetout, mpdc_network_flag_fragment_collection_response, NETWORK_FRAGMENT_COLLECTION_RESPONSE_SEQUENCE, (uint32_t)mlen);

	/* get the client/mas mfk */
	if (qsc_collection_find(state->lmfk, mmfk, state->rnode->serial) == true)
	{
		uint8_t ckey[QSC_SHA3_512_HASH_SIZE] = { 0 };
		uint8_t shdr[MPDC_PACKET_SUBHEADER_SIZE] = { 0 };

		/* derive the client-mas fkey */
		network_derive_fkey(ckey, mmfk, state->rnode->chash, state->lnode->chash, state->ctok);
		/* encrypt the fragment */
		qsc_memutils_xor(ckey, state->frag, MPDC_CRYPTO_SYMMETRIC_KEY_SIZE);
		/* copy the serial number and  encrypted fragment to the message */
		qsc_memutils_copy(packetout->pmessage, state->lnode->serial, MPDC_CERTIFICATE_SERIAL_SIZE);
		qsc_memutils_copy(packetout->pmessage + MPDC_CERTIFICATE_SERIAL_SIZE, ckey, MPDC_CRYPTO_SYMMETRIC_KEY_SIZE);
		mpos = NETWORK_FRAGMENT_QUERY_RESPONSE_SIZE;

		/* copy the client encrypted fragment collection to the message */
		for (size_t i = 0; i < flist->count; ++i)
		{
			uint8_t item[NETWORK_FRAGMENT_QUERY_RESPONSE_SIZE] = { 0 };

			qsc_list_item(flist, item, i);
			qsc_memutils_copy(packetout->pmessage + mpos, item, NETWORK_FRAGMENT_QUERY_RESPONSE_SIZE);
			mpos += NETWORK_FRAGMENT_QUERY_RESPONSE_SIZE;
		}

		/* mac the ciphertexts */
		network_subheader_serialize(shdr, packetout);
		network_mac_message(packetout->pmessage + mpos, ckey + MPDC_CRYPTO_SYMMETRIC_KEY_SIZE, packetout->pmessage, mlen - MPDC_CRYPTO_SYMMETRIC_HASH_SIZE, shdr);
		merr = mpdc_protocol_error_none;
	}
	else
	{
		merr = mpdc_protocol_error_key_unrecognized;
	}

	return merr;
}

static mpdc_protocol_errors network_fragment_collection_request_verify(const mpdc_network_fragment_collection_response_state* state, const mpdc_network_packet* packetin)
{
	MPDC_ASSERT(state != NULL);
	MPDC_ASSERT(packetin != NULL);

	mpdc_protocol_errors merr;

	/* get the client/mas mfk */

	/* validate the incoming packet */
	merr = network_header_validate(packetin, mpdc_network_flag_fragment_collection_request, NETWORK_FRAGMENT_COLLECTION_REQUEST_SEQUENCE, NETWORK_FRAGMENT_COLLECTION_REQUEST_MESSAGE_SIZE);

	if (merr == mpdc_protocol_error_none)
	{
		uint8_t mmfk[MPDC_CRYPTO_SYMMETRIC_KEY_SIZE] = { 0 };

		/* generate an fkey, key the mac and verify the message and timestamp */
		if (qsc_collection_find(state->lmfk, mmfk, state->rnode->serial) == true)
		{
			uint8_t shdr[MPDC_PACKET_SUBHEADER_SIZE] = { 0 };
			uint8_t mkey[MPDC_CRYPTO_SYMMETRIC_KEY_SIZE] = { 0 };
			uint8_t mtag[MPDC_CRYPTO_SYMMETRIC_HASH_SIZE] = { 0 };
			uint8_t mtok[MPDC_CRYPTO_SYMMETRIC_TOKEN_SIZE] = { 0 };
			const uint8_t* ptag;

			ptag = packetin->pmessage + NETWORK_FRAGMENT_COLLECTION_REQUEST_SIZE;
			/* use the hashed message to generate a unique token */
			qsc_shake256_compute(mtok, MPDC_CRYPTO_SYMMETRIC_KEY_SIZE, packetin->pmessage, NETWORK_FRAGMENT_COLLECTION_REQUEST_SIZE);
			/* combine the client-mas mfkey, token, and certificate hashes to generate a mac key */
			network_derive_mkey(mkey, mmfk, state->lnode->chash, state->rnode->chash, mtok);

			/* mac the message and timestamp, and add the tag to the message */
			network_subheader_serialize(shdr, packetin);
			network_mac_message(mtag, mkey, packetin->pmessage, NETWORK_FRAGMENT_COLLECTION_REQUEST_SIZE, shdr);

			if (qsc_memutils_are_equal_256(ptag, mtag) == true)
			{
				merr = mpdc_protocol_error_none;
			}
			else
			{
				merr = mpdc_protocol_error_authentication_failure;
			}
		}
		else
		{
			merr = mpdc_protocol_error_key_unrecognized;
		}
	}

	return merr;
}

static mpdc_protocol_errors network_fragment_collection_response_derive(qsc_keccak_state* fkhs, const mpdc_network_fragment_collection_response_state* state, const mpdc_network_packet* packetin)
{
	MPDC_ASSERT(fkhs != NULL);
	MPDC_ASSERT(state != NULL);
	MPDC_ASSERT(packetin != NULL);

	mpdc_topology_node_state rnode = { 0 };
	const uint8_t* ctxt;
	const uint8_t* rser;
	mpdc_protocol_errors merr;

	rser = packetin->pmessage + NETWORK_FRAGMENT_QUERY_RESPONSE_SIZE;
	ctxt = packetin->pmessage + NETWORK_FRAGMENT_QUERY_RESPONSE_SIZE + MPDC_CERTIFICATE_SERIAL_SIZE;

	if (mpdc_topology_node_find(state->list, &rnode, rser) == true)
	{
		uint8_t amfk[MPDC_CRYPTO_SYMMETRIC_KEY_SIZE] = { 0 };

		if (qsc_collection_find(state->lmfk, amfk, rnode.serial) == true)
		{
			uint8_t fkey[QSC_SHA3_512_HASH_SIZE] = { 0 };
			uint8_t mtag[MPDC_CRYPTO_SYMMETRIC_HASH_SIZE] = { 0 };
			uint8_t shdr[MPDC_PACKET_SUBHEADER_SIZE] = { 0 };
			const uint8_t* ptag;

			/* derive the fkey */
			network_derive_fkey(fkey, amfk, state->lnode->chash, rnode.chash, state->mtok);

			/* mac the message */
			network_subheader_serialize(shdr, packetin);
			network_mac_message(mtag, fkey + MPDC_CRYPTO_SYMMETRIC_KEY_SIZE, packetin->pmessage, packetin->msglen - MPDC_CRYPTO_SYMMETRIC_HASH_SIZE, shdr);
			ptag = packetin->pmessage + (packetin->msglen - MPDC_CRYPTO_SYMMETRIC_HASH_SIZE);

			/* verify the mac, decrypt the fragment key, and add the fragment to the fkey hash */
			if (qsc_memutils_are_equal_256(mtag, ptag) == true)
			{
				/* decrypt the fragment */
				qsc_memutils_xor(fkey, ctxt, MPDC_CRYPTO_SYMMETRIC_KEY_SIZE);
				/* update the hkey hash with the key fragment */
				qsc_sha3_update(fkhs, qsc_keccak_rate_256, fkey, MPDC_CRYPTO_SYMMETRIC_KEY_SIZE);

				merr = mpdc_protocol_error_none;
			}
			else
			{
				/* abort; agent portion of exchange has failed */
				merr = mpdc_protocol_error_authentication_failure;
			}
		}
		else
		{
			/* abort; agent portion of exchange has failed */
			merr = mpdc_protocol_error_key_unrecognized;
		}
	}
	else
	{
		/* abort; agent portion of exchange has failed */
		merr = mpdc_protocol_error_node_not_found;
	}

	return merr;
}

mpdc_protocol_errors mpdc_network_fragment_collection_response(mpdc_network_fragment_collection_response_state* state, const mpdc_network_packet* packetin)
{
	MPDC_ASSERT(state != NULL);
	MPDC_ASSERT(packetin != NULL);

	mpdc_topology_list_state olst = { 0 };
	size_t ncnt;
	size_t mpos;
	mpdc_protocol_errors merr;

	if (state != NULL && packetin != NULL)
	{
		/* validate the collection request */
		merr = network_fragment_collection_request_verify(state, packetin);

		if (merr == mpdc_protocol_error_none)
		{
			qsc_keccak_state fkhs = { 0 };
			qsc_list_state clst = { 0 };

			/* copy the clients session token to state */
			qsc_memutils_copy(state->ctok, packetin->pmessage + MPDC_CERTIFICATE_SERIAL_SIZE, MPDC_CRYPTO_SYMMETRIC_TOKEN_SIZE);
			/* the device creates a sorted list of available agents on the network */
			ncnt = mpdc_topology_ordered_server_list(&olst, state->list, mpdc_network_designation_agent);

			/* initialize the client keychain */
			qsc_list_initialize(&clst, NETWORK_FRAGMENT_QUERY_RESPONSE_SIZE);

			/* generate the fragment and token */
			qsc_acp_generate(state->frag, MPDC_CRYPTO_SYMMETRIC_KEY_SIZE);
			qsc_acp_generate(state->mtok, MPDC_CRYPTO_SYMMETRIC_TOKEN_SIZE);

			/* update the servers key hash with the mas-client key fragment */
			qsc_sha3_initialize(&fkhs);
			qsc_sha3_update(&fkhs, qsc_keccak_rate_256, state->frag, MPDC_CRYPTO_SYMMETRIC_KEY_SIZE);
			mpos = 0;

			/* iterate through the list of agents, connect and collect fragments */
			for (size_t i = 0; i < olst.count; ++i)
			{
				mpdc_network_packet qreq = { 0 };
				mpdc_topology_node_state rnode = { 0 };
				uint8_t sbuf[NETWORK_FRAGMENT_QUERY_REQUEST_PACKET_SIZE] = { 0 };

				mpdc_topology_list_item(&olst, &rnode, i);

				/* create fragment query: cser|ctok, mser|mtok */
				const mpdc_network_fragment_query_request_state qrs = {
					.list = state->list,
					.lmfk = state->lmfk,
					.lnode = state->lnode,
					.rnode = &rnode,
					.token = state->mtok
				};

				/* create the fragment request packet */
				qreq.pmessage = sbuf + MPDC_PACKET_HEADER_SIZE;
				merr = network_fragment_collection_query_request_packet(&qreq, packetin, &qrs);
				mpdc_packet_header_serialize(&qreq, sbuf);

				if (merr == mpdc_protocol_error_none)
				{
					/* connect to the agent */
					qsc_socket csock = { 0 };

					if (mpdc_network_connect_to_device(&csock, rnode.address, mpdc_network_designation_agent) == qsc_socket_exception_success)
					{
						size_t slen;

						/* send the fragment request query */
						slen = qsc_socket_client_send(&csock, sbuf, NETWORK_FRAGMENT_QUERY_REQUEST_PACKET_SIZE, qsc_socket_send_flag_none);

						if (slen == NETWORK_FRAGMENT_QUERY_REQUEST_PACKET_SIZE)
						{
							uint8_t rbuf[NETWORK_FRAGMENT_QUERY_RESPONSE_PACKET_SIZE] = { 0 };
							size_t rlen;

							/* wait for the reply */
							rlen = qsc_socket_receive(&csock, rbuf, sizeof(rbuf), qsc_socket_receive_flag_wait_all);

							if (rlen == NETWORK_FRAGMENT_QUERY_RESPONSE_PACKET_SIZE)
							{
								mpdc_network_packet qrsp = { 0 };

								mpdc_packet_header_deserialize(rbuf, &qrsp);
								qrsp.pmessage = rbuf + MPDC_PACKET_HEADER_SIZE;

								/* process the agent message */
								merr = network_fragment_collection_response_derive(&fkhs, state, &qrsp);

								if (merr == mpdc_protocol_error_none)
								{
									/* copy the client portion to response message */
									qsc_list_add(&clst, qrsp.pmessage);
								}
								else
								{
									break;
								}
							}
							else if (rlen == NETWORK_ERROR_PACKET_SIZE)
							{
								/* get the server error from the packet */
								merr = network_unpack_error(rbuf);
							}
							else
							{
								merr = mpdc_protocol_error_receive_failure;
							}
						}

						mpdc_network_socket_dispose(&csock);
					}
					else
					{
						merr = mpdc_protocol_error_connect_failure;
					}
				}

				/* zero tolerance for agent failure */
				if (merr != mpdc_protocol_error_none)
				{
					break;
				}
			}

			if (merr == mpdc_protocol_error_none && clst.count > 0)
			{
				/* send response to client */
				mpdc_network_packet resp = { 0 };
				uint8_t* pbuf;
				size_t mlen;
				size_t slen;

				mlen = MPDC_PACKET_HEADER_SIZE + ((clst.count + 1) * NETWORK_FRAGMENT_QUERY_RESPONSE_SIZE) + MPDC_CRYPTO_SYMMETRIC_HASH_SIZE;
				pbuf = qsc_memutils_malloc(mlen + MPDC_PACKET_HEADER_SIZE);

				if (pbuf != NULL)
				{
					/* create the client fragment collection response packet */
					resp.pmessage = pbuf + MPDC_PACKET_HEADER_SIZE;
					merr = network_fragment_collection_response_packet(&resp, &clst, state);
					mpdc_packet_header_serialize(&resp, pbuf);

					if (merr == mpdc_protocol_error_none)
					{
						/* send the encrypted key bundle to the client */
						slen = qsc_socket_client_send(state->csock, pbuf, mlen, qsc_socket_send_flag_none);

						if (slen == mlen)
						{
#if defined(MPDC_EXTENDED_SESSION_SECURITY)
							/* create the fragment hash key and store in state */
							qsc_sha3_finalize(&fkhs, qsc_keccak_rate_512, state->hfkey);
#else
							/* create the fragment hash key and store in state */
							qsc_sha3_finalize(&fkhs, qsc_keccak_rate_256, state->hfkey);
#endif
							merr = mpdc_protocol_error_none;
						}
						else
						{
							merr = mpdc_protocol_error_transmit_failure;
						}
					}

					qsc_memutils_alloc_free(pbuf);
				}
				else
				{
					merr = mpdc_protocol_error_memory_allocation;
				}
			}

			qsc_list_dispose(&clst);
		}

#if defined(MPDC_NETWORK_MFK_HASH_CYCLED)
		if (merr == mpdc_protocol_error_none)
		{
			/* mas cycles mfk keys for agents and client here */
			network_hash_cycle_mfk(state->rnode->serial, state->lmfk);

			for (size_t i = 0; i < olst.count; ++i)
			{
				mpdc_topology_node_state rnode = { 0 };

				mpdc_topology_list_item(&olst, &rnode, i);
				network_hash_cycle_mfk(rnode.serial, state->lmfk);
			}
		}
#endif
	}
	else
	{
		merr = mpdc_protocol_error_invalid_request;
	}

	if (merr != mpdc_protocol_error_none)
	{
		mpdc_network_send_error(state->csock, merr);
	}

	return merr;
}

/* Agent: Fkey Query Response:
* The Agent generates a random fragment, encrypts two copies; one with the shared mas master fragmentation key,
* the other with the Client mfk; cptc = Ekc(frag), Ekm(frag)
* The Agent Macs both ciphertexts and sends them to the MAS.
* A(Mk(ccpt | mcpt))->M
*/

static mpdc_protocol_errors network_fragment_query_request_verify(const mpdc_network_fragment_query_response_state* state, const mpdc_network_packet* packetin)
{
	MPDC_ASSERT(state != NULL);
	MPDC_ASSERT(packetin != NULL);

	mpdc_protocol_errors merr;
	
	/* the agent generates the mkey and key the mac, verify the message and timestamp */

	merr = network_header_validate(packetin, mpdc_network_flag_fragment_query_request, NETWORK_FRAGMENT_QUERY_REQUEST_SEQUENCE, NETWORK_FRAGMENT_QUERY_REQUEST_MESSAGE_SIZE);

	if (merr == mpdc_protocol_error_none)
	{
		uint8_t mmfk[MPDC_CRYPTO_SYMMETRIC_KEY_SIZE] = { 0 };

		/* get the client/mas mfk */
		if (qsc_collection_find(state->lmfk, mmfk, state->rnode->serial) == true)
		{
			uint8_t mkey[MPDC_CRYPTO_SYMMETRIC_KEY_SIZE] = { 0 };
			uint8_t mtag[MPDC_CRYPTO_SYMMETRIC_HASH_SIZE] = { 0 };
			uint8_t mtok[MPDC_CRYPTO_SYMMETRIC_TOKEN_SIZE] = { 0 };
			uint8_t shdr[MPDC_PACKET_SUBHEADER_SIZE] = { 0 };

			const uint8_t* ptag = packetin->pmessage + NETWORK_FRAGMENT_COLLECTION_REQUEST_SIZE * 2;
			/* use the hashed message to generate a unique token */
			qsc_shake256_compute(mtok, MPDC_CRYPTO_SYMMETRIC_KEY_SIZE, packetin->pmessage, NETWORK_FRAGMENT_COLLECTION_REQUEST_SIZE * 2);
			/* combine the client-mas mfkey, token, and certificate hashes to generate a mac key */
			network_derive_mkey(mkey, mmfk, state->lnode->chash, state->rnode->chash, mtok);

			/* mac the message and timestamp, and add the tag to the message */
			network_subheader_serialize(shdr, packetin);
			network_mac_message(mtag, mkey, packetin->pmessage, NETWORK_FRAGMENT_COLLECTION_REQUEST_SIZE * 2, shdr);

			if (qsc_memutils_are_equal_256(ptag, mtag) == true)
			{
				merr = mpdc_protocol_error_none;
			}
			else
			{
				merr = mpdc_protocol_error_authentication_failure;
			}
		}
		else
		{
			merr = mpdc_protocol_error_key_unrecognized;
		}
	}

	return merr;
}

static mpdc_protocol_errors network_fragment_query_response_packet(mpdc_network_packet* packetout, const mpdc_network_packet* packetin, const mpdc_network_fragment_query_response_state* state)
{
	MPDC_ASSERT(packetout != NULL);
	MPDC_ASSERT(packetin != NULL);
	MPDC_ASSERT(state != NULL);

	mpdc_topology_node_state cnode = { 0 };
	mpdc_topology_node_state mnode = { 0 };
	const uint8_t* cser;
	const uint8_t* ctok;
	const uint8_t* mser;
	const uint8_t* mtok;
	mpdc_protocol_errors merr;

	/* the agent generates a fragment, encrypts a copy for the mas and another for the client, and macs the encrypted key-set */

	/* create the packet header */
	network_header_create(packetout, mpdc_network_flag_fragment_query_response, NETWORK_FRAGMENT_QUERY_RESPONSE_SEQUENCE, NETWORK_FRAGMENT_QUERY_RESPONSE_MESSAGE_SIZE);

	/* get pointers to the client and server serial numbers and session tokens */
	cser = packetin->pmessage;
	ctok = packetin->pmessage + MPDC_CERTIFICATE_SERIAL_SIZE;
	mser = packetin->pmessage + MPDC_CERTIFICATE_SERIAL_SIZE + MPDC_CRYPTO_SYMMETRIC_TOKEN_SIZE;
	mtok = packetin->pmessage + MPDC_CERTIFICATE_SERIAL_SIZE + MPDC_CRYPTO_SYMMETRIC_TOKEN_SIZE + MPDC_CERTIFICATE_SERIAL_SIZE;

	if (mpdc_topology_node_find(state->list, &cnode, cser) == true && 
		mpdc_topology_node_find(state->list, &mnode, mser) == true)
	{
		uint8_t cmfk[MPDC_CRYPTO_SYMMETRIC_KEY_SIZE] = { 0 };
		uint8_t mmfk[MPDC_CRYPTO_SYMMETRIC_KEY_SIZE] = { 0 };

		/* find the client and servers mfks */
		if (qsc_collection_find(state->lmfk, cmfk, cser) == true && 
			qsc_collection_find(state->lmfk, mmfk, mser) == true)
		{
			/* create the client portion of the message */
			uint8_t fkey[QSC_SHA3_512_HASH_SIZE] = { 0 };
			uint8_t frag[MPDC_CRYPTO_SYMMETRIC_KEY_SIZE] = { 0 };
			uint8_t shdr[MPDC_PACKET_SUBHEADER_SIZE] = { 0 };
			uint8_t* ptag;

			/* serialize the timestamp and sequence number for additional data */
			network_subheader_serialize(shdr, packetout);
				
			/* generate the random fragment */
			qsc_acp_generate(frag, MPDC_CRYPTO_SYMMETRIC_KEY_SIZE);

			/* derive the client fragment encryption key */
			network_derive_fkey(fkey, cmfk, cnode.chash, state->lnode->chash, ctok);

			/* encrypt the client fragment key, and copy the agent serial number and cipher-text to the message */
			qsc_memutils_xor(fkey, frag, MPDC_CRYPTO_SYMMETRIC_KEY_SIZE);
			qsc_memutils_copy(packetout->pmessage, state->lnode->serial, MPDC_CERTIFICATE_SERIAL_SIZE);
			qsc_memutils_copy(packetout->pmessage + MPDC_CERTIFICATE_SERIAL_SIZE, fkey, MPDC_CRYPTO_SYMMETRIC_KEY_SIZE);

			/* create the server portion of the message */

			qsc_memutils_clear(fkey, sizeof(fkey));

			/* derive the mas fragment encryption key */
			network_derive_fkey(fkey, mmfk, mnode.chash, state->lnode->chash, mtok);

			/* encrypt the server fragment key and copy the serial number and cipher-text to the message */
			qsc_memutils_xor(fkey, frag, MPDC_CRYPTO_SYMMETRIC_KEY_SIZE);
			qsc_memutils_copy(packetout->pmessage + MPDC_CERTIFICATE_SERIAL_SIZE + MPDC_CRYPTO_SYMMETRIC_KEY_SIZE, state->lnode->serial, MPDC_CERTIFICATE_SERIAL_SIZE);
			qsc_memutils_copy(packetout->pmessage + MPDC_CERTIFICATE_SERIAL_SIZE + MPDC_CRYPTO_SYMMETRIC_KEY_SIZE + MPDC_CERTIFICATE_SERIAL_SIZE, fkey, MPDC_CRYPTO_SYMMETRIC_KEY_SIZE);
				
			/* mac the encrypted fragment keys and serial number with the packet header data */
			ptag = packetout->pmessage + (packetout->msglen - MPDC_CRYPTO_SYMMETRIC_HASH_SIZE);
			network_mac_message(ptag, fkey + MPDC_CRYPTO_SYMMETRIC_KEY_SIZE, packetout->pmessage, packetout->msglen - MPDC_CRYPTO_SYMMETRIC_HASH_SIZE, shdr);
		
#if defined(MPDC_NETWORK_MFK_HASH_CYCLED)
			/* agent cycles mfk here for client and mas */
			network_hash_cycle_mfk(cnode.serial, state->lmfk);
			network_hash_cycle_mfk(mnode.serial, state->lmfk);
#endif
			merr = mpdc_protocol_error_none;
		}
		else
		{
			merr = mpdc_protocol_error_key_unrecognized;
		}
	}
	else
	{
		merr = mpdc_protocol_error_node_not_found;
	}

	return merr;
}

mpdc_protocol_errors mpdc_network_fragment_query_response(const mpdc_network_fragment_query_response_state* state, const mpdc_network_packet* packetin)
{
	MPDC_ASSERT(state != NULL);
	MPDC_ASSERT(packetin != NULL);

	size_t slen;
	mpdc_protocol_errors merr;

	if (state != NULL && packetin != NULL)
	{
		mpdc_network_packet resp = { 0 };
		uint8_t sbuf[NETWORK_FRAGMENT_QUERY_RESPONSE_PACKET_SIZE] = { 0 };

		/* verify the fragment query sent by the mas */
		merr = network_fragment_query_request_verify(state, packetin);

		if (merr == mpdc_protocol_error_none)
		{
			/* create the packet header */
			resp.pmessage = sbuf + MPDC_PACKET_HEADER_SIZE;
			merr = network_fragment_query_response_packet(&resp, packetin, state);

			if (merr == mpdc_protocol_error_none)
			{
				mpdc_packet_header_serialize(&resp, sbuf);

				slen = qsc_socket_client_send(state->csock, sbuf, NETWORK_FRAGMENT_QUERY_RESPONSE_PACKET_SIZE, qsc_socket_send_flag_none);

				if (slen == NETWORK_FRAGMENT_QUERY_RESPONSE_PACKET_SIZE)
				{
					merr = mpdc_protocol_error_none;
				}
				else
				{
					merr = mpdc_protocol_error_transmit_failure;
				}
			}
		}
	}
	else
	{
		merr = mpdc_protocol_error_invalid_request;
	}

	if (merr != mpdc_protocol_error_none)
	{
		mpdc_network_send_error(state->csock, merr);
	}
	return merr;
}

/* Incremental Update Request: 
* Request a public certificate from a device.
* The requestor sends the serial number of the devices certificate, 
* and the responder sends back the signed certificate.
* The requestor deserializes the certificate, checks the Root signature and verifies the certificate.
* The requestor uses the certificate to verify the message hash.
* rcert = (Vroot(rcert), Vrcert(H(ts | rcert)))
* If the certificate is verified it is stored in the local cache.
*/

static void network_incremental_update_request_packet(mpdc_network_packet* packetout, const mpdc_network_incremental_update_request_state* state)
{
	MPDC_ASSERT(packetout != NULL);
	MPDC_ASSERT(state != NULL);

	/* create the packet header */
	network_header_create(packetout, mpdc_network_flag_incremental_update_request, NETWORK_INCREMENTAL_UPDATE_REQUEST_SEQUENCE, NETWORK_INCREMENTAL_UPDATE_REQUEST_MESSAGE_SIZE);

	qsc_memutils_copy(packetout->pmessage, state->rnode->serial, MPDC_CERTIFICATE_SERIAL_SIZE);
}

static mpdc_protocol_errors network_incremental_update_verify(const mpdc_network_incremental_update_request_state* state, const mpdc_network_packet* packetin)
{
	MPDC_ASSERT(state != NULL);
	MPDC_ASSERT(packetin != NULL);

	mpdc_protocol_errors merr;

	/* check the packet parameters */
	merr = network_header_validate(packetin, mpdc_network_flag_incremental_update_response, NETWORK_INCREMENTAL_UPDATE_RESPONSE_SEQUENCE, NETWORK_INCREMENTAL_UPDATE_RESPONSE_MESSAGE_SIZE);

	if (merr == mpdc_protocol_error_none)
	{
		mpdc_child_certificate ccert = { 0 };

		/* temp copy of inbound certificate */
		mpdc_certificate_child_deserialize(&ccert, packetin->pmessage + MPDC_PACKET_SUBHEADER_SIZE);

		/* verify the certificate signature */
		merr = network_certificate_signed_hash_verify(state->rcert, packetin, &ccert, state->root);
	}

	return merr;
}

mpdc_protocol_errors mpdc_network_incremental_update_request(const mpdc_network_incremental_update_request_state* state)
{
	MPDC_ASSERT(state != NULL);
	
	size_t slen;
	mpdc_protocol_errors merr;

	if (state != NULL)
	{
		qsc_socket csock = { 0 };
		mpdc_network_packet reqt = { 0 };
		uint8_t sbuf[NETWORK_INCREMENTAL_UPDATE_REQUEST_PACKET_SIZE] = { 0 };

		if (mpdc_network_connect_to_device(&csock, state->rnode->address, state->rnode->designation) == qsc_socket_exception_success)
		{
			/* create the packet header */
			reqt.pmessage = sbuf + MPDC_PACKET_HEADER_SIZE;
			network_incremental_update_request_packet(&reqt, state);
			mpdc_packet_header_serialize(&reqt, sbuf);

			slen = qsc_socket_client_send(&csock, sbuf, NETWORK_INCREMENTAL_UPDATE_REQUEST_PACKET_SIZE, qsc_socket_send_flag_none);

			if (slen == NETWORK_INCREMENTAL_UPDATE_REQUEST_PACKET_SIZE)
			{
				uint8_t rbuf[NETWORK_INCREMENTAL_UPDATE_RESPONSE_PACKET_SIZE] = { 0 };
				mpdc_network_packet resp = { 0 };
				size_t rlen;

				/* wait for the reply */
				rlen = qsc_socket_receive(&csock, rbuf, sizeof(rbuf), qsc_socket_receive_flag_wait_all);

				if (rlen == NETWORK_INCREMENTAL_UPDATE_RESPONSE_PACKET_SIZE)
				{
					mpdc_packet_header_deserialize(rbuf, &resp);
					resp.pmessage = rbuf + MPDC_PACKET_HEADER_SIZE;

					/* verify the certificate update */
					merr = network_incremental_update_verify(state, &resp);
				}
				else if (rlen == NETWORK_ERROR_PACKET_SIZE)
				{
					/* get the server error from the packet */
					merr = network_unpack_error(rbuf);
				}
				else
				{
					merr = mpdc_protocol_error_receive_failure;
				}
			}
			else
			{
				merr = mpdc_protocol_error_transmit_failure;
			}

			mpdc_network_socket_dispose(&csock);
		}
		else
		{
			merr = mpdc_protocol_error_connection_failure;
		}
	}
	else
	{
		merr = mpdc_protocol_error_invalid_request;
	}

	return merr;
}

/* Incremental Update Response: 
* The device has received a request for its public certificate. 
* The local certificate is serialized and added to the message,
* the message is hashed and signed and sent back to the requestor.
* sig = Sign(H(ts | lcert))
* B(lcert | sig)->A
*/

static mpdc_protocol_errors network_incremental_update_response_packet(mpdc_network_packet* packetout, const mpdc_network_packet* packetin, const mpdc_network_incremental_update_response_state* state)
{
	MPDC_ASSERT(packetout != NULL);
	MPDC_ASSERT(packetin != NULL);
	MPDC_ASSERT(state != NULL);

	mpdc_protocol_errors merr;

	if (qsc_memutils_are_equal(packetin->pmessage, state->rcert->serial, MPDC_CERTIFICATE_SERIAL_SIZE) == true)
	{
		/* create the packet header */
		network_header_create(packetout, mpdc_network_flag_incremental_update_response, NETWORK_INCREMENTAL_UPDATE_RESPONSE_SEQUENCE, NETWORK_INCREMENTAL_UPDATE_RESPONSE_MESSAGE_SIZE);

		/* add time-stamp and certificate to message, hash, sign the hash, and add the signature to the message */
		merr = network_certificate_hash_sign(packetout, state->sigkey, state->rcert);
	}
	else
	{
		merr = mpdc_protocol_error_invalid_request;
	}

	return merr;
}

mpdc_protocol_errors mpdc_network_incremental_update_response(const mpdc_network_incremental_update_response_state* state, const mpdc_network_packet* packetin)
{
	MPDC_ASSERT(state != NULL);
	MPDC_ASSERT(packetin != NULL);

	mpdc_protocol_errors merr;

	if (state != NULL && packetin != NULL)
	{
		mpdc_network_packet resp = { 0 };
		uint8_t sbuf[NETWORK_INCREMENTAL_UPDATE_RESPONSE_PACKET_SIZE] = { 0 };

		resp.pmessage = sbuf + MPDC_PACKET_HEADER_SIZE;

		/* create the update response packet */
		merr = network_incremental_update_response_packet(&resp, packetin, state);

		if (merr == mpdc_protocol_error_none)
		{
			size_t mlen;

			mpdc_packet_header_serialize(&resp, sbuf);

			/* send the response to the requestor */
			mlen = qsc_socket_client_send(state->csock, sbuf, NETWORK_INCREMENTAL_UPDATE_RESPONSE_PACKET_SIZE, qsc_socket_send_flag_none);

			if (mlen == NETWORK_INCREMENTAL_UPDATE_RESPONSE_PACKET_SIZE)
			{
				merr = mpdc_protocol_error_none;
			}
			else
			{
				merr = mpdc_protocol_error_transmit_failure;
			}
		}
	}
	else
	{
		merr = mpdc_protocol_error_invalid_request;
	}

	/* notify of failure with error message */
	if (merr != mpdc_protocol_error_none)
	{
		mpdc_network_send_error(state->csock, merr);
	}

	return merr;
}

/* MFK Exchange Request: 
* The MAS/Client sends the remote agent its root-signed certificate.
* This certificate is serialized and added to the message, and used to verify the packet time-stamp and certificate hash on the Agent.
* M(lcert | Sign(H(ts | lcert)))->A
* The MAS/Client receive a signed asymmetric public cipher key and time-stamp. The message is verified,
* and the public cipher key is used to encapsulate a shared secret.
* Vrcert(H(ts | pk))
* cpt = Epk(mfk)
* M(cpt | Sign(H(cpt))->A
*/

static mpdc_protocol_errors network_mfk_request_packet(mpdc_network_packet* packetout, const mpdc_network_mfk_request_state* state)
{
	MPDC_ASSERT(packetout != NULL);
	MPDC_ASSERT(state != NULL);

	mpdc_protocol_errors merr;

	/* the server sends the remote agents certificate serial number and its serialized certificate */

	/* create the mfk request header */
	network_header_create(packetout, mpdc_network_flag_mfk_request, NETWORK_MFK_REQUEST_SEQUENCE, NETWORK_MFK_REQUEST_MESSAGE_SIZE);

	/* add time-stamp and certificate to message, hash, sign the hash, and add the signature to the message */
	merr = network_certificate_hash_sign(packetout, state->sigkey, state->lcert);

	return merr;
}

static mpdc_protocol_errors network_mfk_establish_packet(mpdc_network_packet* packetout, const mpdc_network_packet* packetin, mpdc_network_mfk_request_state* state)
{
	MPDC_ASSERT(packetout != NULL);
	MPDC_ASSERT(packetin != NULL);
	MPDC_ASSERT(state != NULL);

	mpdc_protocol_errors merr;

	/* The server verifies the signature hash of the cipher public key, generates the cipher-text and stores the key.
	   The server signs the ciphertext hash and adds the signature and cipher-text to the message */

	/* check packet parameters */
	merr = network_header_validate(packetin, mpdc_network_flag_mfk_response, NETWORK_MFK_RESPONSE_SEQUENCE, NETWORK_MFK_RESPONSE_MESSAGE_SIZE);
	
	if (merr == mpdc_protocol_error_none)
	{
		uint8_t pbk[MPDC_ASYMMETRIC_PUBLIC_KEY_SIZE] = { 0 };

		merr = network_message_signed_hash_verify(pbk, packetin, state->rcert);

		if (merr == mpdc_protocol_error_none)
		{
			uint8_t cpt[MPDC_ASYMMETRIC_CIPHERTEXT_SIZE] = { 0 };

			/* create the mfk establish packet */
			network_header_create(packetout, mpdc_network_flag_mfk_establish, NETWORK_MFK_ESTABLISH_SEQUENCE, NETWORK_MFK_ESTABLISH_MESSAGE_SIZE);

			/* create the shared secret and cipher-text */
			mpdc_cipher_encapsulate(state->mfk, cpt, pbk, qsc_acp_generate);

			/* hash the message and sign the hash */
			merr = network_message_hash_sign(packetout, state->sigkey, cpt, MPDC_ASYMMETRIC_CIPHERTEXT_SIZE);
		}
		else
		{
			merr = mpdc_protocol_error_authentication_failure;
		}
	}

	return merr;
}

mpdc_protocol_errors mpdc_network_mfk_exchange_request(mpdc_network_mfk_request_state* state)
{
	MPDC_ASSERT(state != NULL);
	
	qsc_socket csock = { 0 };
	mpdc_network_packet reqt = { 0 };
	uint8_t sbuf[NETWORK_MFK_REQUEST_PACKET_SIZE] = { 0 };
	size_t rlen;
	size_t slen;
	mpdc_protocol_errors merr;

	if (state != NULL)
	{
		if (mpdc_network_connect_to_device(&csock, state->rnode->address, state->rnode->designation) == qsc_socket_exception_success)
		{
			/* create the mfk request packet */
			reqt.pmessage = sbuf + MPDC_PACKET_HEADER_SIZE;
			network_mfk_request_packet(&reqt, state);
			mpdc_packet_header_serialize(&reqt, sbuf);

			/* send the mfk request */
			slen = qsc_socket_send(&csock, sbuf, NETWORK_MFK_REQUEST_PACKET_SIZE, qsc_socket_send_flag_none);

			if (slen == NETWORK_MFK_REQUEST_PACKET_SIZE)
			{
				/* allocate the receive buffer */
				uint8_t rbuf[NETWORK_MFK_RESPONSE_PACKET_SIZE] = { 0 };

				/* receive the mfk response packet */
				rlen = qsc_socket_receive(&csock, rbuf, sizeof(rbuf), qsc_socket_receive_flag_wait_all);

				if (rlen == NETWORK_MFK_RESPONSE_PACKET_SIZE)
				{
					mpdc_network_packet resp = { 0 };
					uint8_t ebuf[NETWORK_MFK_ESTABLISH_PACKET_SIZE] = { 0 };

					reqt.pmessage = ebuf + MPDC_PACKET_HEADER_SIZE;

					mpdc_packet_header_deserialize(rbuf, &resp);
					resp.pmessage = rbuf + MPDC_PACKET_HEADER_SIZE;

					/* create the mfk establish packet */
					merr = network_mfk_establish_packet(&reqt, &resp, state);

					if (merr == mpdc_protocol_error_none)
					{
						mpdc_packet_header_serialize(&reqt, ebuf);

						/* send the establish message */
						slen = qsc_socket_send(&csock, ebuf, NETWORK_MFK_ESTABLISH_PACKET_SIZE, qsc_socket_send_flag_none);

						if (slen == NETWORK_MFK_ESTABLISH_PACKET_SIZE)
						{
							merr = mpdc_protocol_error_none;
						}
						else
						{
							merr = mpdc_protocol_error_transmit_failure;
						}
					}
				}
				else if (rlen == NETWORK_ERROR_PACKET_SIZE)
				{
					/* get the server error from the packet */
					merr = network_unpack_error(rbuf);
				}
				else
				{
					merr = mpdc_protocol_error_receive_failure;
				}
			}
			else
			{
				merr = mpdc_protocol_error_transmit_failure;
			}

			mpdc_network_socket_dispose(&csock);
		}
		else
		{
			merr = mpdc_protocol_error_connection_failure;
		}
	}
	else
	{
		merr = mpdc_protocol_error_invalid_request;
	}

	return merr;
}

/* MFK Exchange Response: 
* The Agent validates the requestors certificate Root signature, and uses the certificate to verify the message signature and time-stamp.
* rcert = Vroot(rcert), Vrcert(ts | msg)
* The Agent generates an asymmetric cipher key-pair, adds the public key to the message, hashes the key and timestamp,
* and signs the hash.
* pk,sk = G()
* A(ts | pk | Sign(H(ts | pk)))->M
* The Agent receives the signed cipher-text, verifies the hash signature, and decrypts the shared secret.
* Vrcert(H(ts | cpt)),
* mfk = Dsk(cpt)
*/

static mpdc_protocol_errors network_mfk_response_packet(mpdc_network_packet* packetout, const mpdc_network_packet* packetin, mpdc_network_mfk_response_state* state)
{
	MPDC_ASSERT(packetout != NULL);
	MPDC_ASSERT(packetin != NULL);
	MPDC_ASSERT(state != NULL);

	mpdc_protocol_errors merr;

	/* check the packet parameters */
	merr = network_header_validate(packetin, mpdc_network_flag_mfk_request, NETWORK_MFK_REQUEST_SEQUENCE, NETWORK_MFK_REQUEST_MESSAGE_SIZE);

	if (merr == mpdc_protocol_error_none)
	{
		mpdc_child_certificate ccert = { 0 };

		/* temp copy of inbound certificate */
		mpdc_certificate_child_deserialize(&ccert, packetin->pmessage + MPDC_PACKET_SUBHEADER_SIZE);

		/* verify the certificate signature */
		merr = network_certificate_signed_hash_verify(state->rcert, packetin, &ccert, state->root);

		/* the agent verifies the certificate */
		if (merr == mpdc_protocol_error_none)
		{
			/* The device generates a cipher key-pair, copies the public key to the packet,
				hashes the public key, signs the hash, and adds it to the message */

			/* create the packet header */
			network_header_create(packetout, mpdc_network_flag_mfk_response, NETWORK_MFK_RESPONSE_SEQUENCE, NETWORK_MFK_RESPONSE_MESSAGE_SIZE);

			/* initialize the asymmetric cipher keys */
			qsc_memutils_clear(state->ckp.pubkey, MPDC_ASYMMETRIC_PUBLIC_KEY_SIZE);
			qsc_memutils_clear(state->ckp.prikey, MPDC_ASYMMETRIC_PRIVATE_KEY_SIZE);

			/* generate the asymmetric keypair and copy the public encapsulation key to the message */
			mpdc_cipher_generate_keypair(state->ckp.pubkey, state->ckp.prikey, qsc_acp_generate);

			/* add the public key and timestamp to the message, then hash the message, sign the hash, and append the signature */
			merr = network_message_hash_sign(packetout, state->sigkey, state->ckp.pubkey, MPDC_ASYMMETRIC_PUBLIC_KEY_SIZE);
		}
		else
		{
			merr = mpdc_protocol_error_authentication_failure;
		}
	}

	return merr;
}

static mpdc_protocol_errors network_mfk_verify_packet(const mpdc_network_packet* packetin, mpdc_network_mfk_response_state* state)
{
	MPDC_ASSERT(packetin != NULL);
	MPDC_ASSERT(state != NULL);

	mpdc_protocol_errors merr;

	/* The agent verifies the cipher-text using the server's certificate, 
	 * and decapsulates the master fragment key */

	/* vaidate the packet header */
	merr = network_header_validate(packetin, mpdc_network_flag_mfk_establish, NETWORK_MFK_ESTABLISH_SEQUENCE, NETWORK_MFK_ESTABLISH_MESSAGE_SIZE);

	if (merr == mpdc_protocol_error_none)
	{
		uint8_t cpt[MPDC_ASYMMETRIC_CIPHERTEXT_SIZE] = { 0 };

		merr = network_message_signed_hash_verify(cpt, packetin, state->rcert);

		if (merr == mpdc_protocol_error_none)
		{
			if (mpdc_cipher_decapsulate(state->mfk, cpt, state->ckp.prikey) == true)
			{
				merr = mpdc_protocol_error_none;
			}
			else
			{
				merr = mpdc_protocol_error_decapsulation_failure;
			}
		}
	}

	return merr;
}

mpdc_protocol_errors mpdc_network_mfk_exchange_response(mpdc_network_mfk_response_state* state, const mpdc_network_packet* packetin)
{
	MPDC_ASSERT(state != NULL);
	MPDC_ASSERT(packetin != NULL);

	size_t rlen;
	size_t slen;
	mpdc_protocol_errors merr;

	if (state != NULL && packetin != NULL)
	{
		mpdc_network_packet resp = { 0 };
		uint8_t sbuf[NETWORK_MFK_RESPONSE_PACKET_SIZE] = { 0 };

		resp.pmessage = sbuf + MPDC_PACKET_HEADER_SIZE;

		/* create the mfk response packet */
		merr = network_mfk_response_packet(&resp, packetin, state);

		/* serialize the header */
		mpdc_packet_header_serialize(&resp, sbuf);

		/* send the establish message */
		slen = qsc_socket_send(state->csock, sbuf, NETWORK_MFK_RESPONSE_PACKET_SIZE, qsc_socket_send_flag_none);

		if (slen == NETWORK_MFK_RESPONSE_PACKET_SIZE)
		{
			/* allocate the receive buffer */
			uint8_t rbuf[NETWORK_MFK_ESTABLISH_PACKET_SIZE] = { 0 };

			/* receive the establish packet */
			rlen = qsc_socket_receive(state->csock, rbuf, sizeof(rbuf), qsc_socket_receive_flag_wait_all);

			if (rlen == NETWORK_MFK_ESTABLISH_PACKET_SIZE)
			{
				mpdc_network_packet rest = { 0 };

				mpdc_packet_header_deserialize(rbuf, &rest);
				rest.pmessage = rbuf + MPDC_PACKET_HEADER_SIZE;

				/* verify the ciphertext and decapsulate the shared secret */
				merr = network_mfk_verify_packet(&rest, state);
			}
			else if (rlen == NETWORK_ERROR_PACKET_SIZE)
			{
				/* get the server error from the packet */
				merr = network_unpack_error(rbuf);
			}
			else
			{
				merr = mpdc_protocol_error_receive_failure;
			}
		}
		else
		{
			merr = mpdc_protocol_error_transmit_failure;
		}
	}
	else
	{
		merr = mpdc_protocol_error_invalid_request;
	}

	/* notify of failure with error message */
	if (merr != mpdc_protocol_error_none)
	{
		mpdc_network_send_error(state->csock, merr);
	}
	return merr;
}

/* Network Join Request:
* When an Agent joins the network, it sends a copy of its certificate, signed by the Root. 
* This certificate is serialized and added to the message, and used to verify the packet time-stamp and certificate hash on the DLA.
* sig = Sign(H(ts | lcert))
* A(lcert | sig)->D
* The Agent receives the signed DLA certificate, verifies the certificates Root signature, and then uses the certificate 
* to verify the message and time-stamp.
* rcert = Vroot(rcert), Vrcert(ts | rcert)
*/

static mpdc_protocol_errors network_register_request_packet(mpdc_network_packet* packetout, const mpdc_network_register_request_state* state)
{
	MPDC_ASSERT(packetout != NULL);
	MPDC_ASSERT(state != NULL);

	mpdc_protocol_errors merr;

	/* create the packet header */
	network_header_create(packetout, mpdc_network_flag_register_request, NETWORK_JOIN_REQUEST_SEQUENCE, NETWORK_JOIN_REQUEST_MESSAGE_SIZE);

	/* add time-stamp and certificate to message, hash, sign the hash, and add the signature to the message */
	merr = network_certificate_hash_sign(packetout, state->sigkey, state->lcert);
	
	return merr;
}

static mpdc_protocol_errors network_register_verify(mpdc_network_register_request_state* state, const mpdc_network_packet* packetin)
{
	MPDC_ASSERT(state != NULL);
	MPDC_ASSERT(packetin != NULL);

	mpdc_protocol_errors merr;

	merr = network_header_validate(packetin, mpdc_network_flag_register_response, NETWORK_JOIN_RESPONSE_SEQUENCE, NETWORK_JOIN_RESPONSE_MESSAGE_SIZE);

	if (merr == mpdc_protocol_error_none)
	{
		mpdc_child_certificate ccert = { 0 };

		/* temp copy of inbound certificate */
		mpdc_certificate_child_deserialize(&ccert, packetin->pmessage + MPDC_PACKET_SUBHEADER_SIZE);

		/* verify the certificate signature */
		merr = network_certificate_signed_hash_verify(state->rcert, packetin, &ccert, state->root);
	}

	return merr;
}

mpdc_protocol_errors mpdc_network_register_request(mpdc_network_register_request_state* state)
{
	MPDC_ASSERT(state != NULL);
	
	/* Send an agent network join request to the DLA.
	   The message is the callers root-signed certificate. */

	qsc_socket csock = { 0 };
	mpdc_protocol_errors merr;

	if (state != NULL)
	{
		if (mpdc_network_connect_to_device(&csock, state->address, mpdc_network_designation_dla) == qsc_socket_exception_success)
		{
			mpdc_network_packet reqt = { 0 };
			uint8_t sbuf[NETWORK_JOIN_REQUEST_PACKET_SIZE] = { 0 };
			size_t mlen;

			/* create the join request packet */
			reqt.pmessage = sbuf + MPDC_PACKET_HEADER_SIZE;
			network_register_request_packet(&reqt, state);
			mpdc_packet_header_serialize(&reqt, sbuf);

			/* send the join request to the dla */
			mlen = qsc_socket_client_send(&csock, sbuf, NETWORK_JOIN_REQUEST_PACKET_SIZE, qsc_socket_send_flag_none);

			if (mlen == NETWORK_JOIN_REQUEST_PACKET_SIZE)
			{
				uint8_t rbuf[NETWORK_JOIN_RESPONSE_PACKET_SIZE] = { 0 };
				mpdc_network_packet resp = { 0 };
				size_t rlen;

				/* wait for the reply */
				rlen = qsc_socket_receive(&csock, rbuf, sizeof(rbuf), qsc_socket_receive_flag_wait_all);
				resp.pmessage = rbuf + MPDC_PACKET_HEADER_SIZE;

				if (rlen == NETWORK_JOIN_RESPONSE_PACKET_SIZE)
				{
					/* deseialize the response packet */
					mpdc_packet_header_deserialize(rbuf, &resp);

					/* verify the response packet */
					merr = network_register_verify(state, &resp);
				}
				else if (rlen == NETWORK_ERROR_PACKET_SIZE)
				{
					/* get the server error from the packet */
					merr = network_unpack_error(rbuf);
				}
				else
				{
					merr = mpdc_protocol_error_receive_failure;
				}
			}
			else
			{
				merr = mpdc_protocol_error_transmit_failure;
			}

			mpdc_network_socket_dispose(&csock);
		}
		else
		{
			merr = mpdc_protocol_error_connection_failure;
		}
	}
	else
	{
		merr = mpdc_protocol_error_invalid_request;
	}

	return merr;
}

/* Network Join Response: 
* The DLA verifies the agents certificate, then sends a copy of its own root-signed certificate, and adds the device to the topology.
* rcert = Vroot(rcert), Vrcert(ts | rcert)
* D(lcert | Sign(H(ts | lcert)))->A
*/

static mpdc_protocol_errors network_register_response_packet(mpdc_network_packet* packetout, mpdc_network_register_response_state* state, const mpdc_network_packet* packetin)
{
	MPDC_ASSERT(packetout != NULL);
	MPDC_ASSERT(state != NULL);
	MPDC_ASSERT(packetin != NULL);

	mpdc_protocol_errors merr;

	/* validate the packet header */
	merr = network_header_validate(packetin, mpdc_network_flag_register_request, NETWORK_JOIN_REQUEST_SEQUENCE, NETWORK_JOIN_REQUEST_MESSAGE_SIZE);

	/* inspect the request packet parameters */
	if (merr == mpdc_protocol_error_none)
	{
		mpdc_child_certificate ccert = { 0 };

		/* temp copy of inbound certificate */
		mpdc_certificate_child_deserialize(&ccert, packetin->pmessage + MPDC_PACKET_SUBHEADER_SIZE);

		/* verify the root certificate signature */
		merr = network_certificate_signed_hash_verify(state->rcert, packetin, &ccert, state->root);

		if (merr == mpdc_protocol_error_none)
		{
			/* create the packet header */
			network_header_create(packetout, mpdc_network_flag_register_response, NETWORK_JOIN_RESPONSE_SEQUENCE, NETWORK_JOIN_RESPONSE_MESSAGE_SIZE);

			/* add time-stamp and certificate to message, hash, sign the hash, and add the signature to the message */
			merr = network_certificate_hash_sign(packetout, state->sigkey, state->lcert);
		}
	}

	return merr;
}

mpdc_protocol_errors mpdc_network_register_response(mpdc_network_register_response_state* state, const mpdc_network_packet* packetin)
{
	MPDC_ASSERT(state != NULL);
	MPDC_ASSERT(packetin != NULL);

	/* The DLA network join response.
	   When the requests comes from an agent, the DLA verifies the root signature of the agent,
	   and sends its own certificate in the response. */

	size_t slen;
	mpdc_protocol_errors merr;

	if (state != NULL && packetin != NULL)
	{
		mpdc_network_packet resp = { 0 };
		uint8_t sbuf[NETWORK_JOIN_RESPONSE_PACKET_SIZE] = { 0 };

		/* agents are sent only the root-signed dla certificate */
		resp.pmessage = sbuf + MPDC_PACKET_HEADER_SIZE;
		merr = network_register_response_packet(&resp, state, packetin);

		if (merr == mpdc_protocol_error_none)
		{
			mpdc_packet_header_serialize(&resp, sbuf);

			slen = qsc_socket_client_send(state->csock, sbuf, NETWORK_JOIN_RESPONSE_PACKET_SIZE, qsc_socket_send_flag_none);

			if (slen == NETWORK_JOIN_RESPONSE_PACKET_SIZE)
			{
				merr = mpdc_protocol_error_none;
			}
			else
			{
				merr = mpdc_protocol_error_transmit_failure;
			}
		}
	}
	else
	{
		merr = mpdc_protocol_error_invalid_request;
	}

	/* notify of failure with error message */
	if (merr != mpdc_protocol_error_none)
	{
		mpdc_network_send_error(state->csock, merr);
	}

	return merr;
}

/* Network Join Update Request: 
* When an MAS or Client joins the network, it sends a copy of its certificate, signed by the Root.
* This certificate is serialized and added to the message, and used to verify the packet time-stamp and certificate hash on the DLA.
* A(lcert | Sign(H(ts | lcert)))->D
* The MAS/Client verifies the DLA certificate, stores the certificate and adds the DLA to the topology.
* It also receives an update, containing a list of serialized Agent nodes, which it uses
* to contact each Agent and request a certificate copy.
* The update message and a time-stamp are hashed, and the hash is signed.
* msg = Vroot(rcert), Vrcert(ts | msg)
* topology Add(msg)
*/

static mpdc_protocol_errors network_register_update_request_packet(mpdc_network_packet* packetout, const mpdc_network_register_update_request_state* state)
{
	MPDC_ASSERT(packetout != NULL);
	MPDC_ASSERT(state != NULL);

	mpdc_protocol_errors merr;

	/* create the update request header */
	network_header_create(packetout, mpdc_network_flag_register_update_request, NETWORK_JOIN_UPDATE_REQUEST_SEQUENCE, NETWORK_JOIN_UPDATE_REQUEST_MESSAGE_SIZE);

	/* add time-stamp and certificate to message, hash, sign the hash, and add the signature to the message */
	merr = network_certificate_hash_sign(packetout, state->sigkey, state->lcert);

	return merr;
}

static mpdc_protocol_errors network_register_update_verify(mpdc_network_register_update_request_state* state, const mpdc_network_packet* packetin)
{
	MPDC_ASSERT(state != NULL);
	MPDC_ASSERT(packetin != NULL);

	mpdc_protocol_errors merr;

	if (packetin->flag == mpdc_network_flag_register_update_response &&
		packetin->sequence == NETWORK_JOIN_UPDATE_RESPONSE_SEQUENCE)
	{
		if (mpdc_packet_time_valid(packetin) == true)
		{
			mpdc_child_certificate ccert = { 0 };

			/* temp copy of inbound certificate */
			mpdc_certificate_child_deserialize(&ccert, packetin->pmessage + MPDC_PACKET_SUBHEADER_SIZE);

			merr = mpdc_network_certificate_verify(&ccert, state->root);

			if (merr == mpdc_protocol_error_none)
			{
				uint8_t* pmsg;
				size_t mlen;

				mlen = packetin->msglen - (MPDC_PACKET_SUBHEADER_SIZE + MPDC_CERTIFICATE_SIGNED_HASH_SIZE);
				pmsg = (uint8_t*)qsc_memutils_malloc(mlen);

				if (pmsg != NULL)
				{
					/* verify the dla certificate */
					merr = network_message_signed_hash_verify(pmsg, packetin, &ccert);

					if (merr == mpdc_protocol_error_none)
					{
						const uint8_t* pnds;

						/* copy the dla certificate */
						qsc_memutils_copy(state->rcert, &ccert, sizeof(mpdc_child_certificate));

						/* pointer to the topology update list */
						pnds = pmsg + MPDC_CERTIFICATE_CHILD_SIZE;
						mlen = packetin->msglen - (MPDC_PACKET_SUBHEADER_SIZE + MPDC_CERTIFICATE_CHILD_SIZE + MPDC_CERTIFICATE_SIGNED_HASH_SIZE);

						/* deserialize topological nodes and add to local database */
						mpdc_topology_list_update_unpack(state->list, pnds, mlen);
						merr = mpdc_protocol_error_none;
					}

					qsc_memutils_alloc_free(pmsg);
				}
				else
				{
					merr = mpdc_protocol_error_memory_allocation;
				}
			}
		}
		else
		{
			merr = mpdc_protocol_error_message_time_invalid;
		}
	}
	else
	{
		merr = mpdc_protocol_error_invalid_request;
	}

	return merr;
}

mpdc_protocol_errors mpdc_network_register_update_request(mpdc_network_register_update_request_state* state)
{
	MPDC_ASSERT(state != NULL);
	
	/* Send a MAS or client network join request to the DLA.
	   The message is the callers root-signed certificate. */

	mpdc_protocol_errors merr;

	if (state != NULL)
	{
		qsc_socket csock = { 0 };

		if (mpdc_network_connect_to_device(&csock, state->address, mpdc_network_designation_dla) == qsc_socket_exception_success)
		{
			mpdc_network_packet reqt = { 0 };
			uint8_t sbuf[NETWORK_JOIN_REQUEST_PACKET_SIZE] = { 0 };
			size_t slen;

			/* create the join request packet  */
			reqt.pmessage = sbuf + MPDC_PACKET_HEADER_SIZE;
			network_register_update_request_packet(&reqt, state);
			mpdc_packet_header_serialize(&reqt, sbuf);

			/* send the join request to the dla */
			slen = qsc_socket_client_send(&csock, sbuf, NETWORK_JOIN_REQUEST_PACKET_SIZE, qsc_socket_send_flag_none);

			if (slen == NETWORK_JOIN_REQUEST_PACKET_SIZE)
			{
				mpdc_network_packet resp = { 0 };
				uint8_t hdr[MPDC_PACKET_HEADER_SIZE] = { 0 };
				uint8_t* rbuf;
				size_t mlen;
				size_t rlen;

				/* wait for the reply */
				rlen = qsc_socket_peek(&csock, hdr, MPDC_PACKET_HEADER_SIZE);

				if (rlen >= MPDC_PACKET_HEADER_SIZE)
				{
					mpdc_packet_header_deserialize(hdr, &resp);
					mlen = resp.msglen + MPDC_PACKET_HEADER_SIZE;
					rbuf = (uint8_t*)qsc_memutils_malloc(mlen);

					if (rbuf != NULL)
					{
						rlen = qsc_socket_receive(&csock, rbuf, mlen, qsc_socket_receive_flag_wait_all);

						if (rlen == mlen && resp.flag == mpdc_network_flag_register_update_response)
						{
							resp.pmessage = rbuf + MPDC_PACKET_HEADER_SIZE;
							merr = network_register_update_verify(state, &resp);
						}
						else if (rlen == NETWORK_ERROR_PACKET_SIZE)
						{
							/* get the server error from the packet */
							merr = network_unpack_error(rbuf);
						}
						else
						{
							merr = mpdc_protocol_error_receive_failure;
						}

						qsc_memutils_alloc_free(rbuf);
					}
					else
					{
						merr = mpdc_protocol_error_memory_allocation;
					}
				}
				else
				{
					merr = mpdc_protocol_error_receive_failure;
				}
			}
			else
			{
				merr = mpdc_protocol_error_transmit_failure;
			}

			mpdc_network_socket_dispose(&csock);
		}
		else
		{
			merr = mpdc_protocol_error_connection_failure;
		}
	}
	else
	{
		merr = mpdc_protocol_error_invalid_request;
	}

	return merr;
}

/* Network Join Update Response: 
* The DLA verifies the MAS/Client certificate Root signature, uses the certificate to verify the message hash,
* adds the device to the topology, and caches the remote certificate.
* The DLA adds its serialized certificate, and a serialized list of Agent nodes to the message.
* The DLA hashes the message along with the packet timestamp, and signs the hash.
* D(ts | lcert | update | Sign(H(ts | lcert | update))->M
*/

static mpdc_protocol_errors network_register_update_response_packet(mpdc_network_packet* packetout, mpdc_network_register_update_response_state* state, uint8_t* buffer, const mpdc_network_packet* packetin)
{
	MPDC_ASSERT(packetout != NULL);
	MPDC_ASSERT(state != NULL);
	MPDC_ASSERT(buffer != NULL);
	MPDC_ASSERT(packetin != NULL);

	mpdc_protocol_errors merr;

	merr = network_header_validate(packetin, mpdc_network_flag_register_update_request, NETWORK_JOIN_UPDATE_REQUEST_SEQUENCE, NETWORK_JOIN_UPDATE_REQUEST_MESSAGE_SIZE);

	if (merr == mpdc_protocol_error_none)
	{
		/* inspect the request packet parameters */
		if ((state->rcert->designation == mpdc_network_designation_mas ||
			state->rcert->designation == mpdc_network_designation_client))
		{
			mpdc_child_certificate ccert = { 0 };

			/* temp copy of inbound certificate */
			mpdc_certificate_child_deserialize(&ccert, packetin->pmessage + MPDC_PACKET_SUBHEADER_SIZE);

			/* verify the certificate signature */
			merr = network_certificate_signed_hash_verify(state->rcert, packetin, &ccert, state->root);

			/* assemble the updates */
			if (merr == mpdc_protocol_error_none)
			{
				size_t mlen;
				size_t mpos;
				size_t ncnt;

				/* get the number of agents in the topology */
				ncnt = mpdc_topology_list_server_count(state->list, mpdc_network_designation_agent);

				/* clients get the mas topology in addition to the agents */
				if (state->rcert->designation == mpdc_network_designation_client)
				{
					ncnt += mpdc_topology_list_server_count(state->list, mpdc_network_designation_mas);
				}

				if (ncnt > 0)
				{
					mlen = NETWORK_JOIN_UPDATE_RESPONSE_PACKET_SIZE;
					mlen += (ncnt * MPDC_NETWORK_TOPOLOGY_NODE_SIZE);

					/* resize the buffer to the full update size */
					buffer = (uint8_t*)qsc_memutils_realloc(buffer, mlen);

					if (buffer != NULL)
					{
						mlen -= MPDC_PACKET_HEADER_SIZE;
						network_header_create(packetout, mpdc_network_flag_register_update_response, NETWORK_JOIN_UPDATE_RESPONSE_SEQUENCE, (uint32_t)mlen);
						packetout->pmessage = buffer + MPDC_PACKET_HEADER_SIZE;

						/* serialize the packet time-stamp and sequence number and copy it to the packet */
						network_subheader_serialize(packetout->pmessage, packetout);
						mpos = MPDC_PACKET_SUBHEADER_SIZE;

						/* serialize the dla certificate and add it to the message */
						mpdc_certificate_child_serialize(packetout->pmessage + mpos, state->lcert);
						mpos += MPDC_CERTIFICATE_CHILD_SIZE;

						/* pack the list update */
						mlen = mpdc_topology_list_update_pack(packetout->pmessage + mpos, state->list, mpdc_network_designation_agent);
						mpos += mlen;

						if (state->rcert->designation == mpdc_network_designation_client)
						{
							/* clients get agents and mas in update */
							mlen = mpdc_topology_list_update_pack(packetout->pmessage + mpos, state->list, mpdc_network_designation_mas);
							mpos += mlen;
						}

						/* hash the message and sign the hash */
						mlen = mpdc_certificate_message_hash_sign(packetout->pmessage + mpos, state->sigkey, packetout->pmessage, mpos);
						
						if (mlen != MPDC_CERTIFICATE_SIGNED_HASH_SIZE)
						{
							merr = mpdc_protocol_error_signature_failure;
						}
					}
				}
				else
				{
					merr = mpdc_protocol_error_node_not_found;
				}
			}
		}
		else
		{
			merr = mpdc_protocol_error_invalid_request;
		}
	}

	return merr;
}

mpdc_protocol_errors mpdc_network_register_update_response(mpdc_network_register_update_response_state* state, const mpdc_network_packet* packetin)
{
	MPDC_ASSERT(state != NULL);
	MPDC_ASSERT(packetin != NULL);

	/* The DLA network join response.
	   When the requestor is a server, the DLA packages a list of agent node descriptions,
	   signs the list, and sends it along with the DLA certificate. 
	   The server then contacts unknown agent servers and exchanges master keys. */

	uint8_t* pbuf;
	size_t mlen;
	mpdc_protocol_errors merr;

	if (state != NULL && packetin != NULL)
	{
		mpdc_network_packet resp = { 0 };
		pbuf = NULL;

		/* deserialize the remote certificate in the request */
		mpdc_certificate_child_deserialize(state->rcert, packetin->pmessage + MPDC_PACKET_SUBHEADER_SIZE);

		pbuf = (uint8_t*)qsc_memutils_malloc(NETWORK_JOIN_UPDATE_RESPONSE_PACKET_SIZE);

		if (pbuf != NULL)
		{
			/* create the update response packet */
			merr = network_register_update_response_packet(&resp, state, pbuf, packetin);

			if (merr == mpdc_protocol_error_none)
			{
				size_t slen;

				mpdc_packet_header_serialize(&resp, pbuf);
				mlen = resp.msglen + MPDC_PACKET_HEADER_SIZE;

				slen = qsc_socket_client_send(state->csock, pbuf, mlen, qsc_socket_send_flag_none);

				if (slen == mlen)
				{
					merr = mpdc_protocol_error_none;
				}
				else
				{
					merr = mpdc_protocol_error_transmit_failure;
				}

				qsc_memutils_alloc_free(pbuf);
			}
		}
		else
		{
			merr = mpdc_protocol_error_memory_allocation;
		}
	}
	else
	{
		merr = mpdc_protocol_error_invalid_request;
	}

	/* notify of failure with error message */
	if (merr != mpdc_protocol_error_none)
	{
		mpdc_network_send_error(state->csock, merr);
	}

	return merr;
}

/* Remote signature request 
* Sent by the DLA to the RDS server to remotely sign a certificate
* D(ts | cert, Sk(H(ts | cert)))->R
*/

static mpdc_protocol_errors network_remote_signing_request_packet(mpdc_network_remote_signing_request_state* state, mpdc_network_packet* packetout)
{
	MPDC_ASSERT(state != NULL);
	MPDC_ASSERT(packetout != NULL);

	mpdc_protocol_errors merr;

	/* create the packet header */
	network_header_create(packetout, mpdc_network_flag_network_remote_signing_request, NETWORK_REMOTE_SIGNING_REQUEST_SEQUENCE, NETWORK_REMOTE_SIGNING_REQUEST_MESSAGE_SIZE);

	/* add time-stamp and certificate to message, hash, sign the hash, and add the signature to the message */
	merr = network_certificate_hash_sign(packetout, state->sigkey, state->rcert);
	
	return merr;
}

static mpdc_protocol_errors network_remote_signing_request_verify(const mpdc_network_remote_signing_request_state* state, const mpdc_network_packet* packetin)
{
	MPDC_ASSERT(state != NULL);
	MPDC_ASSERT(packetin != NULL);

	mpdc_protocol_errors merr;

	merr = network_header_validate(packetin, mpdc_network_flag_network_remote_signing_response, NETWORK_REMOTE_SIGNING_RESPONSE_SEQUENCE, NETWORK_REMOTE_SIGNING_RESPONSE_MESSAGE_SIZE);

	if (merr == mpdc_protocol_error_none)
	{
		/* temp copy of inbound certificate */
		mpdc_certificate_child_deserialize(state->rcert, packetin->pmessage);

		/* verify the root certificate signature */
		merr = mpdc_network_certificate_verify(state->rcert, state->root);
	}

	return merr;
}

mpdc_protocol_errors mpdc_network_remote_signing_request(mpdc_network_remote_signing_request_state* state)
{
	MPDC_ASSERT(state != NULL);
	
	mpdc_network_packet reqt = { 0 };
	uint8_t sbuf[NETWORK_REMOTE_SIGNING_REQUEST_PACKET_SIZE] = { 0 };
	size_t slen;
	mpdc_protocol_errors merr;

	if (state != NULL)
	{
		/* create the request packet */
		reqt.pmessage = sbuf + MPDC_PACKET_HEADER_SIZE;
		merr = network_remote_signing_request_packet(state, &reqt);

		if (merr == mpdc_protocol_error_none)
		{
			qsc_socket csock = { 0 };

			if (mpdc_network_connect_to_device(&csock, state->address, mpdc_network_designation_rds) == qsc_socket_exception_success)
			{
				mpdc_packet_header_serialize(&reqt, sbuf);

				slen = qsc_socket_client_send(&csock, sbuf, NETWORK_REMOTE_SIGNING_REQUEST_PACKET_SIZE, qsc_socket_send_flag_none);

				if (slen == NETWORK_REMOTE_SIGNING_REQUEST_PACKET_SIZE)
				{
					uint8_t rbuf[NETWORK_REMOTE_SIGNING_RESPONSE_PACKET_SIZE] = { 0 };
					size_t rlen;

					/* wait for the reply */
					rlen = qsc_socket_receive(&csock, rbuf, sizeof(rbuf), qsc_socket_receive_flag_wait_all);

					if (rlen == NETWORK_REMOTE_SIGNING_RESPONSE_PACKET_SIZE)
					{
						mpdc_network_packet resp = { 0 };

						mpdc_packet_header_deserialize(rbuf, &resp);
						resp.pmessage = rbuf + MPDC_PACKET_HEADER_SIZE;

						/* verify the query response message */
						merr = network_remote_signing_request_verify(state, &resp);
					}
					else if (rlen == NETWORK_ERROR_PACKET_SIZE)
					{
						/* get the error from the packet */
						merr = network_unpack_error(rbuf);
					}
					else
					{
						merr = mpdc_protocol_error_receive_failure;
					}
				}
				else
				{
					merr = mpdc_protocol_error_transmit_failure;
				}

				mpdc_network_socket_dispose(&csock);
			}
			else
			{
				merr = mpdc_protocol_error_connection_failure;
			}
		}
	}
	else
	{
		merr = mpdc_protocol_error_invalid_request;
	}

	return merr;
}

/* Remote signature response
* Sent by the RDS to the DLA server as a certificate signing response
* R(ts | scert, Sk(H(ts | scert)))->D
*/

static mpdc_protocol_errors network_remote_signing_response_packet(mpdc_network_remote_signing_response_state* state, mpdc_network_packet* packetout)
{
	MPDC_ASSERT(state != NULL);
	MPDC_ASSERT(packetout != NULL);

	mpdc_protocol_errors merr;

	/* create the packet header */
	network_header_create(packetout, mpdc_network_flag_network_remote_signing_response, NETWORK_REMOTE_SIGNING_RESPONSE_SEQUENCE, NETWORK_REMOTE_SIGNING_RESPONSE_MESSAGE_SIZE);

	/* add time-stamp and certificate to message, hash, sign the hash, and add the signature to the message */
	if (mpdc_certificate_root_sign(state->rcert, state->root, state->sigkey) == MPDC_CERTIFICATE_SIGNED_HASH_SIZE)
	{
		/* serialize the signed certificate to the message */
		mpdc_certificate_child_serialize(packetout->pmessage, state->rcert);
		merr = mpdc_protocol_error_none;
	}
	else
	{
		merr = mpdc_protocol_error_signature_failure;
	}

	return merr;
}

static mpdc_protocol_errors network_remote_signing_response_verify(const mpdc_network_remote_signing_response_state* state, const mpdc_network_packet* packetin)
{
	MPDC_ASSERT(state != NULL);
	MPDC_ASSERT(packetin != NULL);

	mpdc_protocol_errors merr;

	/* validate the packet header */
	merr = network_header_validate(packetin, mpdc_network_flag_network_remote_signing_request, NETWORK_REMOTE_SIGNING_REQUEST_SEQUENCE, NETWORK_REMOTE_SIGNING_REQUEST_MESSAGE_SIZE);

	/* inspect the request packet parameters */
	if (merr == mpdc_protocol_error_none)
	{
		mpdc_child_certificate ccert = { 0 };

		/* temp copy of inbound certificate */
		mpdc_certificate_child_deserialize(&ccert, packetin->pmessage + MPDC_PACKET_SUBHEADER_SIZE);

		/* verify the message signature */
		if (mpdc_certificate_signature_hash_verify(packetin->pmessage + NETWORK_CERTIFICATE_UPDATE_SIZE, MPDC_CERTIFICATE_SIGNED_HASH_SIZE, packetin->pmessage, NETWORK_CERTIFICATE_UPDATE_SIZE, state->dcert) == true)
		{
			uint8_t shdr[MPDC_PACKET_SUBHEADER_SIZE] = { 0 };

			network_subheader_serialize(shdr, packetin);

			/* compare the sub-header time and sequence values with the signed values */
			if (qsc_memutils_are_equal(shdr, packetin->pmessage, MPDC_PACKET_SUBHEADER_SIZE) == false)
			{
				merr = mpdc_protocol_error_message_time_invalid;
			}
		}
		else
		{
			merr = mpdc_protocol_error_authentication_failure;
		}

		if (merr == mpdc_protocol_error_none)
		{
			mpdc_certificate_child_copy(state->rcert, &ccert);
		}
	}

	return merr;
}

mpdc_protocol_errors mpdc_network_remote_signing_response(mpdc_network_remote_signing_response_state* state, const mpdc_network_packet* packetin)
{
	MPDC_ASSERT(state != NULL);
	
	mpdc_protocol_errors merr;

	if (state != NULL)
	{
		merr = network_remote_signing_response_verify(state, packetin);

		if (merr == mpdc_protocol_error_none)
		{
			mpdc_network_packet resp = { 0 };
			uint8_t sbuf[NETWORK_REMOTE_SIGNING_RESPONSE_PACKET_SIZE] = { 0 };
			size_t slen;

			/* create the request packet */
			resp.pmessage = sbuf + MPDC_PACKET_HEADER_SIZE;
			merr = network_remote_signing_response_packet(state, &resp);

			if (merr == mpdc_protocol_error_none)
			{
				mpdc_packet_header_serialize(&resp, sbuf);

				slen = qsc_socket_client_send(state->csock, sbuf, NETWORK_REMOTE_SIGNING_RESPONSE_PACKET_SIZE, qsc_socket_send_flag_none);

				if (slen == NETWORK_REMOTE_SIGNING_RESPONSE_PACKET_SIZE)
				{
					merr = mpdc_protocol_error_none;
				}
				else
				{
					merr = mpdc_protocol_error_transmit_failure;
				}
			}
		}
	}
	else
	{
		merr = mpdc_protocol_error_invalid_request;
	}
	
	/* notify of failure with error message */
	if (merr != mpdc_protocol_error_none)
	{
		mpdc_network_send_error(state->csock, merr);
	}

	return merr;
}

/* Device Resign Request: 
* Sent from an Agent/MAS/IDG/Client to the DLA, resigning from the network.
* The DLA verifies the request and broadcasts a revocation message to the network.
* M(ts | ser | Sign(H(ts | ser)))->D
*/

static mpdc_protocol_errors network_resign_request_packet(mpdc_network_packet* packetout, const mpdc_network_resign_request_state* state)
{
	MPDC_ASSERT(packetout != NULL);
	MPDC_ASSERT(state != NULL);

	mpdc_protocol_errors merr;

	/* create the packet header */
	network_header_create(packetout, mpdc_network_flag_network_resign_request, NETWORK_RESIGN_REQUEST_SEQUENCE, NETWORK_RESIGN_REQUEST_MESSAGE_SIZE);

	merr = network_message_hash_sign(packetout, state->sigkey, state->lnode->serial, MPDC_CERTIFICATE_SERIAL_SIZE);

	return merr;
}

mpdc_protocol_errors mpdc_network_resign_request(const mpdc_network_resign_request_state* state)
{
	MPDC_ASSERT(state != NULL);
	
	mpdc_protocol_errors merr;

	if (state != NULL)
	{
		qsc_socket csock = { 0 };

		if (mpdc_network_connect_to_device(&csock, state->address, mpdc_network_designation_dla) == qsc_socket_exception_success)
		{
			mpdc_network_packet reqt = { 0 };
			uint8_t sbuf[NETWORK_RESIGN_REQUEST_PACKET_SIZE] = { 0 };
			size_t mlen;

			/* create the request packet */
			reqt.pmessage = sbuf + MPDC_PACKET_HEADER_SIZE;
			merr = network_resign_request_packet(&reqt, state);

			if (merr == mpdc_protocol_error_none)
			{
				mpdc_packet_header_serialize(&reqt, sbuf);

				mlen = qsc_socket_client_send(&csock, sbuf, NETWORK_RESIGN_REQUEST_PACKET_SIZE, qsc_socket_send_flag_none);

				if (mlen == NETWORK_RESIGN_REQUEST_PACKET_SIZE)
				{
					merr = mpdc_protocol_error_none;
				}
				else
				{
					merr = mpdc_protocol_error_transmit_failure;
				}
			}

			mpdc_network_socket_dispose(&csock);
		}
		else
		{
			merr = mpdc_protocol_error_connection_failure;
		}
	}
	else
	{
		merr = mpdc_protocol_error_invalid_request;
	}

	return merr;
}

/* Device Resign Response: 
* The DLA verifies the hash and signature, finds the node, then assembles a revocation broadcast message.
* The certificate is deleted on remote nodes, and the node is marked as revoked in the DLA topology, 
* and removed from the topology of other devices.
* Vrcert(ts | ser)
* revoke(ts | rcert | Sign(H(ts | rcert)))->...
*/

mpdc_protocol_errors mpdc_network_resign_response(mpdc_network_resign_response_state* state, const mpdc_network_packet* packetin)
{
	MPDC_ASSERT(state != NULL);
	MPDC_ASSERT(packetin != NULL);

	mpdc_protocol_errors merr;

	if (state != NULL && packetin != NULL)
	{
		/* verify the packet */
		merr = network_header_validate(packetin, mpdc_network_flag_network_resign_request, NETWORK_RESIGN_REQUEST_SEQUENCE, NETWORK_RESIGN_REQUEST_MESSAGE_SIZE);

		if (merr == mpdc_protocol_error_none)
		{
			uint8_t ser[MPDC_CERTIFICATE_SERIAL_SIZE] = { 0 };

			merr = network_message_signed_hash_verify(ser, packetin, state->rcert);

			if (merr == mpdc_protocol_error_none)
			{
				const uint8_t* pser;

				/* find the node in the topological list */
				pser = packetin->pmessage + MPDC_PACKET_SUBHEADER_SIZE;

				if (mpdc_topology_node_find(state->list, state->rnode, pser) == true)
				{
					/* broadcast a certificate revocation message */
					mpdc_network_revoke_request_state rrs = {
						.designation = state->rnode->designation,
						.list = state->list,
						.rnode = state->rnode,
						.sigkey = state->sigkey
					};

					/* broadcast a certificate revocation to nodes on the network */
					merr = mpdc_network_revoke_broadcast(&rrs);
				}
				else
				{
					merr = mpdc_protocol_error_node_not_found;
				}
			}
		}
	}
	else
	{
		merr = mpdc_protocol_error_invalid_request;
	}

	return merr;
}

/* Revocation Broadcast Call: 
* The broadcast revocation of a certificate by the dla.
* Agent revocations are sent to servers and clients, and server or idg revocations are sent to the agents.
* D(ts | rcert | Sign(H(ts | rcert)))->...
*/

static mpdc_protocol_errors network_revoke_packet(mpdc_network_packet* packetout, const mpdc_network_revoke_request_state* state)
{
	MPDC_ASSERT(packetout != NULL);
	MPDC_ASSERT(state != NULL);

	/* The message is the certificate number and a time-stamp, both hashed and signed.
	* loop through topology and send to each mpdc network member.
	* agent revocation is sent to servers and clients, 
	* server and client revocation is sent to agents. */

	mpdc_protocol_errors merr;

	/* create the packet header */
	network_header_create(packetout, mpdc_network_flag_network_revocation_broadcast, NETWORK_REVOKE_REQUEST_SEQUENCE, NETWORK_REVOKE_REQUEST_MESSAGE_SIZE);

	/* add time-stamp and certificate serial number to message, hash, sign the hash, and add the signature to the message */
	merr = network_message_hash_sign(packetout, state->sigkey, state->rnode->serial, MPDC_CERTIFICATE_SERIAL_SIZE);

	return merr;
}

mpdc_protocol_errors mpdc_network_revoke_broadcast(mpdc_network_revoke_request_state* state)
{
	MPDC_ASSERT(state != NULL);
	
	/* The message is the certificate serial number and a time-stamp, both signed.
	* loop through topology and send to each relative member.
	* agent revocation is sent to servers and clients, 
	* server and client revocation is sent to agents. */

	mpdc_protocol_errors merr;

	if (state != NULL)
	{
		mpdc_network_packet reqt = { 0 };
		uint8_t sbuf[NETWORK_REVOKE_REQUEST_PACKET_SIZE] = { 0 };

		reqt.pmessage = sbuf + MPDC_PACKET_HEADER_SIZE;

		/* create the revocation packet */
		merr = network_revoke_packet(&reqt, state);

		/* send the packet to the type-associated target*/
		if (merr == mpdc_protocol_error_none)
		{
			mpdc_packet_header_serialize(&reqt, sbuf);

			if (state->designation == mpdc_network_designation_agent)
			{
				mpdc_network_broadcast_message(state->list, sbuf, NETWORK_REVOKE_REQUEST_PACKET_SIZE, mpdc_network_designation_client);
				mpdc_network_broadcast_message(state->list, sbuf, NETWORK_REVOKE_REQUEST_PACKET_SIZE, mpdc_network_designation_mas);
			}
			else if (state->designation == mpdc_network_designation_client)
			{
				mpdc_network_broadcast_message(state->list, sbuf, NETWORK_REVOKE_REQUEST_PACKET_SIZE, mpdc_network_designation_agent);
				mpdc_network_broadcast_message(state->list, sbuf, NETWORK_REVOKE_REQUEST_PACKET_SIZE, mpdc_network_designation_client);
				mpdc_network_broadcast_message(state->list, sbuf, NETWORK_REVOKE_REQUEST_PACKET_SIZE, mpdc_network_designation_mas);
			}
			else if (state->designation == mpdc_network_designation_mas)
			{
				mpdc_network_broadcast_message(state->list, sbuf, NETWORK_REVOKE_REQUEST_PACKET_SIZE, mpdc_network_designation_agent);
				mpdc_network_broadcast_message(state->list, sbuf, NETWORK_REVOKE_REQUEST_PACKET_SIZE, mpdc_network_designation_client);
			}
			else if (state->designation == mpdc_network_designation_all)
			{
				mpdc_network_broadcast_message(state->list, sbuf, NETWORK_REVOKE_REQUEST_PACKET_SIZE, mpdc_network_designation_agent);
				mpdc_network_broadcast_message(state->list, sbuf, NETWORK_REVOKE_REQUEST_PACKET_SIZE, mpdc_network_designation_client);
				mpdc_network_broadcast_message(state->list, sbuf, NETWORK_REVOKE_REQUEST_PACKET_SIZE, mpdc_network_designation_mas);
			}
			else
			{
				merr = mpdc_protocol_error_invalid_request;
			}
		}
	}
	else
	{
		merr = mpdc_protocol_error_invalid_request;
	}

	return merr;
}

/* Revocation Broadcast Response: 
* Processes the broadcast revocation of a certificate by the dla.
* Agent revocations are sent to MAS and Clients, and MAS or IDG revocations are sent to the Agents.
* The responding device verifies the hash and signature, and removes the certificate and topological node from the database.
* Vrcert(ts | rcert)
* topology Remove(rcert)
*/

mpdc_protocol_errors mpdc_network_revoke_response(mpdc_network_revoke_response_state* state, const mpdc_network_packet* packetin)
{
	MPDC_ASSERT(state != NULL);
	MPDC_ASSERT(packetin != NULL);

	mpdc_protocol_errors merr;

	if (state != NULL && packetin != NULL)
	{
		/* verify the packet */
		merr = network_header_validate(packetin, mpdc_network_flag_network_revocation_broadcast, NETWORK_REVOKE_REQUEST_SEQUENCE, NETWORK_REVOKE_REQUEST_MESSAGE_SIZE);

		if (merr == mpdc_protocol_error_none)
		{
			uint8_t ser[MPDC_CERTIFICATE_SERIAL_SIZE] = { 0 };

			merr = network_message_signed_hash_verify(ser, packetin, state->dcert);

			/* find the node in the topological list */
			if (mpdc_topology_node_find(state->list, state->rnode, ser) == true)
			{
				merr = mpdc_protocol_error_none;
			}
			else
			{
				merr = mpdc_protocol_error_node_not_found;
			}
		}
	}
	else
	{
		merr = mpdc_protocol_error_invalid_request;
	}

	return merr;
}

/* Topological Query Request: 
* The client-requestor sends the hashed and signed issuer string of a remote node and the local certificate serial number to the DLA.
* C1(ts | serial | issuer | Sign(H(ts | serial | issuer )))->D
* The DLA uses the certificate serial number to load the requestors certificate, and verify the signature.
* The requesting client receives the remote clients node information, and uses it to synchronize certificates,
* and exchange master fragment keys.
*/

static mpdc_protocol_errors network_topological_query_request_packet(mpdc_network_packet* packetout, const mpdc_network_topological_query_request_state* state)
{
	MPDC_ASSERT(packetout != NULL);
	MPDC_ASSERT(state != NULL);

	uint8_t msg[NETWORK_TOPOLOGY_QUERY_SIZE] = { 0 };
	mpdc_protocol_errors merr;

	/* create the packet header */
	network_header_create(packetout, mpdc_network_flag_topology_query_request, NETWORK_TOPOLOGY_QUERY_REQUEST_SEQUENCE, NETWORK_TOPOLOGY_QUERY_REQUEST_MESSAGE_SIZE);
	/* copy the requestors serial number and the issuer query string to the message */
	qsc_memutils_copy(msg, state->serial, MPDC_CERTIFICATE_SERIAL_SIZE);
	qsc_memutils_copy(msg + MPDC_CERTIFICATE_SERIAL_SIZE, (uint8_t*)state->issuer, MPDC_CERTIFICATE_ISSUER_SIZE);
	/* hash the message and sign the hash */
	merr = network_message_hash_sign(packetout, state->sigkey, msg, NETWORK_TOPOLOGY_QUERY_SIZE);

	return merr;
}

static mpdc_protocol_errors network_topological_query_request_verify(const mpdc_network_topological_query_request_state* state, const mpdc_network_packet* packetin)
{
	MPDC_ASSERT(packetin != NULL);
	MPDC_ASSERT(state != NULL);

	mpdc_protocol_errors merr;

	/* check the packet parameters */
	merr = network_header_validate(packetin, mpdc_network_flag_topology_query_response, NETWORK_TOPOLOGY_QUERY_RESPONSE_SEQUENCE, NETWORK_TOPOLOGY_QUERY_RESPONSE_MESSAGE_SIZE);

	if (merr == mpdc_protocol_error_none)
	{
		uint8_t snode[MPDC_NETWORK_TOPOLOGY_NODE_SIZE] = { 0 };

		/* verify the certificate signature */
		merr = network_message_signed_hash_verify(snode, packetin, state->dcert);

		if (merr == mpdc_protocol_error_none)
		{
			mpdc_topology_node_deserialize(state->rnode, snode);
		}
	}

	return merr;
}

mpdc_protocol_errors mpdc_network_topological_query_request(const mpdc_network_topological_query_request_state* state)
{
	MPDC_ASSERT(state != NULL);
	
	mpdc_protocol_errors merr;

	if (state != NULL)
	{
		qsc_socket csock = { 0 };

		if (mpdc_network_connect_to_device(&csock, state->dnode->address, state->dnode->designation) == qsc_socket_exception_success)
		{
			mpdc_network_packet reqt = { 0 };
			uint8_t sbuf[NETWORK_TOPOLOGY_QUERY_REQUEST_PACKET_SIZE] = { 0 };
			size_t slen;

			/* create the packet header */
			reqt.pmessage = sbuf + MPDC_PACKET_HEADER_SIZE;
			network_topological_query_request_packet(&reqt, state);
			mpdc_packet_header_serialize(&reqt, sbuf);

			/* send query to the dla */
			slen = qsc_socket_client_send(&csock, sbuf, NETWORK_TOPOLOGY_QUERY_REQUEST_PACKET_SIZE, qsc_socket_send_flag_none);

			if (slen == NETWORK_TOPOLOGY_QUERY_REQUEST_PACKET_SIZE)
			{
				uint8_t rbuf[NETWORK_TOPOLOGY_QUERY_RESPONSE_PACKET_SIZE] = { 0 };
				size_t rlen;

				/* wait for the reply */
				rlen = qsc_socket_receive(&csock, rbuf, sizeof(rbuf), qsc_socket_receive_flag_wait_all);

				if (rlen == NETWORK_TOPOLOGY_QUERY_RESPONSE_PACKET_SIZE)
				{
					mpdc_network_packet qrsp = { 0 };

					mpdc_packet_header_deserialize(rbuf, &qrsp);
					qrsp.pmessage = rbuf + MPDC_PACKET_HEADER_SIZE;

					/* verify the query response message */
					merr = network_topological_query_request_verify(state, &qrsp);
				}
				else if (rlen == NETWORK_ERROR_PACKET_SIZE)
				{
					/* get the error from the packet */
					merr = network_unpack_error(rbuf);
				}
				else
				{
					merr = mpdc_protocol_error_receive_failure;
				}
			}
			else
			{
				merr = mpdc_protocol_error_transmit_failure;
			}

			mpdc_network_socket_dispose(&csock);
		}
		else
		{
			merr = mpdc_protocol_error_connect_failure;
		}
	}
	else
	{
		merr = mpdc_protocol_error_invalid_request;
	}

	return merr;
}

/* Topological Query Response: 
* The DLA loads the requestors certificate and validates the query signature and hash.
* The DLA finds the remote node from the issuer string, signs the serialized node and sends it back to the requestor.
* D(ts | snode, Sign(H(ts | snode)))->C
*/

static mpdc_protocol_errors network_topological_query_response_packet(mpdc_network_packet* packetout, const mpdc_network_topological_query_response_state* state, const mpdc_network_packet* packetin)
{
	MPDC_ASSERT(packetout != NULL);
	MPDC_ASSERT(state != NULL);
	MPDC_ASSERT(packetin != NULL);

	mpdc_protocol_errors merr;
	uint8_t snode[MPDC_NETWORK_TOPOLOGY_NODE_SIZE] = { 0 };

	if (packetout != NULL && state != NULL && packetin != NULL)
	{
		/* add the serialized topological node to the message */
		if (mpdc_topology_node_serialize(snode, state->rnode) == MPDC_NETWORK_TOPOLOGY_NODE_SIZE)
		{
			/* create the packet header */
			network_header_create(packetout, mpdc_network_flag_topology_query_response, NETWORK_TOPOLOGY_QUERY_RESPONSE_SEQUENCE, NETWORK_TOPOLOGY_QUERY_RESPONSE_MESSAGE_SIZE);

			/* hash the message and sign the hash */
			merr = network_message_hash_sign(packetout, state->sigkey, snode, MPDC_NETWORK_TOPOLOGY_NODE_SIZE);
		}
		else
		{
			merr = mpdc_protocol_error_decoding_failure;
		}
	}
	else
	{
		merr = mpdc_protocol_error_invalid_request;
	}

	return merr;
}

static mpdc_protocol_errors network_topological_query_response_verify(uint8_t* query, const mpdc_network_topological_query_response_state* state, const mpdc_network_packet* packetin)
{
	MPDC_ASSERT(query != NULL);
	MPDC_ASSERT(state != NULL);
	MPDC_ASSERT(packetin != NULL);

	mpdc_protocol_errors merr;

	/* check the packet parameters */
	merr = network_header_validate(packetin, mpdc_network_flag_topology_query_request, NETWORK_TOPOLOGY_QUERY_REQUEST_SEQUENCE, NETWORK_TOPOLOGY_QUERY_REQUEST_MESSAGE_SIZE);

	if (merr == mpdc_protocol_error_none)
	{
		/* verify the certificate signature */
		merr = network_message_signed_hash_verify(query, packetin, state->ccert);
	}

	return merr;
}

mpdc_protocol_errors mpdc_network_topological_query_response(const mpdc_network_topological_query_response_state* state, const mpdc_network_packet* packetin)
{
	MPDC_ASSERT(state != NULL);
	MPDC_ASSERT(packetin != NULL);

	mpdc_protocol_errors merr;

	if (state != NULL && packetin != NULL)
	{
		uint8_t query[NETWORK_TOPOLOGY_QUERY_SIZE] = { 0 };

		merr = network_topological_query_response_verify(query, state, packetin);

		if (merr == mpdc_protocol_error_none)
		{
			mpdc_network_packet resp = { 0 };
			uint8_t sbuf[NETWORK_TOPOLOGY_QUERY_RESPONSE_PACKET_SIZE] = { 0 };
			size_t mlen;

			/* create the update response packet */
			resp.pmessage = sbuf + MPDC_PACKET_HEADER_SIZE;
			merr = network_topological_query_response_packet(&resp, state, packetin);

			if (merr == mpdc_protocol_error_none)
			{
				mpdc_packet_header_serialize(&resp, sbuf);

				/* send the response to the requestor */
				mlen = qsc_socket_client_send(state->csock, sbuf, NETWORK_TOPOLOGY_QUERY_RESPONSE_PACKET_SIZE, qsc_socket_send_flag_none);

				if (mlen == NETWORK_TOPOLOGY_QUERY_RESPONSE_PACKET_SIZE)
				{
					merr = mpdc_protocol_error_none;
				}
				else
				{
					merr = mpdc_protocol_error_transmit_failure;
				}
			}
		}
	}
	else
	{
		merr = mpdc_protocol_error_invalid_request;
	}

	/* notify of failure with error message */
	if (merr != mpdc_protocol_error_none)
	{
		mpdc_network_send_error(state->csock, merr);
	}

	return merr;
}

/* Topological Status Request: 
* The DLA sends a status request to the target client, verifying it is online and available.
* It sends a signed copy of its certificate serial number in the message.
* D(ts | lser | Sign(H(ts | lser)))->C
* The remote client receives the signed serial number for the remote node, verifies the hash, signature, and the serial number.
* rser = Verify(H(ts | lser)
* If the responder is available, it sends its signed serial number back to the requestor.
* C(ts | lser | Sign(H(ts | lser)))->D
* The DLA verifies the message, and the function signals if the node is available for connect.
* rser = Verify(H(ts | lser)
*/

static mpdc_protocol_errors network_topological_status_request_packet(mpdc_network_packet* packetout, const mpdc_network_topological_status_request_state* state)
{
	MPDC_ASSERT(packetout != NULL);
	MPDC_ASSERT(state != NULL);

	/* copy the remote node serial number and sign it with the local signing key */

	mpdc_protocol_errors merr;

	/* create the packet header */
	network_header_create(packetout, mpdc_network_flag_topology_status_request, NETWORK_TOPOLOGY_STATUS_REQUEST_SEQUENCE, NETWORK_TOPOLOGY_STATUS_REQUEST_MESSAGE_SIZE);
	
	/* hash the message and sign the hash */
	merr = network_message_hash_sign(packetout, state->sigkey, state->lnode->serial, MPDC_CERTIFICATE_SERIAL_SIZE);

	return merr;
}

mpdc_protocol_errors mpdc_network_topological_status_request_verify(const mpdc_network_topological_status_request_state* state, const mpdc_network_packet* packetin)
{
	MPDC_ASSERT(state != NULL);
	MPDC_ASSERT(packetin != NULL);

	mpdc_protocol_errors merr;

	if (state != NULL && packetin != NULL)
	{
		/* check the packet parameters */
		merr = network_header_validate(packetin, mpdc_network_flag_topology_status_response, NETWORK_TOPOLOGY_STATUS_RESPONSE_SEQUENCE, NETWORK_TOPOLOGY_STATUS_RESPONSE_MESSAGE_SIZE);

		if (merr == mpdc_protocol_error_none)
		{
			uint8_t rser[MPDC_CERTIFICATE_SERIAL_SIZE] = { 0 };

			/* verify the signature */
			merr = network_message_signed_hash_verify(rser, packetin, state->rcert);

			if (merr == mpdc_protocol_error_none)
			{
				if (qsc_memutils_are_equal(state->rcert->serial, rser, MPDC_CERTIFICATE_SERIAL_SIZE) == false)
				{
					merr = mpdc_protocol_error_node_not_found;
				}
			}
		}
	}
	else
	{
		merr = mpdc_protocol_error_invalid_request;
	}

	return merr;
}

mpdc_protocol_errors mpdc_network_topological_status_request(const mpdc_network_topological_status_request_state* state)
{
	MPDC_ASSERT(state != NULL);

	mpdc_protocol_errors merr;

	if (state != NULL)
	{
		qsc_socket csock = { 0 };

		/* connect to query target */
		if (mpdc_network_connect_to_device(&csock, state->rnode->address, state->rnode->designation) == qsc_socket_exception_success)
		{
			mpdc_network_packet reqt = { 0 };
			uint8_t sbuf[NETWORK_TOPOLOGY_STATUS_REQUEST_PACKET_SIZE] = { 0 };
			size_t slen;

			/* create the packet header */
			reqt.pmessage = sbuf + MPDC_PACKET_HEADER_SIZE;
			network_topological_status_request_packet(&reqt, state);
			mpdc_packet_header_serialize(&reqt, sbuf);

			slen = qsc_socket_client_send(&csock, sbuf, NETWORK_TOPOLOGY_STATUS_REQUEST_PACKET_SIZE, qsc_socket_send_flag_none);

			if (slen == NETWORK_TOPOLOGY_STATUS_REQUEST_PACKET_SIZE)
			{
				uint8_t rbuf[NETWORK_TOPOLOGY_STATUS_RESPONSE_PACKET_SIZE] = { 0 };
				mpdc_network_packet resp = { 0 };
				size_t rlen;

				/* wait for the reply */
				rlen = qsc_socket_receive(&csock, rbuf, sizeof(rbuf), qsc_socket_receive_flag_wait_all);

				if (rlen == NETWORK_TOPOLOGY_STATUS_RESPONSE_PACKET_SIZE)
				{
					mpdc_packet_header_deserialize(rbuf, &resp);
					resp.pmessage = rbuf + MPDC_PACKET_HEADER_SIZE;

					/* verify the certificate update */
					merr = mpdc_network_topological_status_request_verify(state, &resp);
				}
				else if (rlen == NETWORK_ERROR_PACKET_SIZE)
				{
					/* get the server error from the packet */
					merr = network_unpack_error(rbuf);
				}
				else
				{
					merr = mpdc_protocol_error_receive_failure;
				}
			}
			else
			{
				merr = mpdc_protocol_error_transmit_failure;
			}

			mpdc_network_socket_dispose(&csock);
		}
		else
		{
			merr = mpdc_protocol_error_connection_failure;
		}
	}
	else
	{
		merr = mpdc_protocol_error_invalid_request;
	}

	return merr;
}

/* Topological Status Response: 
* The server sends a status response back to the requestor, using its signed certificate serial number.
* M(Sk(H(lser)))->C
* If the server is offline the receiver will time out, it can also signal that it is unavailable.
*/

static mpdc_protocol_errors network_topological_status_response_packet(mpdc_network_packet* packetout, const mpdc_network_topological_status_response_state* state)
{
	MPDC_ASSERT(packetout != NULL);
	MPDC_ASSERT(state != NULL);

	mpdc_protocol_errors merr;

	/* create the packet header */
	network_header_create(packetout, mpdc_network_flag_topology_status_response, NETWORK_TOPOLOGY_STATUS_RESPONSE_SEQUENCE, NETWORK_TOPOLOGY_STATUS_RESPONSE_MESSAGE_SIZE);

	/* hash the message and sign the hash */
	merr = network_message_hash_sign(packetout, state->sigkey, state->lnode->serial, MPDC_CERTIFICATE_SERIAL_SIZE);

	return merr;
}

static mpdc_protocol_errors network_topological_status_response_verify(const mpdc_network_topological_status_response_state* state, const mpdc_network_packet* packetin)
{
	MPDC_ASSERT(state != NULL);
	MPDC_ASSERT(packetin != NULL);

	mpdc_protocol_errors merr;

	/* check the packet parameters */
	merr = network_header_validate(packetin, mpdc_network_flag_topology_status_request, NETWORK_TOPOLOGY_STATUS_REQUEST_SEQUENCE, NETWORK_TOPOLOGY_STATUS_REQUEST_MESSAGE_SIZE);

	if (state != NULL && packetin != NULL)
	{
		if (merr == mpdc_protocol_error_none)
		{
			uint8_t rser[MPDC_CERTIFICATE_SERIAL_SIZE] = { 0 };

			/* verify the certificate signature */
			merr = network_message_signed_hash_verify(rser, packetin, state->rcert);

			if (merr == mpdc_protocol_error_none)
			{
				/* compare the remote copy of the local certificate serial number with the local node copy */
				if (qsc_memutils_are_equal(state->rcert->serial, rser, MPDC_CERTIFICATE_SERIAL_SIZE) == false)
				{
					merr = mpdc_protocol_error_node_not_found;
				}
			}
		}
	}
	else
	{
		merr = mpdc_protocol_error_invalid_request;
	}

	return merr;
}

mpdc_protocol_errors mpdc_network_topological_status_response(const mpdc_network_topological_status_response_state* state, const mpdc_network_packet* packetin)
{
	MPDC_ASSERT(state != NULL);
	MPDC_ASSERT(packetin != NULL);

	mpdc_protocol_errors merr;

	if (state != NULL)
	{
		merr = network_topological_status_response_verify(state, packetin);

		if (merr == mpdc_protocol_error_none)
		{
			mpdc_network_packet resp = { 0 };
			uint8_t sbuf[NETWORK_TOPOLOGY_STATUS_RESPONSE_PACKET_SIZE] = { 0 };
			size_t mlen;

			/* create the update response packet */
			resp.pmessage = sbuf + MPDC_PACKET_HEADER_SIZE;
			merr = network_topological_status_response_packet(&resp, state);
			mpdc_packet_header_serialize(&resp, sbuf);

			/* send the response to the requestor */
			mlen = qsc_socket_client_send(state->csock, sbuf, NETWORK_TOPOLOGY_STATUS_RESPONSE_PACKET_SIZE, qsc_socket_send_flag_none);

			if (mlen == NETWORK_TOPOLOGY_STATUS_RESPONSE_PACKET_SIZE)
			{
				merr = mpdc_protocol_error_none;
			}
			else
			{
				merr = mpdc_protocol_error_transmit_failure;
			}
		}
	}
	else
	{
		merr = mpdc_protocol_error_invalid_request;
	}
	
	/* notify of failure with error message */
	if (merr != mpdc_protocol_error_none)
	{
		mpdc_network_send_error(state->csock, merr);
	}

	return merr;
}

/* Helper Functions */

mpdc_protocol_errors mpdc_network_certificate_verify(const mpdc_child_certificate* ccert, const mpdc_root_certificate* root)
{
	MPDC_ASSERT(ccert != NULL);
	MPDC_ASSERT(root != NULL);

	mpdc_protocol_errors merr;

	if (ccert != NULL && root != NULL)
	{
		/* validate the certificate format */
		if (mpdc_certificate_child_is_valid(ccert) == true)
		{
			/* authenticate the root signature */
			if (mpdc_certificate_root_signature_verify(ccert, root) == true)
			{
				merr = mpdc_protocol_error_none;
			}
			else
			{
				merr = mpdc_protocol_error_root_signature_invalid;
			}
		}
		else
		{
			merr = mpdc_protocol_error_verification_failure;
		}
	}
	else
	{
		merr = mpdc_protocol_error_invalid_request;
	}

	return merr;
}

mpdc_network_designations mpdc_network_port_to_application(uint16_t port)
{
	mpdc_network_designations tnode;

	if (port == MPDC_APPLICATION_AGENT_PORT)
	{
		tnode = mpdc_network_designation_agent;
	}
	else if (port == MPDC_APPLICATION_CLIENT_PORT)
	{
		tnode = mpdc_network_designation_client;
	}
	else if (port == MPDC_APPLICATION_DLA_PORT)
	{
		tnode = mpdc_network_designation_dla;
	}
	else if (port == MPDC_APPLICATION_IDG_PORT)
	{
		tnode = mpdc_network_designation_idg;
	}
	else if (port == MPDC_APPLICATION_RDS_PORT)
	{
		tnode = mpdc_network_designation_rds;
	}
	else if (port == MPDC_APPLICATION_MAS_PORT)
	{
		tnode = mpdc_network_designation_mas;
	}
	else
	{
		tnode = mpdc_network_designation_none;
	}

	return tnode;
}

uint16_t mpdc_network_application_to_port(mpdc_network_designations tnode)
{
	uint16_t port;

	if (tnode == mpdc_network_designation_agent)
	{
		port = MPDC_APPLICATION_AGENT_PORT;
	}
	else if (tnode == mpdc_network_designation_client)
	{
		port = MPDC_APPLICATION_CLIENT_PORT;
	}
	else if (tnode == mpdc_network_designation_dla)
	{
		port = MPDC_APPLICATION_DLA_PORT;
	}
	else if (tnode == mpdc_network_designation_idg)
	{
		port = MPDC_APPLICATION_IDG_PORT;
	}
	else if (tnode == mpdc_network_designation_rds)
	{
		port = MPDC_APPLICATION_RDS_PORT;
	}
	else if (tnode == mpdc_network_designation_mas)
	{
		port = MPDC_APPLICATION_MAS_PORT;
	}
	else
	{
		port = 0;
	}
		
	return port;
}

void mpdc_network_broadcast_message(const mpdc_topology_list_state* list, const uint8_t* message, size_t msglen, mpdc_network_designations tnode)
{
	MPDC_ASSERT(list != NULL);
	MPDC_ASSERT(message != NULL);

	size_t i;
	uint16_t port;

	if (list != NULL && message != NULL)
	{
		qsc_socket csock = { 0 };

		port = mpdc_network_application_to_port(tnode);

		for (i = 0; i < list->count; ++i)
		{
			mpdc_topology_node_state node = { 0 };

			if (mpdc_topology_list_item(list, &node, i) == true)
			{
				if (node.designation == tnode)
				{
					if (mpdc_network_connect_to_address(&csock, node.address, port) == qsc_socket_exception_success)
					{
						qsc_socket_client_send(&csock, message, msglen, qsc_socket_send_flag_none);
						mpdc_network_socket_dispose(&csock);
					}
				}
			}
		}
	}
}

qsc_socket_exceptions mpdc_network_connect_to_device(qsc_socket* csock, const char* address, mpdc_network_designations designation)
{
	MPDC_ASSERT(csock != NULL);
	MPDC_ASSERT(address != NULL);

	qsc_socket_exceptions serr;
	qsc_ipinfo_address_types tadd;
	uint16_t port;

	serr = qsc_socket_exception_error;

	if (csock != NULL && address != NULL)
	{
		tadd = qsc_ipinfo_get_address_type(address);
		port = mpdc_network_application_to_port(designation);

		qsc_socket_client_initialize(csock);

		if (tadd == qsc_ipinfo_address_type_ipv4)
		{
			qsc_ipinfo_ipv4_address ipv4 = { 0 };

			ipv4 = qsc_ipinfo_ipv4_address_from_string(address);

			if (qsc_ipinfo_ipv4_address_is_valid(&ipv4) == true)
			{
				serr = qsc_socket_client_connect_ipv4(csock, &ipv4, port);
			}
			else
			{
				serr = qsc_socket_exception_invalid_address;
			}
		}
		else if (tadd == qsc_ipinfo_address_type_ipv6)
		{
			qsc_ipinfo_ipv6_address ipv6 = { 0 };

			ipv6 = qsc_ipinfo_ipv6_address_from_string(address);

			if (qsc_ipinfo_ipv6_address_is_valid(&ipv6) == true)
			{
				serr = qsc_socket_client_connect_ipv6(csock, &ipv6, port);
			}
			else
			{
				serr = qsc_socket_exception_invalid_address;
			}
		}
		else
		{
			serr = qsc_socket_exception_address_unsupported;
		}
	}

	return serr;
}

qsc_socket_exceptions mpdc_network_connect_to_address(qsc_socket* csock, const char* address, uint16_t port)
{
	MPDC_ASSERT(csock != NULL);
	MPDC_ASSERT(address != NULL);

	qsc_socket_exceptions serr;
	qsc_ipinfo_address_types tadd;

	serr = qsc_socket_exception_error;

	if (csock != NULL && address != NULL)
	{
		tadd = qsc_ipinfo_get_address_type(address);

		qsc_socket_client_initialize(csock);

		if (tadd == qsc_ipinfo_address_type_ipv4)
		{
			qsc_ipinfo_ipv4_address ipv4 = { 0 };

			ipv4 = qsc_ipinfo_ipv4_address_from_string(address);

			if (qsc_ipinfo_ipv4_address_is_valid(&ipv4) == true)
			{
				serr = qsc_socket_client_connect_ipv4(csock, &ipv4, port);
			}
			else
			{
				serr = qsc_socket_exception_invalid_address;
			}
		}
		else if (tadd == qsc_ipinfo_address_type_ipv6)
		{
			qsc_ipinfo_ipv6_address ipv6 = { 0 };

			ipv6 = qsc_ipinfo_ipv6_address_from_string(address);

			if (qsc_ipinfo_ipv6_address_is_valid(&ipv6) == true)
			{
				serr = qsc_socket_client_connect_ipv6(csock, &ipv6, port);
			}
			else
			{
				serr = qsc_socket_exception_invalid_address;
			}
		}
		else
		{
			serr = qsc_socket_exception_address_unsupported;
		}
	}

	return serr;
}

bool mpdc_network_get_local_address(char address[MPDC_CERTIFICATE_ADDRESS_SIZE])
{
	bool res;

#if defined(NETWORK_PROTOCOL_IPV6)
	qsc_ipinfo_ipv6_address v6add = { 0 };

	res = qsc_netutils_get_ipv6_address(&v6add);

	if (res == true)
	{
		qsc_memutils_copy(address, v6add.ipv6, QSC_IPINFO_IPV6_BYTELEN);
	}
#else
	qsc_ipinfo_ipv4_address v4add = { 0 };

	res = qsc_netutils_get_ipv4_address(&v4add);

	if (res == true)
	{
		qsc_ipinfo_ipv4_address_to_string(address, &v4add);
	}
#endif

	return res;
}

mpdc_protocol_errors mpdc_network_send_error(const qsc_socket* csock, mpdc_protocol_errors error)
{
	MPDC_ASSERT(csock != NULL);
	
	mpdc_network_packet resp = { 0 };
	uint8_t ebuf[NETWORK_ERROR_PACKET_SIZE] = { 0 };
	size_t slen;
	mpdc_protocol_errors merr;

	merr = error;

	if (csock != NULL)
	{
		if (qsc_socket_is_connected(csock) == true)
		{
			resp.pmessage = ebuf + MPDC_PACKET_HEADER_SIZE;
			mpdc_packet_error_message(&resp, error);
			mpdc_packet_header_serialize(&resp, ebuf);
			slen = qsc_socket_send(csock, ebuf, NETWORK_ERROR_PACKET_SIZE, qsc_socket_send_flag_none);

			if (slen == NETWORK_ERROR_PACKET_SIZE)
			{
				merr = mpdc_protocol_error_none;
			}
			else
			{
				merr = mpdc_protocol_error_transmit_failure;
			}
		}
		else
		{
			merr = mpdc_protocol_error_connection_failure;
		}
	}
	else
	{
		merr = mpdc_protocol_error_channel_down;
	}

	return merr;
}

void mpdc_network_socket_dispose(qsc_socket* csock)
{
	MPDC_ASSERT(csock != NULL);

	if (csock != NULL)
	{
		qsc_socket_client_shut_down(csock);
	}
}

#if defined(MPDC_DEBUG_MODE)
typedef struct network_test_device_package
{
	mpdc_signature_keypair akp;
	mpdc_signature_keypair akp2;
	mpdc_signature_keypair akp3;
	mpdc_signature_keypair akp4;
	mpdc_signature_keypair ckp;
	mpdc_signature_keypair ckp2;
	mpdc_signature_keypair dkp;
	mpdc_signature_keypair mkp;
	mpdc_signature_keypair rkp;
	mpdc_child_certificate acrt;
	mpdc_child_certificate acrt2;
	mpdc_child_certificate acrt3;
	mpdc_child_certificate acrt4;
	mpdc_child_certificate ccrt;
	mpdc_child_certificate ccrt2;
	mpdc_child_certificate dcrt;
	mpdc_child_certificate mcrt;
	mpdc_root_certificate root;
	mpdc_topology_node_state ande;
	mpdc_topology_node_state ande2;
	mpdc_topology_node_state ande3;
	mpdc_topology_node_state ande4;
	mpdc_topology_node_state cnde;
	mpdc_topology_node_state cnde2;
	mpdc_topology_node_state dnde;
	mpdc_topology_node_state mnde;
	mpdc_topology_list_state list;
	qsc_collection_state amfk;
	qsc_collection_state amfk2;
	qsc_collection_state amfk3;
	qsc_collection_state amfk4;
	qsc_collection_state cmfk;
	qsc_collection_state cmfk2;
	qsc_collection_state mmfk;

} network_test_device_package;

static void network_test_load_node(mpdc_topology_list_state* list, mpdc_topology_node_state* node, const mpdc_child_certificate* ccert)
{
	uint8_t ipa[MPDC_CERTIFICATE_ADDRESS_SIZE] = { 192, 168, 1 };

	qsc_acp_generate(ipa + 3, 1);
	mpdc_topology_child_register(list, ccert, ipa);
	mpdc_topology_node_find(list, node, ccert->serial);
}

static void network_test_device_destroy(network_test_device_package* spkg)
{
	qsc_collection_dispose(&spkg->amfk);
	qsc_collection_dispose(&spkg->amfk2);
	qsc_collection_dispose(&spkg->amfk3);
	qsc_collection_dispose(&spkg->amfk4);
	qsc_collection_dispose(&spkg->cmfk);
	qsc_collection_dispose(&spkg->cmfk2);
	qsc_collection_dispose(&spkg->mmfk);
	mpdc_topology_list_dispose(&spkg->list);
}

static void network_test_device_instantiate(network_test_device_package* spkg)
{
	mpdc_certificate_expiration exp = { 0 };
	uint8_t mfk[MPDC_CRYPTO_SYMMETRIC_KEY_SIZE] = { 0 };

	qsc_collection_initialize(&spkg->amfk, sizeof(mfk));
	qsc_collection_initialize(&spkg->amfk2, sizeof(mfk));
	qsc_collection_initialize(&spkg->amfk3, sizeof(mfk));
	qsc_collection_initialize(&spkg->amfk4, sizeof(mfk));
	qsc_collection_initialize(&spkg->cmfk, sizeof(mfk));
	qsc_collection_initialize(&spkg->cmfk2, sizeof(mfk));
	qsc_collection_initialize(&spkg->mmfk, sizeof(mfk));

	mpdc_topology_list_initialize(&spkg->list);

	/* generate the root certificate */
	mpdc_certificate_signature_generate_keypair(&spkg->rkp);
	mpdc_certificate_expiration_set_days(&exp, 0, 30);
	mpdc_certificate_root_create(&spkg->root, spkg->rkp.pubkey, &exp, "XYZ_RDS1");

	/* create the dla */
	mpdc_certificate_signature_generate_keypair(&spkg->dkp);
	mpdc_certificate_expiration_set_days(&exp, 0, 100);
	mpdc_certificate_child_create(&spkg->dcrt, spkg->dkp.pubkey, &exp, "XYZ_DLA1", mpdc_network_designation_dla);
	mpdc_certificate_root_sign(&spkg->dcrt, &spkg->root, spkg->rkp.prikey);
	network_test_load_node(&spkg->list, &spkg->dnde, &spkg->dcrt);

	/* create the mas */
	mpdc_certificate_signature_generate_keypair(&spkg->mkp);
	mpdc_certificate_expiration_set_days(&exp, 0, 100);
	mpdc_certificate_child_create(&spkg->mcrt, spkg->mkp.pubkey, &exp, "XYZ_MAS1", mpdc_network_designation_mas);
	mpdc_certificate_root_sign(&spkg->mcrt, &spkg->root, spkg->rkp.prikey);
	network_test_load_node(&spkg->list, &spkg->mnde, &spkg->mcrt);
	
	/* create a client 1 */
	mpdc_certificate_signature_generate_keypair(&spkg->ckp);
	mpdc_certificate_expiration_set_days(&exp, 0, 100);
	mpdc_certificate_child_create(&spkg->ccrt, spkg->ckp.pubkey, &exp, "XYZ_CLT1", mpdc_network_designation_client);
	mpdc_certificate_root_sign(&spkg->ccrt, &spkg->root, spkg->rkp.prikey);
	qsc_acp_generate(mfk, MPDC_CRYPTO_SYMMETRIC_KEY_SIZE);
	qsc_collection_add(&spkg->mmfk, mfk, spkg->ccrt.serial);
	qsc_collection_add(&spkg->cmfk, mfk, spkg->mcrt.serial);
	network_test_load_node(&spkg->list, &spkg->cnde, &spkg->ccrt);
		
	/* create a client 2 */
	mpdc_certificate_signature_generate_keypair(&spkg->ckp2);
	mpdc_certificate_expiration_set_days(&exp, 0, 100);
	mpdc_certificate_child_create(&spkg->ccrt2, spkg->ckp2.pubkey, &exp, "XYZ_CLT2", mpdc_network_designation_client);
	mpdc_certificate_root_sign(&spkg->ccrt2, &spkg->root, spkg->rkp.prikey);
	qsc_acp_generate(mfk, MPDC_CRYPTO_SYMMETRIC_KEY_SIZE);
	qsc_collection_add(&spkg->mmfk, mfk, spkg->ccrt2.serial);
	qsc_collection_add(&spkg->cmfk2, mfk, spkg->mcrt.serial);
	network_test_load_node(&spkg->list, &spkg->cnde2, &spkg->ccrt2);

	/* create the agents */
	mpdc_certificate_signature_generate_keypair(&spkg->akp);
	mpdc_certificate_expiration_set_days(&exp, 0, 100);
	mpdc_certificate_child_create(&spkg->acrt, spkg->akp.pubkey, &exp, "XYZ_AGT1", mpdc_network_designation_agent);
	mpdc_certificate_root_sign(&spkg->acrt, &spkg->root, spkg->rkp.prikey);

	/* generate the shared mfk keys for a simulated topology */
	qsc_acp_generate(mfk, MPDC_CRYPTO_SYMMETRIC_KEY_SIZE);
	qsc_collection_add(&spkg->amfk, mfk, spkg->ccrt.serial);
	qsc_collection_add(&spkg->cmfk, mfk, spkg->acrt.serial);
	qsc_acp_generate(mfk, MPDC_CRYPTO_SYMMETRIC_KEY_SIZE);
	qsc_collection_add(&spkg->amfk, mfk, spkg->mcrt.serial);
	qsc_collection_add(&spkg->mmfk, mfk, spkg->acrt.serial);
	network_test_load_node(&spkg->list, &spkg->ande, &spkg->acrt);

	mpdc_certificate_signature_generate_keypair(&spkg->akp2);
	mpdc_certificate_expiration_set_days(&exp, 0, 100);
	mpdc_certificate_child_create(&spkg->acrt2, spkg->akp2.pubkey, &exp, "XYZ_AGT2", mpdc_network_designation_agent);
	mpdc_certificate_root_sign(&spkg->acrt2, &spkg->root, spkg->rkp.prikey);
	qsc_acp_generate(mfk, MPDC_CRYPTO_SYMMETRIC_KEY_SIZE);
	qsc_collection_add(&spkg->amfk2, mfk, spkg->ccrt.serial);
	qsc_collection_add(&spkg->cmfk, mfk, spkg->acrt2.serial);
	qsc_acp_generate(mfk, MPDC_CRYPTO_SYMMETRIC_KEY_SIZE);
	qsc_collection_add(&spkg->amfk2, mfk, spkg->mcrt.serial);
	qsc_collection_add(&spkg->mmfk, mfk, spkg->acrt2.serial);
	network_test_load_node(&spkg->list, &spkg->ande2, &spkg->acrt2);

	mpdc_certificate_signature_generate_keypair(&spkg->akp3);
	mpdc_certificate_expiration_set_days(&exp, 0, 100);
	mpdc_certificate_child_create(&spkg->acrt3, spkg->akp3.pubkey, &exp, "XYZ_AGT3", mpdc_network_designation_agent);
	mpdc_certificate_root_sign(&spkg->acrt3, &spkg->root, spkg->rkp.prikey);
	qsc_acp_generate(mfk, MPDC_CRYPTO_SYMMETRIC_KEY_SIZE);
	qsc_collection_add(&spkg->amfk3, mfk, spkg->ccrt.serial);
	qsc_collection_add(&spkg->cmfk, mfk, spkg->acrt3.serial);
	qsc_acp_generate(mfk, MPDC_CRYPTO_SYMMETRIC_KEY_SIZE);
	qsc_collection_add(&spkg->amfk3, mfk, spkg->mcrt.serial);
	qsc_collection_add(&spkg->mmfk, mfk, spkg->acrt3.serial);
	network_test_load_node(&spkg->list, &spkg->ande3, &spkg->acrt3);
	
	mpdc_certificate_signature_generate_keypair(&spkg->akp4);
	mpdc_certificate_expiration_set_days(&exp, 0, 100);
	mpdc_certificate_child_create(&spkg->acrt4, spkg->akp4.pubkey, &exp, "XYZ_AGT4", mpdc_network_designation_agent);
	mpdc_certificate_root_sign(&spkg->acrt4, &spkg->root, spkg->rkp.prikey);
	qsc_acp_generate(mfk, MPDC_CRYPTO_SYMMETRIC_KEY_SIZE);
	qsc_collection_add(&spkg->amfk4, mfk, spkg->ccrt.serial);
	qsc_collection_add(&spkg->cmfk, mfk, spkg->acrt4.serial);
	qsc_acp_generate(mfk, MPDC_CRYPTO_SYMMETRIC_KEY_SIZE);
	qsc_collection_add(&spkg->amfk4, mfk, spkg->mcrt.serial);
	qsc_collection_add(&spkg->mmfk, mfk, spkg->acrt4.serial);
	network_test_load_node(&spkg->list, &spkg->ande4, &spkg->acrt4);
}

static bool network_test_announce_test(void)
{
	mpdc_topology_node_state rnode = { 0 };
	mpdc_child_certificate rcert = { 0 };
	network_test_device_package spkg = { 0 };
	mpdc_network_packet reqt = { 0 };
	uint8_t breqt[NETWORK_ANNOUNCE_REQUEST_PACKET_SIZE] = { 0 };
	mpdc_protocol_errors merr;

	network_test_device_instantiate(&spkg);

	reqt.pmessage = breqt + MPDC_PACKET_HEADER_SIZE;
	
	mpdc_network_announce_request_state aqs = { 
		.list = &spkg.list,		/* topology list */
		.rnode = &spkg.ande,	/* agent node */
		.sigkey = spkg.dkp.prikey };	/* dla signing key */

	/* the dla announces a new agent in a broadcast request */
	merr = network_announce_broadcast_packet(&reqt, &aqs);

	mpdc_network_announce_response_state ars = { 
		.dcert = &spkg.dcrt,	/* dla certificate*/
		.rnode = &rnode,		/* node copy */
		.root = &spkg.root };	/* root certificate */

	/* the mas/client process the request */
	merr = mpdc_network_announce_response(&ars, &reqt);

	/* compare received node with stored copy */
	if (mpdc_topology_nodes_are_equal(&spkg.ande, &rnode) != true)
	{
		merr = mpdc_protocol_error_exchange_failure;
	}

	network_test_device_destroy(&spkg);

	return (merr == mpdc_protocol_error_none);
}

static bool network_test_converge(void)
{
	network_test_device_package spkg = { 0 };
	mpdc_network_packet reqt = { 0 };
	mpdc_network_packet resp = { 0 };
	uint8_t breqt[NETWORK_CONVERGE_REQUEST_PACKET_SIZE] = { 0 };
	uint8_t bresp[NETWORK_CONVERGE_RESPONSE_PACKET_SIZE] = { 0 };
	uint8_t snode[MPDC_NETWORK_TOPOLOGY_NODE_SIZE] = { 0 };
	mpdc_protocol_errors merr;

	network_test_device_instantiate(&spkg);

	reqt.pmessage = breqt + MPDC_PACKET_HEADER_SIZE;
	resp.pmessage = bresp + MPDC_PACKET_HEADER_SIZE;

	mpdc_topology_node_serialize(snode, &spkg.mnde);

	mpdc_network_converge_request_state cqs = {
		.rcert = &spkg.mcrt,		/* mas cert */
		.rnode = &spkg.mnde,		/* mas node */
		.sigkey = spkg.dkp.prikey	/* dla signing key*/
	};

	/* the dla sends the converge request */
	merr = network_converge_request_packet(&reqt, &cqs, snode);

	if (merr == mpdc_protocol_error_none)
	{
		const mpdc_network_converge_response_state cus = {
			.csock = NULL,				/* the socket */
			.lcert = &spkg.mcrt,		/* mas certificate*/
			.lnode = &spkg.mnde,		/* mas topological node */
			.rcert = &spkg.dcrt,		/* dla certificate */
			.sigkey = spkg.mkp.prikey	/* the mas signing key */
		};

		merr = network_converge_request_verify(&cus, &reqt);

		if (merr == mpdc_protocol_error_none)
		{
			/* the remote node sends the reply */
			merr = network_converge_response_packet(&resp, &cus);

			if (merr == mpdc_protocol_error_none)
			{
				/* verify the response */
				merr = network_converge_response_verify(&cqs, &resp);
			}
		}
	}

	network_test_device_destroy(&spkg);

	return (merr == mpdc_protocol_error_none);
}

static bool network_test_fkey_exchange(void)
{
	network_test_device_package spkg = { 0 };
	mpdc_network_packet reqt = { 0 };
	mpdc_network_packet resp = { 0 };
	uint8_t fra[MPDC_CRYPTO_SYMMETRIC_SECRET_SIZE] = { 0 };
	uint8_t frm[MPDC_CRYPTO_SYMMETRIC_SECRET_SIZE] = { 0 };
	uint8_t breqt[NETWORK_FRAGMENT_FKEY_REQUEST_PACKET_SIZE] = { 0 };
	uint8_t bresp[NETWORK_FRAGMENT_FKEY_RESPONSE_PACKET_SIZE] = { 0 };
	uint8_t mfa[MPDC_CRYPTO_SYMMETRIC_KEY_SIZE] = { 0 };
	uint8_t mfm[MPDC_CRYPTO_SYMMETRIC_KEY_SIZE] = { 0 };
	uint8_t atok[MPDC_CRYPTO_SYMMETRIC_TOKEN_SIZE] = { 0 };
	mpdc_protocol_errors merr;
	bool res;

	res = false;
	network_test_device_instantiate(&spkg);

	reqt.pmessage = breqt + MPDC_PACKET_HEADER_SIZE;
	resp.pmessage = bresp + MPDC_PACKET_HEADER_SIZE;

	/* generate the shared mfk */
	qsc_acp_generate(mfa, MPDC_CRYPTO_SYMMETRIC_KEY_SIZE);
	qsc_memutils_copy(mfm, mfa, MPDC_CRYPTO_SYMMETRIC_KEY_SIZE);

	mpdc_network_fkey_request_state frs = {
		.frag = frm,		/* fragment storage */
		.lnode = &spkg.mnde,	/* local node */
		.mfk = mfm,		/* master fragment key */
		.rnode = &spkg.ande,	/* remote node */
		.token = atok		/* token storage */
	};

	/* the mas fkey request packet */
	network_fkey_request_packet(&reqt, &frs);

	mpdc_network_fkey_response_state frr = {
		.csock = NULL,		/* the socket */
		.frag = fra,		/* fragment storage */
		.lnode = &spkg.ande,	/* local node */
		.mfk = mfa,		/* master fragment key */
		.rnode = &spkg.mnde	/* remote node */
	};

	/* the agent fkey response packet */
	merr = network_fkey_response_packet(&resp, &reqt, &frr);

	if (merr == mpdc_protocol_error_none)
	{
		/* server verifies the fkey response packet */
		merr = network_fkey_response_verify(&frs, &resp);

		if (merr == mpdc_protocol_error_none)
		{
			/* test that both fragment keys are identical */
			res = qsc_memutils_are_equal(frs.frag, frr.frag, MPDC_CRYPTO_SYMMETRIC_KEY_SIZE);
		}
	}

	network_test_device_destroy(&spkg);

	return res;
}

static bool network_test_fragment_collection(void)
{
	network_test_device_package spkg = { 0 };
	qsc_list_state clst = { 0 };
	mpdc_network_packet crqt = { 0 };
	mpdc_network_packet crsp = { 0 };
	mpdc_network_packet qrqt = { 0 };
	mpdc_network_packet qrsp = { 0 };
	qsc_keccak_state fkhc = { 0 };
	qsc_keccak_state fkhs = { 0 };
	uint8_t bcrqt[NETWORK_FRAGMENT_COLLECTION_REQUEST_PACKET_SIZE] = { 0 };
	uint8_t bcrsp[NETWORK_FRAGMENT_COLLECTION_RESPONSE_PACKET_SIZE + (NETWORK_FRAGMENT_QUERY_RESPONSE_SIZE * 4)] = { 0 };
	uint8_t bqrqt[NETWORK_FRAGMENT_QUERY_REQUEST_PACKET_SIZE] = { 0 };
	uint8_t bqrsp[NETWORK_FRAGMENT_QUERY_RESPONSE_PACKET_SIZE] = { 0 };
	uint8_t frag[MPDC_CRYPTO_SYMMETRIC_KEY_SIZE] = { 0 };
	uint8_t hfkc[MPDC_CRYPTO_SYMMETRIC_SESSION_KEY_SIZE] = { 0 };
	uint8_t hfkm[MPDC_CRYPTO_SYMMETRIC_SESSION_KEY_SIZE] = { 0 };
	uint8_t tokc[MPDC_CRYPTO_SYMMETRIC_TOKEN_SIZE] = { 0 };
	uint8_t tokm[MPDC_CRYPTO_SYMMETRIC_TOKEN_SIZE] = { 0 };
	mpdc_protocol_errors merr;

	crqt.pmessage = bcrqt + MPDC_PACKET_HEADER_SIZE;
	crsp.pmessage = bcrsp + MPDC_PACKET_HEADER_SIZE;
	qrqt.pmessage = bqrqt + MPDC_PACKET_HEADER_SIZE;
	qrsp.pmessage = bqrsp + MPDC_PACKET_HEADER_SIZE;

	network_test_device_instantiate(&spkg);

	qsc_acp_generate(tokc, sizeof(tokc));
	qsc_acp_generate(tokm, sizeof(tokm));
	qsc_acp_generate(frag, sizeof(frag));

	mpdc_network_fragment_collection_request_state crs = {
		.hfkey = hfkc,
		.list = &spkg.list,
		.lmfk = &spkg.cmfk,
		.lnode = &spkg.cnde,
		.rnode = &spkg.mnde,
		.token = tokc
	};

	/* the client requests a fragment collection from the mas */
	merr = network_fragment_collection_request_packet(&crqt, &crs);

	if (merr == mpdc_protocol_error_none)
	{
		mpdc_network_fragment_query_request_state qrs = {
			.list = &spkg.list,
			.lmfk = &spkg.mmfk,
			.lnode = &spkg.mnde,
			.rnode = &spkg.ande,
			.token = tokm
		};

		/* the mas sends a fragment set query to an agent */
		merr = network_fragment_collection_query_request_packet(&qrqt, &crqt, &qrs);

		if (merr == mpdc_protocol_error_none)
		{
			mpdc_network_fragment_query_response_state qrr = {
				.csock = NULL,
				.list = &spkg.list,
				.lmfk = &spkg.amfk,
				.lnode = &spkg.ande,
				.rnode = &spkg.mnde
			};

			merr = network_fragment_query_request_verify(&qrr, &qrqt);

			if (merr == mpdc_protocol_error_none)
			{
				/* the agent sends an encrypted set of fragments to the mas */
				merr = network_fragment_query_response_packet(&qrsp, &qrqt, &qrr);

				if (merr == mpdc_protocol_error_none)
				{
					mpdc_network_fragment_collection_response_state crr = {
						.csock = NULL,
						.ctok = tokc,
						.frag = frag,
						.hfkey = hfkm,
						.list = &spkg.list,
						.lmfk = &spkg.mmfk,
						.lnode = &spkg.mnde,
						.rnode = &spkg.cnde,
						.mtok = tokm
					};

					merr = network_fragment_collection_request_verify(&crr, &crqt);

					if (merr == mpdc_protocol_error_none)
					{
						/* add the client mfk as first in list */
						uint8_t ftm[NETWORK_FRAGMENT_QUERY_RESPONSE_SIZE] = { 0 };

						qsc_list_initialize(&clst, NETWORK_FRAGMENT_QUERY_RESPONSE_SIZE);

						/* update the servers key hash with the mas-client key fragment */
						qsc_sha3_initialize(&fkhs);
						qsc_sha3_update(&fkhs, qsc_keccak_rate_256, crr.frag, MPDC_CRYPTO_SYMMETRIC_KEY_SIZE);

						/* add agent fragment to the key collection */
						qsc_list_add(&clst, qrsp.pmessage);

						merr = network_fragment_collection_response_derive(&fkhs, &crr, &qrsp);

						/* create the fragment hash key and store in state */
#if defined(MPDC_EXTENDED_SESSION_SECURITY)
						qsc_sha3_finalize(&fkhs, qsc_keccak_rate_512, crr.hfkey);
#else
						qsc_sha3_finalize(&fkhs, qsc_keccak_rate_256, crr.hfkey);
#endif

						if (merr == mpdc_protocol_error_none)
						{
							/* the mas creates the response packet for the client */
							merr = network_fragment_collection_response_packet(&crsp, &clst, &crr);

							if (merr == mpdc_protocol_error_none)
							{
								/* the client decrypts the fragments and derives the fragment hash key */
								merr = network_fragment_collection_request_derive(&crs, &crsp);

								if (merr == mpdc_protocol_error_none)
								{
									/* compare the hkeys */
									if (qsc_memutils_are_equal_256(crs.hfkey, crr.hfkey) == false)
									{
										merr = mpdc_protocol_error_verification_failure;
									}
								}
							}
						}
					}
				}
			}
		}
	}
	
	network_test_device_destroy(&spkg);

	return (merr == mpdc_protocol_error_none);
}

static bool network_test_fkey_encryption(void)
{
	network_test_device_package spkg = { 0 };
	uint8_t data[MPDC_PACKET_SUBHEADER_SIZE] = { 0 };
	uint8_t frags[MPDC_CRYPTO_SYMMETRIC_KEY_SIZE] = { 0 };
	uint8_t token[MPDC_CRYPTO_SYMMETRIC_TOKEN_SIZE] = { 0 };
	uint8_t mfka[MPDC_CRYPTO_SYMMETRIC_KEY_SIZE] = { 0 };
	
	bool res;

	res = false;
	network_test_device_instantiate(&spkg);

	qsc_acp_generate(frags, sizeof(frags));
	qsc_acp_generate(token, sizeof(token));
	qsc_acp_generate(data, sizeof(data));

	/* agent uses mas shared key */
	if (qsc_collection_find(&spkg.amfk, mfka, spkg.mnde.serial) == true)
	{
		uint8_t ckey[QSC_SHA3_512_HASH_SIZE] = { 0 };
		uint8_t fragr[MPDC_CRYPTO_SYMMETRIC_KEY_SIZE] = { 0 };
		uint8_t mctxt[MPDC_CRYPTO_SYMMETRIC_KEY_SIZE + MPDC_CRYPTO_SYMMETRIC_HASH_SIZE] = { 0 };
		uint8_t mfkm[MPDC_CRYPTO_SYMMETRIC_KEY_SIZE] = { 0 };

		/* generate the fragment encryption key */
		network_derive_fkey(ckey, mfka, spkg.cnde.chash, spkg.mnde.chash, token);

		/* encrypt fragment key and copy the cipher-text to the message */
		qsc_memutils_xor(ckey, frags, MPDC_CRYPTO_SYMMETRIC_KEY_SIZE);
		qsc_memutils_copy(mctxt, ckey, MPDC_CRYPTO_SYMMETRIC_KEY_SIZE);

		/* create the mac tag */
		network_mac_message(mctxt + MPDC_CRYPTO_SYMMETRIC_KEY_SIZE, ckey + MPDC_CRYPTO_SYMMETRIC_KEY_SIZE, mctxt, MPDC_CRYPTO_SYMMETRIC_KEY_SIZE, data);

		/* mas uses agents shared key */
		if (qsc_collection_find(&spkg.mmfk, mfkm, spkg.ande.serial) == true)
		{
			uint8_t mtag[MPDC_CRYPTO_SYMMETRIC_HASH_SIZE] = { 0 };

			/* generate the fragment encryption key */
			network_derive_fkey(ckey, mfkm, spkg.cnde.chash, spkg.mnde.chash, token);

			/* create the mac tag */
			network_mac_message(mtag, ckey + MPDC_CRYPTO_SYMMETRIC_KEY_SIZE, mctxt, MPDC_CRYPTO_SYMMETRIC_KEY_SIZE, data);

			if (qsc_memutils_are_equal(mtag, mctxt + MPDC_CRYPTO_SYMMETRIC_KEY_SIZE, MPDC_CRYPTO_SYMMETRIC_HASH_SIZE) == true)
			{
				/* decrypt the fragment */
				qsc_memutils_xor(ckey, mctxt, MPDC_CRYPTO_SYMMETRIC_KEY_SIZE);
				qsc_memutils_copy(fragr, ckey, MPDC_CRYPTO_SYMMETRIC_KEY_SIZE);

				res = qsc_memutils_are_equal(frags, fragr, MPDC_CRYPTO_SYMMETRIC_KEY_SIZE);
			}
		}
	}

	network_test_device_destroy(&spkg);

	return res;
}

static bool network_test_incremental_update(void)
{
	network_test_device_package spkg = { 0 };
	mpdc_network_packet reqt = { 0 };
	mpdc_network_packet resp = { 0 };
	uint8_t breqt[NETWORK_INCREMENTAL_UPDATE_REQUEST_PACKET_SIZE] = { 0 };
	uint8_t bresp[NETWORK_INCREMENTAL_UPDATE_RESPONSE_PACKET_SIZE] = { 0 };
	mpdc_protocol_errors merr;

	network_test_device_instantiate(&spkg);

	reqt.pmessage = breqt + MPDC_PACKET_HEADER_SIZE;
	resp.pmessage = bresp + MPDC_PACKET_HEADER_SIZE;

	mpdc_child_certificate ccert = { 0 };

	/* the server has received the agent topology node from the dla, 
	   and requests a certificate update from the agent */
	mpdc_network_incremental_update_request_state urs = {
		.rcert = &ccert,		/* certificate storage */
		.rnode = &spkg.mnde,	/* the remote node */
		.root = &spkg.root,		/* root certificate */
	};

	/* the server request packet */
	network_incremental_update_request_packet(&reqt, &urs);

	mpdc_network_incremental_update_response_state urr = {
		.csock = NULL,
		.rcert = &spkg.mcrt,
		.sigkey = spkg.mkp.prikey
	};

	/* the agent update response packet */
	merr = network_incremental_update_response_packet(&resp, &reqt, &urr);

	if (merr == mpdc_protocol_error_none)
	{
		/* server verifies the response */
		merr = network_incremental_update_verify(&urs, &resp);

		if (merr == mpdc_protocol_error_none)
		{
			/* received certificate and stored are identical */
			if (mpdc_certificate_child_are_equal(&ccert, &spkg.mcrt) == true)
			{
				merr = mpdc_protocol_error_none;
			}
			else
			{
				merr = mpdc_protocol_error_decoding_failure;
			}
		}
	}

	network_test_device_destroy(&spkg);

	return (merr == mpdc_protocol_error_none);
}

static bool network_test_join(void)
{
	network_test_device_package spkg = { 0 };
	mpdc_network_packet reqt = { 0 };
	mpdc_network_packet resp = { 0 };
	mpdc_child_certificate dccp = { 0 };
	uint8_t breqt[NETWORK_JOIN_REQUEST_PACKET_SIZE] = { 0 };
	uint8_t bresp[NETWORK_JOIN_RESPONSE_PACKET_SIZE] = { 0 };
	mpdc_protocol_errors merr;

	network_test_device_instantiate(&spkg);

	reqt.pmessage = breqt + MPDC_PACKET_HEADER_SIZE;	
	resp.pmessage = bresp + MPDC_PACKET_HEADER_SIZE;

	/* an agent joins the dla */
	mpdc_network_register_request_state jrs = {
		.lcert = &spkg.acrt,	/* agent certificate */
		.rcert = &spkg.dcrt,	/* dla certificate storage */
		.root = &spkg.root,		/* root certificate */
		.sigkey = spkg.akp.prikey	/* the agents signing key */
	};

	/* the agent join request packet */
	merr = network_register_request_packet(&reqt, &jrs);

	if (merr == mpdc_protocol_error_none)
	{
		mpdc_network_register_response_state jrr = {
			.csock = NULL,			/* the socket */
			.lcert = &spkg.dcrt,	/* dla certificate */
			.rcert = &spkg.acrt,	/* agent certificate storage */
			.root = &spkg.root,		/* root certificate */
			.sigkey = spkg.dkp.prikey	/* the dla signing key */
		};

		/* the dla join response packet */
		merr = network_register_response_packet(&resp, &jrr, &reqt);

		if (merr == mpdc_protocol_error_none)
		{
			/* the agent verifies the join response */
			merr = network_register_verify(&jrs, &resp);
		}
	}

	network_test_device_destroy(&spkg);

	return (merr == mpdc_protocol_error_none);
}

static bool network_test_mfk_exchange(void)
{
	network_test_device_package spkg = { 0 };
	mpdc_network_packet esta = { 0 };
	mpdc_network_packet reqt = { 0 };
	mpdc_network_packet resp = { 0 };
	uint8_t breqt[NETWORK_MFK_REQUEST_PACKET_SIZE] = { 0 };
	uint8_t bresp[NETWORK_MFK_RESPONSE_PACKET_SIZE] = { 0 };
	uint8_t besta[NETWORK_MFK_ESTABLISH_PACKET_SIZE] = { 0 };
	uint8_t mfa[MPDC_CRYPTO_SYMMETRIC_KEY_SIZE] = { 0 };
	uint8_t mfm[MPDC_CRYPTO_SYMMETRIC_KEY_SIZE] = { 0 };
	mpdc_protocol_errors merr;
	bool res;

	res = false;
	network_test_device_instantiate(&spkg);

	reqt.pmessage = breqt + MPDC_PACKET_HEADER_SIZE;
	resp.pmessage = bresp + MPDC_PACKET_HEADER_SIZE;
	esta.pmessage = besta + MPDC_PACKET_HEADER_SIZE;

	/* a server initiates an mfk exchange with an agent */
	mpdc_network_mfk_request_state sreqt = {
		.lcert = &spkg.mcrt,		/* mas certificate*/
		.rcert = &spkg.acrt,		/* agent certificate */
		.root = &spkg.root,			/* root certificate */
		.sigkey = spkg.mkp.prikey,	/* mas signing key */
		.mfk = mfm					/* mfk storage */
	};

	/* server starts the exchange with a request */
	merr = network_mfk_request_packet(&reqt, &sreqt);

	if (merr == mpdc_protocol_error_none)
	{
		mpdc_network_mfk_response_state sresp = {
			.lcert = &spkg.acrt,		/* agent certificate */
			.rcert = &spkg.mcrt,		/* mas certificate*/
			.root = &spkg.root,			/* root certificate */
			.sigkey = spkg.akp.prikey,	/* agent signing key */
			.mfk = mfa					/* mfk storage */
		};

		/* the agent responds */
		merr = network_mfk_response_packet(&resp, &reqt, &sresp);

		if (merr == mpdc_protocol_error_none)
		{
			/* the server creates the establish packet */
			merr = network_mfk_establish_packet(&esta, &resp, &sreqt);

			if (merr == mpdc_protocol_error_none)
			{
				/* the agent verifies the message */
				merr = network_mfk_verify_packet(&esta, &sresp);

				if (merr == mpdc_protocol_error_none)
				{
					/* both master keys are identical */
					res = qsc_memutils_are_equal(sreqt.mfk, sresp.mfk, MPDC_CRYPTO_SYMMETRIC_KEY_SIZE);
				}
			}
		}
	}

	network_test_device_destroy(&spkg);

	return res;
}

static bool network_test_register_update(void)
{
	network_test_device_package spkg = { 0 };
	mpdc_network_packet reqt = { 0 };
	mpdc_network_packet resp = { 0 };
	mpdc_child_certificate dccp = { 0 };
	uint8_t breqt[NETWORK_JOIN_UPDATE_REQUEST_PACKET_SIZE] = { 0 };
	uint8_t bresp[NETWORK_JOIN_UPDATE_RESPONSE_PACKET_SIZE + (MPDC_NETWORK_TOPOLOGY_NODE_SIZE * 2) + sizeof(uint32_t)] = { 0 };
	mpdc_protocol_errors merr;

	network_test_device_instantiate(&spkg);

	reqt.pmessage = breqt + MPDC_PACKET_HEADER_SIZE;	
	resp.pmessage = bresp + MPDC_PACKET_HEADER_SIZE;

	/* a client joins the dla and receives a topological update */
	mpdc_network_register_update_request_state jus = {
		.lcert = &spkg.ccrt,	/* client certificate */
		.list = &spkg.list,		/* topology list */
		.rcert = &spkg.dcrt,	/* dla certificate storage */
		.root = &spkg.root,		/* root certificate */
		.sigkey = spkg.ckp.prikey	/* client signing key */
	};

	/* client join up date request */
	merr = network_register_update_request_packet(&reqt, &jus);

	if (merr == mpdc_protocol_error_none)
	{
		uint8_t* pbuf;

		mpdc_network_register_update_response_state jur = {
			.lcert = &spkg.dcrt,	/* dla certificate */
			.list = &spkg.list,		/* topology list */
			.rcert = &spkg.ccrt,	/* client certificate storage */
			.root = &spkg.root,		/* root certificate */
			.sigkey = spkg.dkp.prikey	/* dla signing key */
		};

		pbuf = (uint8_t*)qsc_memutils_malloc(NETWORK_JOIN_UPDATE_RESPONSE_PACKET_SIZE);

		if (pbuf != NULL)
		{
			/* dla join update resonse */
			merr = network_register_update_response_packet(&resp, &jur, pbuf, &reqt);

			if (merr == mpdc_protocol_error_none)
			{
				/* client verifies the update, updates added to list */
				merr = network_register_update_verify(&jus, &resp);
			}

			qsc_memutils_alloc_free(pbuf);
		}
	}

	network_test_device_destroy(&spkg);

	return (merr == mpdc_protocol_error_none);
}

static bool network_test_remote_signing(void)
{
	network_test_device_package spkg = { 0 };
	mpdc_signature_keypair ckp3 = { 0 };
	mpdc_certificate_expiration exp = { 0 };
	mpdc_child_certificate rcert = { 0 };
	mpdc_network_packet reqt = { 0 };
	mpdc_network_packet resp = { 0 };
	uint8_t breqt[NETWORK_REMOTE_SIGNING_REQUEST_PACKET_SIZE] = { 0 };
	uint8_t bresp[NETWORK_REMOTE_SIGNING_RESPONSE_PACKET_SIZE] = { 0 };
	mpdc_protocol_errors merr;

	network_test_device_instantiate(&spkg);

	reqt.pmessage = breqt + MPDC_PACKET_HEADER_SIZE;	
	resp.pmessage = bresp + MPDC_PACKET_HEADER_SIZE;

	mpdc_certificate_signature_generate_keypair(&ckp3);
	mpdc_certificate_expiration_set_days(&exp, 0, 100);
	mpdc_certificate_child_create(&rcert, ckp3.pubkey, &exp, "XYZ_CLT3", mpdc_network_designation_client);

	mpdc_network_remote_signing_request_state rsr = {
		.address = NULL,
		.rcert = &rcert,
		.root = &spkg.root,
		.sigkey = spkg.dkp.prikey
	};

	merr = network_remote_signing_request_packet(&rsr, &reqt);

	if (merr == mpdc_protocol_error_none)
	{
		mpdc_child_certificate scert = { 0 };

		mpdc_network_remote_signing_response_state rsq = {
			.csock = NULL,
			.dcert = &spkg.dcrt,
			.rcert = &scert,
			.root = &spkg.root,
			.sigkey = spkg.rkp.prikey
		};

		merr = network_remote_signing_response_verify(&rsq, &reqt);

		if (merr == mpdc_protocol_error_none)
		{
			merr = network_remote_signing_response_packet(&rsq, &resp);

			if (merr == mpdc_protocol_error_none)
			{
				merr = network_remote_signing_request_verify(&rsr, &resp);
			}
		}
	}

	network_test_device_destroy(&spkg);

	return (merr == mpdc_protocol_error_none);
}

static bool network_test_topological_query(void)
{
	network_test_device_package spkg = { 0 };
	mpdc_network_packet reqt = { 0 };
	mpdc_network_packet resp = { 0 };
	mpdc_topology_node_state rnode = { 0 };
	uint8_t breqt[NETWORK_TOPOLOGY_QUERY_REQUEST_PACKET_SIZE] = { 0 };
	uint8_t bresp[NETWORK_TOPOLOGY_QUERY_RESPONSE_PACKET_SIZE] = { 0 };
	uint8_t query[NETWORK_TOPOLOGY_QUERY_SIZE] = { 0 };
	mpdc_protocol_errors merr;

	reqt.pmessage = breqt + MPDC_PACKET_HEADER_SIZE;
	resp.pmessage = bresp + MPDC_PACKET_HEADER_SIZE;
	network_test_device_instantiate(&spkg);

	const mpdc_network_topological_query_request_state qrs = {
		.dcert = &spkg.dcrt,			/* the dla certificate */
		.dnode = &spkg.dnde,			/* the dla node */
		.issuer = spkg.ccrt2.issuer,	/* client target issuer string */
		.rnode = &rnode,				/* the remote node */
		.serial = spkg.ccrt.serial,		/* the local serial number */
		.sigkey = spkg.ckp.prikey		/* client signing key */
	};

	/* a client requests another clients node description from the dla */
	merr = network_topological_query_request_packet(&reqt, &qrs);

	if (merr == mpdc_protocol_error_none)
	{
		mpdc_network_topological_query_response_state tsr = {
			.csock = NULL,				/* the socket */
			.ccert = &spkg.ccrt,		/* the client certificate */
			.rnode = &spkg.cnde,		/* the remote client node */
			.sigkey = spkg.dkp.prikey,	/* the dla signing key */
		};

		/* the DLA verifies the request */
		merr = network_topological_query_response_verify(query, &tsr, &reqt);

		if (merr == mpdc_protocol_error_none)
		{
			/* the DLA creates the response packet */
			merr = network_topological_query_response_packet(&resp, &tsr, &reqt);
		}
	}

	network_test_device_destroy(&spkg);

	return (merr == mpdc_protocol_error_none);
}

static bool network_test_topological_status(void)
{
	network_test_device_package spkg = { 0 };
	mpdc_network_packet reqt = { 0 };
	mpdc_network_packet resp = { 0 };
	uint8_t breqt[NETWORK_TOPOLOGY_STATUS_REQUEST_PACKET_SIZE] = { 0 };
	uint8_t bresp[NETWORK_TOPOLOGY_STATUS_RESPONSE_PACKET_SIZE] = { 0 };
	mpdc_protocol_errors merr;

	network_test_device_instantiate(&spkg);

	reqt.pmessage = breqt + MPDC_PACKET_HEADER_SIZE;
	resp.pmessage = bresp + MPDC_PACKET_HEADER_SIZE;

	mpdc_network_topological_status_request_state tsq = {
		.lnode = &spkg.cnde,		/* the client node */
		.rcert = &spkg.ccrt2,		/* the client certificate */
		.rnode = &spkg.cnde2,
		.sigkey = spkg.ckp.prikey	/* the dla signing key */
	};

	/* sent from the DLA to the client */
	merr = network_topological_status_request_packet(&reqt, &tsq);

	if (merr == mpdc_protocol_error_none)
	{
		mpdc_network_topological_status_response_state tsr = {
			.csock = NULL,				/* the socket */
			.lnode = &spkg.cnde2,		/* the local client node */
			.rcert = &spkg.ccrt,		/* the dla certificate */
			.sigkey = spkg.ckp2.prikey	/* the client signing key */
		};

		/* the DLA creates the client response packet */
		merr = network_topological_status_response_verify(&tsr, &reqt);

		if (merr == mpdc_protocol_error_none)
		{
			/* the client verifies the request from the DLA */
			merr = network_topological_status_response_packet(&resp, &tsr, &reqt);

			if (merr == mpdc_protocol_error_none)
			{
				/* the DLA checks the client response */
				merr = mpdc_network_topological_status_request_verify(&tsq, &resp);
			}
		}
	}
	
	network_test_device_destroy(&spkg);

	return (merr == mpdc_protocol_error_none);
}

bool mpdc_network_protocols_test(void)
{
	bool res;

	res = network_test_announce_test();

	if (res == true)
	{
		res = network_test_converge();

		if (res == true)
		{
			res = network_test_fkey_encryption();

			if (res == true)
			{
				res = network_test_fragment_collection();

				if (res == true)
				{
					res = network_test_fkey_exchange();

					if (res == true)
					{
						res = network_test_incremental_update();

						if (res == true)
						{
							res = network_test_join();

							if (res == true)
							{
								res = network_test_register_update();

								if (res == true)
								{
									res = network_test_mfk_exchange();

									if (res == true)
									{
										res = network_test_remote_signing();

										if (res == true)
										{
											res = network_test_topological_query();

											if (res == true)
											{
												res = network_test_topological_status();
											}
										}
									}
								}
							}
						}
					}
				}
			}
		}
	}

	return res;
}
#endif
