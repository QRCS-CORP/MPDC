#include "mpdc.h"
#include "certificate.h"
#include "resources.h"
#include "encoding.h"
#include "intutils.h"
#include "memutils.h"
#include "stringutils.h"
#include "timestamp.h"

void mpdc_connection_close(qsc_socket* rsock, mpdc_network_errors err, bool notify)
{
	MPDC_ASSERT(rsock != NULL);

	if (rsock != NULL)
	{
		if (qsc_socket_is_connected(rsock) == true)
		{
			if (notify == true)
			{
				mpdc_network_packet resp = { 0 };
				uint8_t spct[MPDC_PACKET_HEADER_SIZE + sizeof(uint8_t)] = {0};

				/* send a disconnect message */
				resp.flag = mpdc_network_flag_tunnel_connection_terminate;
				resp.sequence = MPDC_PACKET_SEQUENCE_TERMINATOR;
				resp.msglen = 1;
				mpdc_packet_header_serialize(&resp, spct);

				spct[MPDC_PACKET_HEADER_SIZE] = (uint8_t)err;
				
				qsc_socket_send(rsock, spct, sizeof(spct), qsc_socket_send_flag_none);
			}

			/* close the socket */
			qsc_socket_shut_down(rsock, qsc_socket_shut_down_flag_both);
			qsc_socket_close_socket(rsock);
		}
	}
}

mpdc_protocol_errors mpdc_decrypt_packet(mpdc_connection_state* pcns, uint8_t* message, size_t* msglen, const mpdc_network_packet* packetin)
{
	MPDC_ASSERT(pcns != NULL);
	MPDC_ASSERT(packetin != NULL);
	MPDC_ASSERT(message != NULL);
	MPDC_ASSERT(msglen != NULL);

	mpdc_protocol_errors merr;

	if (pcns != NULL && message != NULL && msglen != NULL && packetin != NULL)
	{
		*msglen = 0;
		pcns->rxseq += 1;

		if (mpdc_packet_time_valid(packetin) == true)
		{
			if (packetin->sequence == pcns->rxseq)
			{
				if (pcns->exflag == mpdc_network_flag_tunnel_session_established)
				{
					uint8_t hdr[MPDC_PACKET_HEADER_SIZE] = { 0 };

					/* serialize the header and add it to the ciphers associated data */
					mpdc_packet_header_serialize(packetin, hdr);
					mpdc_cipher_set_associated(&pcns->rxcpr, hdr, MPDC_PACKET_HEADER_SIZE);
					*msglen = packetin->msglen - MPDC_CRYPTO_SYMMETRIC_MAC_SIZE;

					/* authenticate then decrypt the data */
					if (mpdc_cipher_transform(&pcns->rxcpr, message, packetin->pmessage, *msglen) == true)
					{
						merr = mpdc_protocol_error_none;
					}
					else
					{
						*msglen = 0;
						merr = mpdc_protocol_error_authentication_failure;
					}
				}
				else
				{
					merr = mpdc_protocol_error_packet_header_invalid;
				}
			}
			else
			{
				merr = mpdc_protocol_error_packet_unsequenced;
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

mpdc_protocol_errors mpdc_encrypt_packet(mpdc_connection_state* pcns, mpdc_network_packet* packetout, const uint8_t* message, size_t msglen)
{
	MPDC_ASSERT(pcns != NULL);
	MPDC_ASSERT(message != NULL);
	MPDC_ASSERT(packetout != NULL);

	mpdc_protocol_errors merr;

	if (pcns != NULL && message != NULL && packetout != NULL)
	{
		if (pcns->exflag == mpdc_network_flag_tunnel_session_established && msglen != 0)
		{
			uint8_t hdr[MPDC_PACKET_HEADER_SIZE] = { 0 };

			/* assemble the encryption packet */
			pcns->txseq += 1;
			packetout->flag = mpdc_network_flag_tunnel_encrypted_message;
			packetout->msglen = (uint32_t)msglen + MPDC_CRYPTO_SYMMETRIC_MAC_SIZE;
			packetout->sequence = pcns->txseq;
			mpdc_packet_set_utc_time(packetout);

			/* serialize the header and add it to the ciphers associated data */
			mpdc_packet_header_serialize(packetout, hdr);
			mpdc_cipher_set_associated(&pcns->txcpr, hdr, MPDC_PACKET_HEADER_SIZE);
			/* encrypt the message */
			mpdc_cipher_transform(&pcns->txcpr, packetout->pmessage, message, msglen);

			merr = mpdc_protocol_error_none;
		}
		else
		{
			merr = mpdc_protocol_error_channel_down;
		}
	}
	else
	{
		merr = mpdc_protocol_error_invalid_request;
	}

	return merr;
}

const char* mpdc_network_error_to_string(mpdc_network_errors err)
{
	const char* dsc;

	dsc = NULL;

	if ((uint32_t)err < MPDC_ERROR_STRING_DEPTH)
	{
		dsc = MPDC_NETWORK_ERROR_STRINGS[(size_t)err];
	}

	return dsc;
}

const char* mpdc_protocol_error_to_string(mpdc_protocol_errors err)
{
	const char* dsc;

	dsc = NULL;

	if ((uint32_t)err < MPDC_ERROR_STRING_DEPTH)
	{
		dsc = MPDC_PROTOCOL_ERROR_STRINGS[(size_t)err];
	}

	return dsc;
}

void mpdc_packet_clear(mpdc_network_packet* packet)
{
	qsc_memutils_clear(packet->pmessage, packet->msglen);
	packet->flag = (uint8_t)mpdc_network_flag_none;
	packet->msglen = 0;
	packet->sequence = 0;
}

void mpdc_packet_error_message(mpdc_network_packet* packet, mpdc_protocol_errors error)
{
	MPDC_ASSERT(packet != NULL);

	if (packet != NULL)
	{
		packet->flag = mpdc_network_flag_system_error_condition;
		packet->pmessage[0] = (uint8_t)error;
		packet->msglen = 1;
		packet->sequence = MPDC_PACKET_SEQUENCE_TERMINATOR;
	}
}

void mpdc_packet_header_deserialize(const uint8_t* header, mpdc_network_packet* packet)
{
	MPDC_ASSERT(header != NULL);
	MPDC_ASSERT(packet != NULL);

	if (header != NULL && packet != NULL)
	{
		size_t pos;

		packet->flag = header[0];
		pos = sizeof(uint8_t);
		packet->msglen = qsc_intutils_le8to32(header + pos);
		pos += sizeof(uint32_t);
		packet->sequence = qsc_intutils_le8to64(header + pos);
		pos += sizeof(uint64_t);
		packet->utctime = qsc_intutils_le8to64(header + pos);
	}
}

void mpdc_packet_header_serialize(const mpdc_network_packet* packet, uint8_t* header)
{
	MPDC_ASSERT(header != NULL);
	MPDC_ASSERT(packet != NULL);

	if (header != NULL && packet != NULL)
	{
		size_t pos;

		header[0] = packet->flag;
		pos = sizeof(uint8_t);
		qsc_intutils_le32to8(header + pos, packet->msglen);
		pos += sizeof(uint32_t);
		qsc_intutils_le64to8(header + pos, packet->sequence);
		pos += sizeof(uint64_t);
		qsc_intutils_le64to8(header + pos, packet->utctime);
	}
}

void mpdc_packet_set_utc_time(mpdc_network_packet* packet)
{
	packet->utctime = qsc_timestamp_datetime_utc();
}

bool mpdc_packet_time_valid(const mpdc_network_packet* packet)
{
	uint64_t ltime;

	ltime = qsc_timestamp_datetime_utc();

	return (ltime >= packet->utctime - MPDC_PACKET_TIME_THRESHOLD && ltime <= packet->utctime + MPDC_PACKET_TIME_THRESHOLD);
}

size_t mpdc_packet_to_stream(const mpdc_network_packet* packet, uint8_t* pstream)
{
	MPDC_ASSERT(packet != NULL);
	MPDC_ASSERT(pstream != NULL);

	size_t res;

	res = 0;

	if (packet != NULL && pstream != NULL)
	{
		size_t pos;

		pstream[0] = packet->flag;
		pos = sizeof(uint8_t);
		qsc_intutils_le32to8(pstream + pos, packet->msglen);
		pos += sizeof(uint32_t);
		qsc_intutils_le64to8(pstream + pos, packet->sequence);
		pos += sizeof(uint64_t);
		qsc_intutils_le64to8(pstream + pos, packet->utctime);
		pos += sizeof(uint64_t);

		if (packet->msglen <= MPDC_MESSAGE_MAX_SIZE)
		{
			qsc_memutils_copy(pstream + pos, packet->pmessage, packet->msglen);
			res = pos + packet->msglen;
		}
	}

	return res;
}

void mpdc_stream_to_packet(const uint8_t* pstream, mpdc_network_packet* packet)
{
	MPDC_ASSERT(packet != NULL);
	MPDC_ASSERT(pstream != NULL);

	if (packet != NULL && pstream != NULL)
	{
		size_t pos;

		packet->flag = pstream[0];
		pos = sizeof(uint8_t);
		packet->msglen = qsc_intutils_le8to32(pstream + pos);
		pos += sizeof(uint32_t);
		packet->sequence = qsc_intutils_le8to64(pstream + pos);
		pos += sizeof(uint64_t);
		packet->utctime = qsc_intutils_le8to64(pstream + pos);
		pos += sizeof(uint64_t);

		if (packet->msglen <= MPDC_MESSAGE_MAX_SIZE)
		{
			qsc_memutils_copy(packet->pmessage, pstream + pos, packet->msglen);
		}
	}
}

void mpdc_connection_state_dispose(mpdc_connection_state* pcns)
{
	MPDC_ASSERT(pcns != NULL);

	if (pcns != NULL)
	{
		mpdc_cipher_dispose(&pcns->rxcpr);
		mpdc_cipher_dispose(&pcns->txcpr);
		qsc_memutils_clear((uint8_t*)&pcns->target, sizeof(qsc_socket));
		pcns->rxseq = 0;
		pcns->txseq = 0;
		pcns->instance = 0;
		pcns->exflag = mpdc_network_flag_none;
	}
}
