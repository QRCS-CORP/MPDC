#include "certificate.h"
#include "crypto.h"
#include "acp.h"
#include "encoding.h"
#include "fileutils.h"
#include "memutils.h"
#include "sha3.h"
#include "stringutils.h"
#include "timestamp.h"
#if defined(MPDC_DEBUG_TESTS_RUN)
#include "consoleutils.h"
#endif

mpdc_configuration_sets mpdc_certificate_algorithm_decode(const char* name)
{
	assert(name != NULL);

	mpdc_configuration_sets cset;

	cset = mpdc_configuration_set_none;

	if (name != NULL)
	{
		if (qsc_stringutils_compare_strings("dilithium-s1_kyber-s1_rcs-256_sha3-256", name, MPDC_PROTOCOL_SET_SIZE))
		{
			cset = mpdc_configuration_set_dilithium1_kyber1_rcs256_shake256;
		}
		else if (qsc_stringutils_compare_strings("dilithium-s3_kyber-s3_rcs-256_sha3-256", name, MPDC_PROTOCOL_SET_SIZE))
		{
			cset = mpdc_configuration_set_dilithium3_kyber3_rcs256_shake256;
		}
		else if (qsc_stringutils_compare_strings("dilithium-s5_kyber-s5_rcs-256_sha3-256", name, MPDC_PROTOCOL_SET_SIZE))
		{
			cset = mpdc_configuration_set_dilithium5_kyber5_rcs256_shake256;
		}
		else if (qsc_stringutils_compare_strings("dilithium-s5_kyber-s6_rcs-512_sha3-512", name, MPDC_PROTOCOL_SET_SIZE))
		{
			cset = mpdc_configuration_set_dilithium5_kyber6_rcs512_shake256;
		}
		else if (qsc_stringutils_compare_strings("sphincs-1f_mceliece-s1_rcs-256_sha3-256", name, MPDC_PROTOCOL_SET_SIZE))
		{
			cset = mpdc_configuration_set_sphincsplus1f_mceliece1_rcs256_shake256;
		}
		else if (qsc_stringutils_compare_strings("sphincs-1s_mceliece-s1_rcs-256_sha3-256", name, MPDC_PROTOCOL_SET_SIZE))
		{
			cset = mpdc_configuration_set_sphincsplus1s_mceliece1_rcs256_shake256;
		}
		else if (qsc_stringutils_compare_strings("sphincs-3f_mceliece-s3_rcs-256_sha3-256", name, MPDC_PROTOCOL_SET_SIZE))
		{
			cset = mpdc_configuration_set_sphincsplus3f_mceliece3_rcs256_shake256;
		}
		else if (qsc_stringutils_compare_strings("sphincs-3s_mceliece-s3_rcs-256_sha3-256", name, MPDC_PROTOCOL_SET_SIZE))
		{
			cset = mpdc_configuration_set_sphincsplus3s_mceliece3_rcs256_shake256;
		}
		else if (qsc_stringutils_compare_strings("sphincs-5f_mceliece-s5_rcs-256_sha3-256", name, MPDC_PROTOCOL_SET_SIZE))
		{
			cset = mpdc_configuration_set_sphincsplus5f_mceliece5_rcs256_shake256;
		}
		else if (qsc_stringutils_compare_strings("sphincs-5s_mceliece-s5_rcs-256_sha3-256", name, MPDC_PROTOCOL_SET_SIZE))
		{
			cset = mpdc_configuration_set_sphincsplus5s_mceliece5_rcs256_shake256;
		}
		else if (qsc_stringutils_compare_strings("sphincs-5f_mceliece-s6_rcs-256_sha3-256", name, MPDC_PROTOCOL_SET_SIZE))
		{
			cset = mpdc_configuration_set_sphincsplus5f_mceliece6_rcs256_shake256;
		}
		else if (qsc_stringutils_compare_strings("sphincs-5s_mceliece-s6_rcs-256_sha3-256", name, MPDC_PROTOCOL_SET_SIZE))
		{
			cset = mpdc_configuration_set_sphincsplus5s_mceliece6_rcs256_shake256;
		}
		else if (qsc_stringutils_compare_strings("sphincs-5f_mceliece-s7_rcs-256_sha3-256", name, MPDC_PROTOCOL_SET_SIZE))
		{
			cset = mpdc_configuration_set_sphincsplus5f_mceliece7_rcs256_shake256;
		}
		else if (qsc_stringutils_compare_strings("sphincs-5s_mceliece-s7_rcs-256_sha3-256", name, MPDC_PROTOCOL_SET_SIZE))
		{
			cset = mpdc_configuration_set_sphincsplus5s_mceliece7_rcs256_shake256;
		}
		else
		{
			cset = mpdc_configuration_set_none;
		}
	}

	return cset;
}

void mpdc_certificate_algorithm_encode(char* name, mpdc_configuration_sets conf)
{
	assert(name != NULL);

	if (name != NULL)
	{
		if (conf == mpdc_configuration_set_dilithium1_kyber1_rcs256_shake256)
		{
			qsc_stringutils_copy_string(name, MPDC_PROTOCOL_SET_SIZE, "dilithium-s1_kyber-s1_rcs-256_sha3-256");
		}
		else if (conf == mpdc_configuration_set_dilithium3_kyber3_rcs256_shake256)
		{
			qsc_stringutils_copy_string(name, MPDC_PROTOCOL_SET_SIZE, "dilithium-s3_kyber-s3_rcs-256_sha3-256");
		}
		else if (conf == mpdc_configuration_set_dilithium5_kyber5_rcs256_shake256)
		{
			qsc_stringutils_copy_string(name, MPDC_PROTOCOL_SET_SIZE, "dilithium-s5_kyber-s5_rcs-256_sha3-256");
		}
		else if (conf == mpdc_configuration_set_dilithium5_kyber6_rcs512_shake256)
		{
			qsc_stringutils_copy_string(name, MPDC_PROTOCOL_SET_SIZE, "dilithium-s5_kyber-s6_rcs-512_sha3-512");
		}
		else if (conf == mpdc_configuration_set_sphincsplus1f_mceliece1_rcs256_shake256)
		{
			qsc_stringutils_copy_string(name, MPDC_PROTOCOL_SET_SIZE, "sphincs-1f_mceliece-s1_rcs-256_sha3-256");
		}
		else if (conf == mpdc_configuration_set_sphincsplus1s_mceliece1_rcs256_shake256)
		{
			qsc_stringutils_copy_string(name, MPDC_PROTOCOL_SET_SIZE, "sphincs-1s_mceliece-s1_rcs-256_sha3-256");
		}
		else if (conf == mpdc_configuration_set_sphincsplus3f_mceliece3_rcs256_shake256)
		{
			qsc_stringutils_copy_string(name, MPDC_PROTOCOL_SET_SIZE, "sphincs-3f_mceliece-s3_rcs-256_sha3-256");
		}
		else if (conf == mpdc_configuration_set_sphincsplus3s_mceliece3_rcs256_shake256)
		{
			qsc_stringutils_copy_string(name, MPDC_PROTOCOL_SET_SIZE, "sphincs-3s_mceliece-s3_rcs-256_sha3-256");
		}
		else if (conf == mpdc_configuration_set_sphincsplus5f_mceliece5_rcs256_shake256)
		{
			qsc_stringutils_copy_string(name, MPDC_PROTOCOL_SET_SIZE, "sphincs-5f_mceliece-s5_rcs-256_sha3-256");
		}
		else if (conf == mpdc_configuration_set_sphincsplus5s_mceliece5_rcs256_shake256)
		{
			qsc_stringutils_copy_string(name, MPDC_PROTOCOL_SET_SIZE, "sphincs-5s_mceliece-s5_rcs-256_sha3-256");
		}
		else if (conf == mpdc_configuration_set_sphincsplus5f_mceliece6_rcs256_shake256)
		{
			qsc_stringutils_copy_string(name, MPDC_PROTOCOL_SET_SIZE, "sphincs-5f_mceliece-s6_rcs-256_sha3-256");
		}
		else if (conf == mpdc_configuration_set_sphincsplus5s_mceliece6_rcs256_shake256)
		{
			qsc_stringutils_copy_string(name, MPDC_PROTOCOL_SET_SIZE, "sphincs-5s_mceliece-s6_rcs-256_sha3-256");
		}
		else if (conf == mpdc_configuration_set_sphincsplus5f_mceliece7_rcs256_shake256)
		{
			qsc_stringutils_copy_string(name, MPDC_PROTOCOL_SET_SIZE, "sphincs-5f_mceliece-s7_rcs-256_sha3-256");
		}
		else if (conf == mpdc_configuration_set_sphincsplus5s_mceliece7_rcs256_shake256)
		{
			qsc_stringutils_copy_string(name, MPDC_PROTOCOL_SET_SIZE, "sphincs-5s_mceliece-s7_rcs-256_sha3-256");
		}
	}
}

bool mpdc_certificate_algorithm_enabled(mpdc_configuration_sets conf)
{
	assert(conf != 0);

	return (conf == MPDC_CONFIGURATION_SET);
}

bool mpdc_certificate_child_are_equal(const mpdc_child_certificate* a, const mpdc_child_certificate* b)
{
	assert(a != NULL);
	assert(b != NULL);

	bool res;

	res = false;

	if (a != NULL)
	{
		if (a->algorithm == b->algorithm && a->version == b->version && a->designation == b->designation &&
			a->expiration.from == b->expiration.from && a->expiration.to == b->expiration.to)
		{
			if (qsc_memutils_are_equal(a->issuer, b->issuer, MPDC_CERTIFICATE_ISSUER_SIZE) == true)
			{
				if (qsc_memutils_are_equal(a->serial, b->serial, MPDC_CERTIFICATE_SERIAL_SIZE) == true)
				{
					if (qsc_memutils_are_equal(a->csig, b->csig, MPDC_CERTIFICATE_SIGNED_HASH_SIZE) == true)
					{
						if (qsc_memutils_are_equal(a->rootser, b->rootser, MPDC_CERTIFICATE_SERIAL_SIZE) == true)
						{
							res = qsc_memutils_are_equal(a->verkey, b->verkey, MPDC_ASYMMETRIC_VERIFICATION_KEY_SIZE);
						}
					}
				}
			}
		}
	}

	return res;
}

void mpdc_certificate_child_copy(mpdc_child_certificate* output, const mpdc_child_certificate* input)
{
	assert(output != NULL);
	assert(input != NULL);

	if (output != NULL && input != NULL)
	{
		qsc_memutils_copy(output->csig, input->csig, MPDC_CERTIFICATE_SIGNED_HASH_SIZE);
		qsc_memutils_copy(output->verkey, input->verkey, MPDC_ASYMMETRIC_VERIFICATION_KEY_SIZE);
		qsc_memutils_copy(output->issuer, input->issuer, MPDC_CERTIFICATE_ISSUER_SIZE);
		qsc_memutils_copy(output->serial, input->serial, MPDC_CERTIFICATE_SERIAL_SIZE);
		qsc_memutils_copy(output->rootser, input->rootser, MPDC_CERTIFICATE_SERIAL_SIZE);
		qsc_memutils_copy(&output->expiration, &input->expiration, MPDC_CERTIFICATE_EXPIRATION_SIZE);
		qsc_memutils_copy(&output->designation, &input->designation, MPDC_CERTIFICATE_DESIGNATION_SIZE);
		qsc_memutils_copy(&output->algorithm, &input->algorithm, MPDC_CERTIFICATE_ALGORITHM_SIZE);
		qsc_memutils_copy(&output->version, &input->version, MPDC_CERTIFICATE_VERSION_SIZE);
	}
}

void mpdc_certificate_child_create(mpdc_child_certificate* child, const uint8_t* pubkey, const mpdc_certificate_expiration* expiration, const char* issuer, mpdc_network_designations designation)
{
	assert(child != NULL);
	assert(pubkey != NULL);
	assert(expiration != NULL);
	assert(issuer != NULL);

	if (child != NULL && pubkey != NULL && expiration != NULL && issuer != NULL)
	{
		qsc_memutils_clear(child, MPDC_CERTIFICATE_CHILD_SIZE);
		child->algorithm = (uint8_t)MPDC_CONFIGURATION_SET;
		qsc_stringutils_copy_string(child->issuer, MPDC_CERTIFICATE_ISSUER_SIZE, issuer);
		qsc_memutils_copy(&child->expiration, expiration, MPDC_CERTIFICATE_EXPIRATION_SIZE);
		qsc_memutils_copy(child->verkey, pubkey, MPDC_ASYMMETRIC_VERIFICATION_KEY_SIZE);
		qsc_acp_generate(child->serial, MPDC_CERTIFICATE_SERIAL_SIZE);
		child->designation = (uint8_t)designation;
		child->version = (uint8_t)mpdc_version_set_one_zero;
	}
}

bool mpdc_certificate_child_decode(mpdc_child_certificate* child, const char enck[MPDC_CHILD_CERTIFICATE_STRING_SIZE])
{
	assert(child != NULL);
	assert(enck != NULL);

	bool res;

	res = false;

	if (child != NULL && enck != NULL)
	{
		char tmpvk[MPDC_VERIFICATION_KEY_ENCODING_SIZE] = { 0 };
		char dtm[QSC_TIMESTAMP_STRING_SIZE] = { 0 };
		char tmpsg[MPDC_SIGNATURE_ENCODING_SIZE + ((MPDC_SIGNATURE_ENCODING_SIZE / 64) + 1)] = { 0 };
		const char* penc;
		size_t slen;

		penc = enck;
		penc += qsc_stringutils_string_size(MPDC_CHILD_CERTIFICATE_HEADER) + qsc_stringutils_string_size(MPDC_CHILD_CERTIFICATE_SERIAL_PREFIX) + 1;
		qsc_intutils_hex_to_bin(penc, child->serial, MPDC_CERTIFICATE_SERIAL_SIZE * 2);
		penc += (MPDC_CERTIFICATE_SERIAL_SIZE * 2);

		penc += qsc_stringutils_string_size(MPDC_CHILD_CERTIFICATE_ISSUER_PREFIX) + 1;
		slen = qsc_stringutils_find_string(penc, "\n");
		qsc_memutils_copy(child->issuer, penc, slen);
		penc += slen;

		penc += qsc_stringutils_string_size(MPDC_CHILD_CERTIFICATE_VALID_FROM_PREFIX) + 1;
		slen = QSC_TIMESTAMP_STRING_SIZE;
		qsc_memutils_copy(dtm, penc, slen);
		child->expiration.from = qsc_timestamp_datetime_to_seconds(dtm);
		penc += slen;

		penc += qsc_stringutils_string_size(MPDC_CHILD_CERTIFICATE_EXPIRATION_TO_PREFIX) - 1;
		slen = QSC_TIMESTAMP_STRING_SIZE;
		qsc_memutils_copy(dtm, penc, slen);
		child->expiration.to = qsc_timestamp_datetime_to_seconds(dtm);
		penc += slen;

		penc += qsc_stringutils_string_size(MPDC_CHILD_CERTIFICATE_ALGORITHM_PREFIX) + 1;
		slen = qsc_stringutils_find_string(penc, "\n");
		child->algorithm = mpdc_certificate_algorithm_decode(penc);
		penc += slen;

		penc += qsc_stringutils_string_size(MPDC_CHILD_CERTIFICATE_VERSION_PREFIX) + 1;
		slen = qsc_stringutils_find_string(penc, "\n");

		if (qsc_stringutils_compare_strings(penc, MPDC_ACTIVE_VERSION_STRING, slen) == true)
		{
			child->version = mpdc_version_set_one_zero;
		}
		else
		{
			child->version = mpdc_version_set_none;
		}

		penc += slen;
		penc += qsc_stringutils_string_size(MPDC_CHILD_CERTIFICATE_DESIGNATION_PREFIX) + 1;
		slen = qsc_stringutils_find_string(penc, "\n");
		child->designation = mpdc_certificate_designation_decode(penc);
		penc += slen;
		++penc;

		penc += qsc_stringutils_string_size(MPDC_CHILD_CERTIFICATE_ADDRESS_PREFIX);
		slen = qsc_stringutils_find_string(penc, "\n");
		penc += slen;
		++penc;

		penc += qsc_stringutils_string_size(MPDC_CHILD_CERTIFICATE_ROOT_HASH_PREFIX) + 1;
		slen = sizeof(tmpsg);
		qsc_stringutils_remove_line_breaks(tmpsg, sizeof(tmpsg), penc, slen);
		res = qsc_encoding_base64_decode(child->csig, MPDC_CERTIFICATE_SIGNED_HASH_SIZE, tmpsg, MPDC_SIGNATURE_ENCODING_SIZE);
		penc += slen;

		slen = qsc_stringutils_find_string(penc, "\n");
		qsc_stringutils_remove_line_breaks(tmpvk, sizeof(tmpvk), penc, MPDC_CHILD_CERTIFICATE_STRING_SIZE);
		res = qsc_encoding_base64_decode(child->verkey, MPDC_ASYMMETRIC_VERIFICATION_KEY_SIZE, tmpvk, MPDC_VERIFICATION_KEY_ENCODING_SIZE);
	}

	return res;
}

void mpdc_certificate_child_deserialize(mpdc_child_certificate* child, const uint8_t* input)
{
	assert(child != NULL);
	assert(input != NULL);

	size_t pos;

	if (child != NULL && input != NULL)
	{
		qsc_memutils_copy(child->csig, input, MPDC_CERTIFICATE_SIGNED_HASH_SIZE);
		pos = MPDC_CERTIFICATE_SIGNED_HASH_SIZE;
		qsc_memutils_copy(child->verkey, input + pos, MPDC_ASYMMETRIC_VERIFICATION_KEY_SIZE);
		pos += MPDC_ASYMMETRIC_VERIFICATION_KEY_SIZE;
		qsc_memutils_copy(child->issuer, input + pos, MPDC_CERTIFICATE_ISSUER_SIZE);
		pos += MPDC_CERTIFICATE_ISSUER_SIZE;
		qsc_memutils_copy(child->serial, input + pos, MPDC_CERTIFICATE_SERIAL_SIZE);
		pos += MPDC_CERTIFICATE_SERIAL_SIZE;
		qsc_memutils_copy(child->rootser, input + pos, MPDC_CERTIFICATE_SERIAL_SIZE);
		pos += MPDC_CERTIFICATE_SERIAL_SIZE;
		qsc_memutils_copy(&child->expiration, input + pos, MPDC_CERTIFICATE_EXPIRATION_SIZE);
		pos += MPDC_CERTIFICATE_EXPIRATION_SIZE;
		qsc_memutils_copy(&child->designation, input + pos, MPDC_CERTIFICATE_DESIGNATION_SIZE);
		pos += MPDC_CERTIFICATE_DESIGNATION_SIZE;
		qsc_memutils_copy(&child->algorithm, input + pos, MPDC_CERTIFICATE_ALGORITHM_SIZE);
		pos += MPDC_CERTIFICATE_ALGORITHM_SIZE;
		qsc_memutils_copy(&child->version, input + pos, MPDC_CERTIFICATE_VERSION_SIZE);
	}
}

size_t mpdc_certificate_child_encode(char enck[MPDC_CHILD_CERTIFICATE_STRING_SIZE], const mpdc_child_certificate* child)
{
	assert(enck != NULL);
	assert(child != NULL);

	size_t slen;
	size_t spos;

	spos = 0;

	if (enck != NULL && child != NULL)
	{
		char dtm[QSC_TIMESTAMP_STRING_SIZE] = { 0 };
		char hexid[MPDC_CERTIFICATE_SERIAL_SIZE * 2] = { 0 };
		char tmpvk[MPDC_VERIFICATION_KEY_ENCODING_SIZE] = { 0 };
		char tmpsg[MPDC_SIGNATURE_ENCODING_SIZE] = { 0 };

		slen = qsc_stringutils_string_size(MPDC_CHILD_CERTIFICATE_HEADER);
		qsc_memutils_copy(enck, MPDC_CHILD_CERTIFICATE_HEADER, slen);
		spos = slen;
		enck[spos] = '\n';
		++spos;

		slen = qsc_stringutils_string_size(MPDC_CHILD_CERTIFICATE_ISSUER_PREFIX);
		qsc_memutils_copy((enck + spos), MPDC_CHILD_CERTIFICATE_ISSUER_PREFIX, slen);
		spos += slen;
		slen = qsc_stringutils_string_size(child->issuer);
		qsc_memutils_copy((enck + spos), child->issuer, slen);
		spos += slen;
		enck[spos] = '\n';
		++spos;

		slen = qsc_stringutils_string_size(MPDC_CHILD_CERTIFICATE_SERIAL_PREFIX);
		qsc_memutils_copy((enck + spos), MPDC_CHILD_CERTIFICATE_SERIAL_PREFIX, slen);
		spos += slen;
		qsc_intutils_bin_to_hex(child->serial, hexid, MPDC_CERTIFICATE_SERIAL_SIZE);
		qsc_stringutils_to_uppercase(hexid);
		slen = sizeof(hexid);
		qsc_memutils_copy((enck + spos), hexid, slen);
		spos += slen;
		enck[spos] = '\n';
		++spos;

		slen = qsc_stringutils_string_size(MPDC_CHILD_CERTIFICATE_VALID_FROM_PREFIX);
		qsc_memutils_copy((enck + spos), MPDC_CHILD_CERTIFICATE_VALID_FROM_PREFIX, slen);
		spos += slen;
		qsc_timestamp_seconds_to_datetime(child->expiration.from, dtm);
		slen = sizeof(dtm) - 1;
		qsc_memutils_copy((enck + spos), dtm, slen);
		spos += slen;
		slen = qsc_stringutils_string_size(MPDC_CHILD_CERTIFICATE_EXPIRATION_TO_PREFIX);
		qsc_memutils_copy((enck + spos), MPDC_CHILD_CERTIFICATE_EXPIRATION_TO_PREFIX, slen);
		spos += slen;
		qsc_timestamp_seconds_to_datetime(child->expiration.to, dtm);
		slen = sizeof(dtm) - 1;
		qsc_memutils_copy((enck + spos), dtm, slen);
		spos += slen;
		enck[spos] = '\n';
		++spos;

		slen = qsc_stringutils_string_size(MPDC_CHILD_CERTIFICATE_ALGORITHM_PREFIX);
		qsc_memutils_copy((enck + spos), MPDC_CHILD_CERTIFICATE_ALGORITHM_PREFIX, slen);
		spos += slen;
		slen = qsc_stringutils_string_size(MPDC_CONFIG_STRING);
		qsc_memutils_copy((enck + spos), MPDC_CONFIG_STRING, slen);
		spos += slen;
		enck[spos] = '\n';
		++spos;

		slen = qsc_stringutils_string_size(MPDC_CHILD_CERTIFICATE_VERSION_PREFIX);
		qsc_memutils_copy((enck + spos), MPDC_CHILD_CERTIFICATE_VERSION_PREFIX, slen);
		spos += slen;

		if (child->version == mpdc_version_set_one_zero)
		{
			slen = qsc_stringutils_string_size(MPDC_ACTIVE_VERSION_STRING);
			qsc_memutils_copy((enck + spos), MPDC_ACTIVE_VERSION_STRING, slen);
		}
		else
		{
			const char defv[] = "0x00";
			slen = qsc_stringutils_string_size(defv);
			qsc_memutils_copy((enck + spos), defv, slen);
		}

		spos += slen;
		enck[spos] = '\n';
		++spos;

		slen = qsc_stringutils_string_size(MPDC_CHILD_CERTIFICATE_DESIGNATION_PREFIX);
		qsc_memutils_copy((enck + spos), MPDC_CHILD_CERTIFICATE_DESIGNATION_PREFIX, slen);
		spos += slen;
		spos += mpdc_certificate_designation_encode((enck + spos), child->designation);
		enck[spos] = '\n';
		++spos;

		slen = qsc_stringutils_string_size(MPDC_CHILD_CERTIFICATE_ROOT_SERIAL_PREFIX);
		qsc_memutils_copy((enck + spos), MPDC_CHILD_CERTIFICATE_ROOT_SERIAL_PREFIX, slen);
		spos += slen;
		qsc_intutils_bin_to_hex(child->rootser, hexid, MPDC_CERTIFICATE_SERIAL_SIZE);
		qsc_stringutils_to_uppercase(hexid);
		slen = sizeof(hexid);
		qsc_memutils_copy((enck + spos), hexid, slen);
		spos += slen;
		enck[spos] = '\n';
		++spos;

		slen = qsc_stringutils_string_size(MPDC_CHILD_CERTIFICATE_ROOT_HASH_PREFIX);
		qsc_memutils_copy((enck + spos), MPDC_CHILD_CERTIFICATE_ROOT_HASH_PREFIX, slen);
		spos += slen;
		enck[spos] = '\n';
		++spos;

		//size_t enclen = qsc_encoding_base64_encoded_size(sizeof(child->csig));
		slen = MPDC_CERTIFICATE_SIGNED_HASH_SIZE;
		qsc_encoding_base64_encode(tmpsg, MPDC_SIGNATURE_ENCODING_SIZE, child->csig, slen);
		spos += qsc_stringutils_add_line_breaks((enck + spos), MPDC_CHILD_CERTIFICATE_STRING_SIZE - spos, MPDC_CERTIFICATE_LINE_LENGTH, tmpsg, sizeof(tmpsg));
		enck[spos] = '\n';
		++spos;

		slen = qsc_stringutils_string_size(MPDC_CHILD_CERTIFICATE_SIGNATURE_KEY_PREFIX);
		qsc_memutils_copy((enck + spos), MPDC_CHILD_CERTIFICATE_SIGNATURE_KEY_PREFIX, slen);
		spos += slen;
		enck[spos] = '\n';
		++spos;

		slen = MPDC_ASYMMETRIC_VERIFICATION_KEY_SIZE;
		//size_t enclen = qsc_encoding_base64_encoded_size(slen);
		qsc_encoding_base64_encode(tmpvk, MPDC_VERIFICATION_KEY_ENCODING_SIZE, child->verkey, slen);
		spos += qsc_stringutils_add_line_breaks((enck + spos), MPDC_ROOT_CERTIFICATE_STRING_SIZE - spos, MPDC_CERTIFICATE_LINE_LENGTH, tmpvk, sizeof(tmpvk));

		slen = qsc_stringutils_string_size(MPDC_CHILD_CERTIFICATE_FOOTER);
		qsc_memutils_copy((enck + spos), MPDC_CHILD_CERTIFICATE_FOOTER, slen);
		spos += slen;
		enck[spos] = 0;
		++spos;
	}

	return spos;
}

void mpdc_certificate_child_erase(mpdc_child_certificate* child)
{
	assert(child != NULL);

	if (child != NULL)
	{
		qsc_memutils_clear(child->csig, MPDC_ASYMMETRIC_SIGNATURE_SIZE);
		qsc_memutils_clear(child->verkey, MPDC_ASYMMETRIC_VERIFICATION_KEY_SIZE);
		qsc_memutils_clear(child->issuer, MPDC_CERTIFICATE_ISSUER_SIZE);
		qsc_memutils_clear(child->serial, MPDC_CERTIFICATE_SERIAL_SIZE);
		qsc_memutils_clear(child->rootser, MPDC_CERTIFICATE_SERIAL_SIZE);
		qsc_memutils_clear(&child->expiration, MPDC_CERTIFICATE_EXPIRATION_SIZE);
		child->designation = (uint8_t)mpdc_network_designation_none;
		child->algorithm = (uint8_t)mpdc_configuration_set_none;
		child->version = (uint8_t)mpdc_version_set_one_zero;
	}
}

bool mpdc_certificate_child_file_to_struct(const char* fpath, mpdc_child_certificate* child)
{
	assert(fpath != NULL);
	assert(child != NULL);

	bool res;

	res = false;

	if (fpath != NULL && child != NULL)
	{
		if (qsc_fileutils_exists(fpath) == true)
		{
			uint8_t schild[MPDC_CERTIFICATE_CHILD_SIZE] = { 0 };

			if (qsc_fileutils_copy_file_to_stream(fpath, schild, MPDC_CERTIFICATE_CHILD_SIZE) == MPDC_CERTIFICATE_CHILD_SIZE)
			{
				mpdc_certificate_child_deserialize(child, schild);
				res = true;
			}
		}
	}

	return res;
}

void mpdc_certificate_child_hash(uint8_t* output, const mpdc_child_certificate* child)
{
	assert(output != NULL);
	assert(child != NULL);

	if (output != NULL && child != NULL)
	{
		qsc_keccak_state hstate = { 0 };
		uint8_t nbuf[sizeof(uint64_t)] = { 0 };

		qsc_sha3_initialize(&hstate);
		nbuf[0] = child->algorithm;
		qsc_sha3_update(&hstate, qsc_keccak_rate_256, nbuf, sizeof(uint8_t));
		nbuf[0] = child->designation;
		qsc_sha3_update(&hstate, qsc_keccak_rate_256, nbuf, sizeof(uint8_t));
		nbuf[0] = child->version;
		qsc_sha3_update(&hstate, qsc_keccak_rate_256, nbuf, sizeof(uint8_t));
		qsc_intutils_le64to8(nbuf, child->expiration.from);
		qsc_sha3_update(&hstate, qsc_keccak_rate_256, nbuf, sizeof(uint64_t));
		qsc_intutils_le64to8(nbuf, child->expiration.to);
		qsc_sha3_update(&hstate, qsc_keccak_rate_256, nbuf, sizeof(uint64_t));
		qsc_sha3_update(&hstate, qsc_keccak_rate_256, child->issuer, qsc_stringutils_string_size((const char*)child->issuer));
		qsc_sha3_update(&hstate, qsc_keccak_rate_256, child->serial, MPDC_CERTIFICATE_SERIAL_SIZE);
		qsc_sha3_update(&hstate, qsc_keccak_rate_256, child->verkey, MPDC_ASYMMETRIC_VERIFICATION_KEY_SIZE);
		qsc_sha3_finalize(&hstate, qsc_keccak_rate_256, output);
	}
}

bool mpdc_certificate_child_is_valid(const mpdc_child_certificate* child)
{
	assert(child != NULL);

	bool res;

	res = false;

	if (child != NULL)
	{
		if (child->algorithm == MPDC_CONFIGURATION_SET &&
			child->designation != mpdc_network_designation_none &&
			child->version == MPDC_ACTIVE_VERSION &&
			qsc_memutils_zeroed(child->csig, MPDC_CERTIFICATE_SIGNED_HASH_SIZE) == false &&
			qsc_memutils_zeroed(child->rootser, MPDC_CERTIFICATE_SERIAL_SIZE) == false &&
			qsc_memutils_zeroed(child->serial, MPDC_CERTIFICATE_SERIAL_SIZE) == false &&
			qsc_memutils_zeroed(child->verkey, MPDC_ASYMMETRIC_VERIFICATION_KEY_SIZE) == false)
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

bool mpdc_certificate_child_message_verify(uint8_t* message, size_t* msglen, const uint8_t* signature, size_t siglen, const mpdc_child_certificate* child)
{
	assert(message != NULL);
	assert(msglen != NULL);
	assert(signature != NULL);
	assert(siglen != 0);
	assert(child != NULL);

	bool res;

	res = false;
	*msglen = 0;

	if (message != NULL && msglen != NULL && signature != NULL && siglen != 0 && child != NULL)
	{
		res = mpdc_signature_verify(message, msglen, signature, siglen, child->verkey);
	}

	return res;
}

void mpdc_certificate_child_serialize(uint8_t* output, const mpdc_child_certificate* child)
{
	assert(output != NULL);
	assert(child != NULL);

	size_t pos;

	if (output != NULL && child != NULL)
	{
		qsc_memutils_copy(output, child->csig, MPDC_CERTIFICATE_SIGNED_HASH_SIZE);
		pos = MPDC_CERTIFICATE_SIGNED_HASH_SIZE;
		qsc_memutils_copy(output + pos, child->verkey, MPDC_ASYMMETRIC_VERIFICATION_KEY_SIZE);
		pos += MPDC_ASYMMETRIC_VERIFICATION_KEY_SIZE;
		qsc_memutils_copy(output + pos, child->issuer, MPDC_CERTIFICATE_ISSUER_SIZE);
		pos += MPDC_CERTIFICATE_ISSUER_SIZE;
		qsc_memutils_copy(output + pos, child->serial, MPDC_CERTIFICATE_SERIAL_SIZE);
		pos += MPDC_CERTIFICATE_SERIAL_SIZE;
		qsc_memutils_copy(output + pos, child->rootser, MPDC_CERTIFICATE_SERIAL_SIZE);
		pos += MPDC_CERTIFICATE_SERIAL_SIZE;
		qsc_memutils_copy(output + pos, &child->expiration, MPDC_CERTIFICATE_EXPIRATION_SIZE);
		pos += MPDC_CERTIFICATE_EXPIRATION_SIZE;
		qsc_memutils_copy(output + pos, &child->designation, MPDC_CERTIFICATE_DESIGNATION_SIZE);
		pos += MPDC_CERTIFICATE_DESIGNATION_SIZE;
		qsc_memutils_copy(output + pos, &child->algorithm, MPDC_CERTIFICATE_ALGORITHM_SIZE);
		pos += MPDC_CERTIFICATE_ALGORITHM_SIZE;
		qsc_memutils_copy(output + pos, &child->version, MPDC_CERTIFICATE_VERSION_SIZE);
	}
}

bool mpdc_certificate_signature_hash_verify(const uint8_t* signature, size_t siglen, const uint8_t* message, size_t msglen, const mpdc_child_certificate* lcert)
{
	assert(signature != NULL);
	assert(siglen != 0);
	assert(message != NULL);
	assert(msglen != 0);
	assert(lcert != NULL);

	size_t mlen;
	bool res;

	mlen = 0;
	res = false;

	if (signature != NULL && siglen != 0 && message != NULL && msglen != 0 && lcert != NULL)
	{
		uint8_t rhash[MPDC_CERTIFICATE_HASH_SIZE] = { 0 };

		res = mpdc_signature_verify(rhash, &mlen, signature, siglen, lcert->verkey);

		if (res == true && mlen == MPDC_CERTIFICATE_HASH_SIZE)
		{
			uint8_t lhash[MPDC_CERTIFICATE_HASH_SIZE] = { 0 };

			qsc_sha3_compute256(lhash, message, msglen);
			res = qsc_memutils_are_equal(rhash, lhash, MPDC_CERTIFICATE_HASH_SIZE);
		}
	}

	return res;
}

bool mpdc_certificate_child_struct_to_file(const char* fpath, const mpdc_child_certificate* child)
{
	assert(fpath != NULL);
	assert(child != NULL);

	bool res;

	res = false;

	if (fpath != NULL && child != NULL)
	{
		uint8_t schild[MPDC_CERTIFICATE_CHILD_SIZE] = { 0 };

		if (qsc_fileutils_exists(fpath) == true)
		{
			qsc_fileutils_delete(fpath);
		}

		mpdc_certificate_child_serialize(schild, child);
		res = qsc_fileutils_copy_stream_to_file(fpath, schild, sizeof(schild));
	}

	return res;
}

mpdc_network_designations mpdc_certificate_designation_decode(const char* sdsg)
{
	assert(sdsg != NULL);

	mpdc_network_designations dsg;

	dsg = mpdc_network_designation_none;

	if (sdsg != NULL)
	{
		if (qsc_stringutils_find_string(sdsg, MPDC_NETWORK_DESIGNATION_AGENT) != QSC_STRINGUTILS_TOKEN_NOT_FOUND)
		{
			dsg = mpdc_network_designation_agent;
		}
		else if (qsc_stringutils_find_string(sdsg, MPDC_NETWORK_DESIGNATION_CLIENT) != QSC_STRINGUTILS_TOKEN_NOT_FOUND)
		{
			dsg = mpdc_network_designation_client;
		}
		else if (qsc_stringutils_find_string(sdsg, MPDC_NETWORK_DESIGNATION_IDG) != QSC_STRINGUTILS_TOKEN_NOT_FOUND)
		{
			dsg = mpdc_network_designation_idg;
		}
		else if (qsc_stringutils_find_string(sdsg, MPDC_NETWORK_DESIGNATION_REMOTE) != QSC_STRINGUTILS_TOKEN_NOT_FOUND)
		{
			dsg = mpdc_network_designation_remote;
		}
		else if (qsc_stringutils_find_string(sdsg, MPDC_NETWORK_DESIGNATION_ROOT) != QSC_STRINGUTILS_TOKEN_NOT_FOUND)
		{
			dsg = mpdc_network_designation_rds;
		}
		else if (qsc_stringutils_find_string(sdsg, MPDC_NETWORK_DESIGNATION_SERVER) != QSC_STRINGUTILS_TOKEN_NOT_FOUND)
		{
			dsg = mpdc_network_designation_mas;
		}
		else if (qsc_stringutils_find_string(sdsg, MPDC_NETWORK_DESIGNATION_ALL) != QSC_STRINGUTILS_TOKEN_NOT_FOUND)
		{
			dsg = mpdc_network_designation_all;
		}
		else
		{
			dsg = mpdc_network_designation_none;
		}
	}

	return dsg;
}

size_t mpdc_certificate_designation_encode(char* sdsg, mpdc_network_designations designation)
{
	assert(sdsg != NULL);

	if (sdsg != NULL)
	{
		if (designation == mpdc_network_designation_agent)
		{
			qsc_stringutils_copy_string(sdsg, MPDC_NETWORK_DESIGNATION_SIZE, MPDC_NETWORK_DESIGNATION_AGENT);
		}
		else if (designation == mpdc_network_designation_client)
		{
			qsc_stringutils_copy_string(sdsg, MPDC_NETWORK_DESIGNATION_SIZE, MPDC_NETWORK_DESIGNATION_CLIENT);
		}
		else if (designation == mpdc_network_designation_dla)
		{
			qsc_stringutils_copy_string(sdsg, MPDC_NETWORK_DESIGNATION_SIZE, MPDC_NETWORK_DESIGNATION_DLA);
		}
		else if (designation == mpdc_network_designation_idg)
		{
			qsc_stringutils_copy_string(sdsg, MPDC_NETWORK_DESIGNATION_SIZE, MPDC_NETWORK_DESIGNATION_IDG);
		}
		else if (designation == mpdc_network_designation_remote)
		{
			qsc_stringutils_copy_string(sdsg, MPDC_NETWORK_DESIGNATION_SIZE, MPDC_NETWORK_DESIGNATION_REMOTE);
		}
		else if (designation == mpdc_network_designation_rds)
		{
			qsc_stringutils_copy_string(sdsg, MPDC_NETWORK_DESIGNATION_SIZE, MPDC_NETWORK_DESIGNATION_ROOT);
		}
		else if (designation == mpdc_network_designation_mas)
		{
			qsc_stringutils_copy_string(sdsg, MPDC_NETWORK_DESIGNATION_SIZE, MPDC_NETWORK_DESIGNATION_SERVER);
		}
		else if (designation == mpdc_network_designation_all)
		{
			qsc_stringutils_copy_string(sdsg, MPDC_NETWORK_DESIGNATION_SIZE, MPDC_NETWORK_DESIGNATION_ALL);
		}
	}

	return qsc_stringutils_string_size(sdsg);
}

void mpdc_certificate_expiration_set_days(mpdc_certificate_expiration* expiration, uint16_t start, uint16_t duration)
{
	assert(expiration != NULL);

	if (expiration != NULL)
	{
		expiration->from = qsc_timestamp_datetime_utc() + (start * 24 * 60 * 60);
		expiration->to = expiration->from + (duration * 24 * 60 * 60);
	}
}

void mpdc_certificate_expiration_set_seconds(mpdc_certificate_expiration* expiration, uint64_t start, uint64_t period)
{
	assert(expiration != NULL);

	if (expiration != NULL)
	{
		expiration->from = qsc_timestamp_datetime_utc() + start;
		expiration->to = expiration->from + period;
	}
}

bool mpdc_certificate_expiration_time_verify(const mpdc_certificate_expiration* expiration)
{
	assert(expiration != NULL);

	uint64_t nsec;
	bool res;

	nsec = qsc_timestamp_datetime_utc();

	if (nsec >= expiration->from && nsec <= expiration->to)
	{
		res = true;
	}
	else
	{
		res = false;
	}

	return res;
}

size_t mpdc_certificate_message_hash_sign(uint8_t* signature, const uint8_t* sigkey, const uint8_t* message, size_t msglen)
{
	assert(signature != NULL);
	assert(sigkey != NULL);
	assert(message != NULL);
	assert(msglen != 0);

	size_t slen;

	slen = 0;

	if (signature != NULL)
	{
		uint8_t hash[MPDC_CERTIFICATE_HASH_SIZE] = { 0 };

		qsc_sha3_compute256(hash, message, msglen);
		mpdc_signature_sign(signature, &slen, hash, sizeof(hash), sigkey, qsc_acp_generate);
	}

	return slen;
}

bool mpdc_certificate_root_compare(const mpdc_root_certificate* a, const mpdc_root_certificate* b)
{
	assert(a != NULL);
	assert(b != NULL);

	bool res;

	res = false;

	if (a != NULL && b != NULL)
	{
		if (a->algorithm == b->algorithm && a->version == b->version &&
			a->expiration.from == b->expiration.from && a->expiration.to == b->expiration.to)
		{
			if (qsc_memutils_are_equal(a->issuer, b->issuer, MPDC_CERTIFICATE_ISSUER_SIZE) == true)
			{
				if (qsc_memutils_are_equal(a->serial, b->serial, MPDC_CERTIFICATE_SERIAL_SIZE) == true)
				{
					res = qsc_memutils_are_equal(a->verkey, b->verkey, MPDC_ASYMMETRIC_VERIFICATION_KEY_SIZE);
				}
			}
		}
	}

	return res;
}

void mpdc_certificate_root_create(mpdc_root_certificate* root, const uint8_t* pubkey, const mpdc_certificate_expiration* expiration, const char* issuer)
{
	assert(root != NULL);
	assert(pubkey != NULL);
	assert(expiration != NULL);
	assert(issuer != NULL);

	if (root != NULL && pubkey != NULL && expiration != NULL && issuer != NULL)
	{
		root->algorithm = (uint8_t)MPDC_CONFIGURATION_SET;
		root->version = MPDC_ACTIVE_VERSION;
		qsc_stringutils_copy_string(root->issuer, MPDC_CERTIFICATE_ISSUER_SIZE, issuer);
		qsc_memutils_copy(&root->expiration, expiration, MPDC_CERTIFICATE_EXPIRATION_SIZE);
		qsc_memutils_copy(root->verkey, pubkey, MPDC_ASYMMETRIC_VERIFICATION_KEY_SIZE);
		qsc_acp_generate(root->serial, MPDC_CERTIFICATE_SERIAL_SIZE);
	}
}

bool mpdc_certificate_root_decode(mpdc_root_certificate* root, const char* enck)
{
	assert(root != NULL);
	assert(enck != NULL);

	const char* penc;
	size_t slen;
	bool res;

	res = false;

	if (root != NULL && enck != NULL)
	{
		char tmpvk[MPDC_VERIFICATION_KEY_ENCODING_SIZE] = { 0 };
		char dtm[QSC_TIMESTAMP_STRING_SIZE] = { 0 };

		penc = enck;
		penc += qsc_stringutils_string_size(MPDC_ROOT_CERTIFICATE_HEADER) + qsc_stringutils_string_size(MPDC_ROOT_CERTIFICATE_SERIAL_PREFIX) + 1;
		slen = MPDC_CERTIFICATE_SERIAL_SIZE;

		qsc_intutils_hex_to_bin(penc, root->serial, MPDC_CERTIFICATE_SERIAL_SIZE * 2);
		penc += (MPDC_CERTIFICATE_SERIAL_SIZE * 2);

		penc += qsc_stringutils_string_size(MPDC_ROOT_CERTIFICATE_ISSUER_PREFIX) + 1;
		slen = qsc_stringutils_find_string(penc, "\n");
		qsc_memutils_copy(root->issuer, penc, slen);
		penc += slen;

		penc += qsc_stringutils_string_size(MPDC_ROOT_CERTIFICATE_VALID_FROM_PREFIX) + 1;
		slen = QSC_TIMESTAMP_STRING_SIZE;
		qsc_memutils_copy(dtm, penc, slen);
		root->expiration.from = qsc_timestamp_datetime_to_seconds(dtm);
		penc += slen;

		penc += qsc_stringutils_string_size(MPDC_CHILD_CERTIFICATE_EXPIRATION_TO_PREFIX) - 1;
		slen = QSC_TIMESTAMP_STRING_SIZE;
		qsc_memutils_copy(dtm, penc, slen);
		root->expiration.to = qsc_timestamp_datetime_to_seconds(dtm);
		penc += slen;

		penc += qsc_stringutils_string_size(MPDC_ROOT_CERTIFICATE_ALGORITHM_PREFIX) + 1;
		slen = qsc_stringutils_find_string(penc, "\n");
		root->algorithm = mpdc_certificate_algorithm_decode(penc);
		penc += slen;

		penc += qsc_stringutils_string_size(MPDC_ROOT_CERTIFICATE_VERSION_PREFIX) + 1;
		slen = qsc_stringutils_find_string(penc, "\n");

		if (qsc_stringutils_compare_strings(penc, MPDC_ACTIVE_VERSION_STRING, slen) == true)
		{
			root->version = mpdc_version_set_one_zero;
		}
		else
		{
			root->version = mpdc_version_set_none;
		}
		penc += slen;

		penc += qsc_stringutils_string_size(MPDC_ROOT_CERTIFICATE_PUBLICKEY_PREFIX) + 1;
		qsc_stringutils_remove_line_breaks(tmpvk, sizeof(tmpvk), penc, MPDC_ROOT_CERTIFICATE_STRING_SIZE);
		res = qsc_encoding_base64_decode(root->verkey, MPDC_ASYMMETRIC_VERIFICATION_KEY_SIZE, tmpvk, MPDC_VERIFICATION_KEY_ENCODING_SIZE);
	}

	return res;
}

void mpdc_certificate_root_deserialize(mpdc_root_certificate* root, const uint8_t* input)
{
	assert(root != NULL);
	assert(input != NULL);

	size_t pos;

	if (root != NULL && input != NULL)
	{
		qsc_memutils_copy(root->verkey, input, MPDC_ASYMMETRIC_VERIFICATION_KEY_SIZE);
		pos = MPDC_ASYMMETRIC_VERIFICATION_KEY_SIZE;
		qsc_memutils_copy(root->issuer, input + pos, MPDC_CERTIFICATE_ISSUER_SIZE);
		pos += MPDC_CERTIFICATE_ISSUER_SIZE;
		qsc_memutils_copy(root->serial, input + pos, MPDC_CERTIFICATE_SERIAL_SIZE);
		pos += MPDC_CERTIFICATE_SERIAL_SIZE;
		qsc_memutils_copy(&root->expiration, input + pos, MPDC_CERTIFICATE_EXPIRATION_SIZE);
		pos += MPDC_CERTIFICATE_EXPIRATION_SIZE;
		qsc_memutils_copy(&root->algorithm, input + pos, sizeof(uint8_t));
		pos += sizeof(uint8_t);
		qsc_memutils_copy(&root->version, input + pos, sizeof(uint8_t));
	}
}

size_t mpdc_certificate_root_encode(char* enck, const mpdc_root_certificate* root)
{
	assert(enck != NULL);
	assert(root != NULL);

	size_t slen;
	size_t spos;

	spos = 0;

	if (enck != NULL && root != NULL)
	{
		char dtm[QSC_TIMESTAMP_STRING_SIZE] = { 0 };
		char hexid[MPDC_CERTIFICATE_SERIAL_SIZE * 2] = { 0 };
		char tmpvk[MPDC_VERIFICATION_KEY_ENCODING_SIZE] = { 0 };

		slen = qsc_stringutils_string_size(MPDC_ROOT_CERTIFICATE_HEADER);
		qsc_memutils_copy(enck, MPDC_ROOT_CERTIFICATE_HEADER, slen);
		spos = slen;
		enck[spos] = '\n';
		++spos;

		slen = qsc_stringutils_string_size(MPDC_ROOT_CERTIFICATE_ISSUER_PREFIX);
		qsc_memutils_copy((enck + spos), MPDC_ROOT_CERTIFICATE_ISSUER_PREFIX, slen);
		spos += slen;
		slen = qsc_stringutils_string_size(root->issuer);
		qsc_memutils_copy((enck + spos), root->issuer, slen);
		spos += slen;
		enck[spos] = '\n';
		++spos;

		slen = qsc_stringutils_string_size(MPDC_ROOT_CERTIFICATE_SERIAL_PREFIX);
		qsc_memutils_copy((enck + spos), MPDC_ROOT_CERTIFICATE_SERIAL_PREFIX, slen);
		spos += slen;
		qsc_intutils_bin_to_hex(root->serial, hexid, MPDC_CERTIFICATE_SERIAL_SIZE);
		qsc_stringutils_to_uppercase(hexid);
		slen = sizeof(hexid);
		qsc_memutils_copy((enck + spos), hexid, slen);
		spos += slen;
		enck[spos] = '\n';
		++spos;

		slen = qsc_stringutils_string_size(MPDC_ROOT_CERTIFICATE_VALID_FROM_PREFIX);
		qsc_memutils_copy((enck + spos), MPDC_ROOT_CERTIFICATE_VALID_FROM_PREFIX, slen);
		spos += slen;
		qsc_timestamp_seconds_to_datetime(root->expiration.from, dtm);
		slen = sizeof(dtm) - 1;
		qsc_memutils_copy((enck + spos), dtm, slen);
		spos += slen;
		slen = qsc_stringutils_string_size(MPDC_ROOT_CERTIFICATE_EXPIRATION_TO_PREFIX);
		qsc_memutils_copy((enck + spos), MPDC_ROOT_CERTIFICATE_EXPIRATION_TO_PREFIX, slen);
		spos += slen;
		qsc_timestamp_seconds_to_datetime(root->expiration.to, dtm);
		slen = sizeof(dtm) - 1;
		qsc_memutils_copy((enck + spos), dtm, slen);
		spos += slen;
		enck[spos] = '\n';
		++spos;

		slen = qsc_stringutils_string_size(MPDC_ROOT_CERTIFICATE_ALGORITHM_PREFIX);
		qsc_memutils_copy((enck + spos), MPDC_ROOT_CERTIFICATE_ALGORITHM_PREFIX, slen);
		spos += slen;
		slen = qsc_stringutils_string_size(MPDC_CONFIG_STRING);
		qsc_memutils_copy((enck + spos), MPDC_CONFIG_STRING, slen);
		spos += slen;
		enck[spos] = '\n';
		++spos;

		slen = qsc_stringutils_string_size(MPDC_ROOT_CERTIFICATE_VERSION_PREFIX);
		qsc_memutils_copy((enck + spos), MPDC_ROOT_CERTIFICATE_VERSION_PREFIX, slen);
		spos += slen;
		slen = qsc_stringutils_string_size(MPDC_ACTIVE_VERSION_STRING);
		qsc_memutils_copy((enck + spos), MPDC_ACTIVE_VERSION_STRING, slen);
		spos += slen;
		enck[spos] = '\n';
		++spos;

		slen = qsc_stringutils_string_size(MPDC_ROOT_CERTIFICATE_PUBLICKEY_PREFIX);
		qsc_memutils_copy((enck + spos), MPDC_ROOT_CERTIFICATE_PUBLICKEY_PREFIX, slen);
		spos += slen;
		enck[spos] = '\n';
		++spos;
		slen = MPDC_ASYMMETRIC_VERIFICATION_KEY_SIZE;
		qsc_encoding_base64_encode(tmpvk, MPDC_VERIFICATION_KEY_ENCODING_SIZE, root->verkey, slen);
		spos += qsc_stringutils_add_line_breaks((enck + spos), MPDC_ROOT_CERTIFICATE_STRING_SIZE - spos, MPDC_CERTIFICATE_LINE_LENGTH, tmpvk, sizeof(tmpvk));

		slen = qsc_stringutils_string_size(MPDC_ROOT_CERTIFICATE_FOOTER);
		qsc_memutils_copy((enck + spos), MPDC_ROOT_CERTIFICATE_FOOTER, slen);
		spos += slen;
		enck[spos] = 0;
		++spos;
	}

	return spos;
}

void mpdc_certificate_root_erase(mpdc_root_certificate* root)
{
	assert(root != NULL);

	if (root != NULL)
	{
		root->algorithm = mpdc_configuration_set_none;
		root->version = mpdc_version_set_none;
		qsc_memutils_clear(&root->expiration, MPDC_CERTIFICATE_EXPIRATION_SIZE);
		qsc_memutils_clear(root->issuer, MPDC_CERTIFICATE_ISSUER_SIZE);
		qsc_memutils_clear(root->serial, MPDC_CERTIFICATE_SERIAL_SIZE);
		qsc_memutils_clear(root->verkey, MPDC_ASYMMETRIC_VERIFICATION_KEY_SIZE);
	}
}

bool mpdc_certificate_root_file_to_struct(const char* fpath, mpdc_root_certificate* root)
{
	assert(fpath != NULL);
	assert(root != NULL);

	bool res;

	res = false;

	if (fpath != NULL && root != NULL)
	{
		if (qsc_fileutils_exists(fpath) == true)
		{
			uint8_t sroot[MPDC_CERTIFICATE_ROOT_SIZE] = { 0 };

			if (qsc_fileutils_copy_file_to_stream(fpath, sroot, MPDC_CERTIFICATE_ROOT_SIZE) == MPDC_CERTIFICATE_ROOT_SIZE)
			{
				mpdc_certificate_root_deserialize(root, sroot);
				res = mpdc_certificate_root_is_valid(root);
			}
		}
	}

	return res;
}

void mpdc_certificate_root_hash(uint8_t* output, const mpdc_root_certificate* root)
{
	assert(output != NULL);
	assert(root != NULL);

	if (output != NULL && root != NULL)
	{
		qsc_keccak_state hstate = { 0 };
		uint8_t nbuf[sizeof(uint64_t)] = { 0 };

		qsc_sha3_initialize(&hstate);
		nbuf[0] = root->algorithm;
		qsc_sha3_update(&hstate, qsc_keccak_rate_256, nbuf, sizeof(uint8_t));
		nbuf[0] = root->version;
		qsc_sha3_update(&hstate, qsc_keccak_rate_256, nbuf, sizeof(uint8_t));
		qsc_intutils_le64to8(nbuf, root->expiration.from);
		qsc_sha3_update(&hstate, qsc_keccak_rate_256, nbuf, sizeof(uint64_t));
		qsc_intutils_le64to8(nbuf, root->expiration.to);
		qsc_sha3_update(&hstate, qsc_keccak_rate_256, nbuf, sizeof(uint64_t));
		qsc_sha3_update(&hstate, qsc_keccak_rate_256, root->issuer, qsc_stringutils_string_size((const char*)root->issuer));
		qsc_sha3_update(&hstate, qsc_keccak_rate_256, root->serial, MPDC_CERTIFICATE_SERIAL_SIZE);
		qsc_sha3_update(&hstate, qsc_keccak_rate_256, root->verkey, MPDC_ASYMMETRIC_VERIFICATION_KEY_SIZE);
		qsc_sha3_finalize(&hstate, qsc_keccak_rate_256, output);
		qsc_keccak_dispose(&hstate);
	}
}

bool mpdc_certificate_root_is_valid(const mpdc_root_certificate* root)
{
	assert(root != NULL);

	bool res;

	res = false;

	if (root != NULL)
	{
		if (root->algorithm == MPDC_CONFIGURATION_SET &&
			root->version == MPDC_ACTIVE_VERSION &&
			qsc_memutils_zeroed(root->issuer, MPDC_CERTIFICATE_ISSUER_SIZE) == false &&
			qsc_memutils_zeroed(root->serial, MPDC_CERTIFICATE_SERIAL_SIZE) == false &&
			qsc_memutils_zeroed(root->verkey, MPDC_ASYMMETRIC_VERIFICATION_KEY_SIZE) == false)
		{
			uint64_t nsec;

			nsec = qsc_timestamp_datetime_utc();

			if (nsec >= root->expiration.from && nsec <= root->expiration.to)
			{
				res = true;
			}
		}
	}

	return res;
}

void mpdc_certificate_root_serialize(uint8_t* output, const mpdc_root_certificate* root)
{
	assert(output != NULL);
	assert(root != NULL);

	size_t pos;

	if (output != NULL && root != NULL)
	{
		qsc_memutils_copy(output, root->verkey, MPDC_ASYMMETRIC_VERIFICATION_KEY_SIZE);
		pos = MPDC_ASYMMETRIC_VERIFICATION_KEY_SIZE;
		qsc_memutils_copy(output + pos, root->issuer, MPDC_CERTIFICATE_ISSUER_SIZE);
		pos += MPDC_CERTIFICATE_ISSUER_SIZE;
		qsc_memutils_copy(output + pos, root->serial, MPDC_CERTIFICATE_SERIAL_SIZE);
		pos += MPDC_CERTIFICATE_SERIAL_SIZE;
		qsc_memutils_copy(output + pos, &root->expiration, MPDC_CERTIFICATE_EXPIRATION_SIZE);
		pos += MPDC_CERTIFICATE_EXPIRATION_SIZE;
		qsc_memutils_copy(output + pos, &root->algorithm, sizeof(uint8_t));
		pos += sizeof(uint8_t);
		qsc_memutils_copy(output + pos, &root->version, sizeof(uint8_t));
	}
}

size_t mpdc_certificate_root_sign(mpdc_child_certificate* child, const mpdc_root_certificate* root, const uint8_t* rsigkey)
{
	assert(child != NULL);
	assert(root != NULL);
	assert(rsigkey != NULL);

	size_t slen;

	slen = 0;

	if (child != NULL && root != NULL && rsigkey != NULL)
	{
		uint8_t hash[MPDC_CERTIFICATE_HASH_SIZE] = { 0 };

		qsc_memutils_copy(child->rootser, root->serial, MPDC_CERTIFICATE_SERIAL_SIZE);
		mpdc_certificate_child_hash(hash, child);
		mpdc_signature_sign(child->csig, &slen, hash, sizeof(hash), rsigkey, qsc_acp_generate);
	}

	return slen;
}

bool mpdc_certificate_root_signature_verify(const mpdc_child_certificate* child, const mpdc_root_certificate* root)
{
	assert(child != NULL);
	assert(root != NULL);

	size_t mlen;
	bool res;

	res = false;
	mlen = 0;

	if (child != NULL && root != NULL)
	{
		uint8_t msg[MPDC_CERTIFICATE_HASH_SIZE] = { 0 };

		res = mpdc_signature_verify(msg, &mlen, child->csig, MPDC_CERTIFICATE_SIGNED_HASH_SIZE, root->verkey);

		if (res == true)
		{
			uint8_t hash[MPDC_CERTIFICATE_HASH_SIZE] = { 0 };

			mpdc_certificate_child_hash(hash, child);

			res = qsc_memutils_are_equal(msg, hash, MPDC_CERTIFICATE_HASH_SIZE);
		}
	}

	return res;
}

bool mpdc_certificate_root_struct_to_file(const char* fpath, const mpdc_root_certificate* root)
{
	assert(fpath != NULL);
	assert(root != NULL);

	bool res;

	res = false;

	if (fpath != NULL)
	{
		uint8_t sroot[MPDC_CERTIFICATE_ROOT_SIZE] = { 0 };

		mpdc_certificate_root_serialize(sroot, root);
		res = qsc_fileutils_copy_stream_to_file(fpath, sroot, sizeof(sroot));
	}

	return res;
}

void mpdc_certificate_signature_generate_keypair(mpdc_signature_keypair* keypair)
{
	assert(keypair != NULL);

	if (keypair != NULL)
	{
		mpdc_signature_generate_keypair(keypair->pubkey, keypair->prikey, qsc_acp_generate);
	}
}

size_t mpdc_certificate_signature_sign_message(uint8_t* signature, const uint8_t* message, size_t msglen, const uint8_t* prikey)
{
	assert(signature != NULL);
	assert(message != NULL);
	assert(msglen != 0);
	assert(prikey != NULL);

	size_t slen;

	slen = 0;

	if (signature != NULL && message != NULL && msglen != 0 && prikey != NULL)
	{
		slen = msglen + MPDC_ASYMMETRIC_SIGNATURE_SIZE;
		mpdc_signature_sign(signature, &slen, message, msglen, prikey, qsc_acp_generate);
	}

	return slen;
}

bool mpdc_certificate_signature_verify_message(const uint8_t* message, size_t msglen, const uint8_t* signature, size_t siglen, const uint8_t* pubkey)
{
	assert(message != NULL);
	assert(msglen != 0);
	assert(signature != NULL);
	assert(pubkey != NULL);

	size_t mlen;
	bool res;

	res = false;

	if (message != NULL && msglen != 0 && signature != NULL && pubkey != NULL)
	{
		uint8_t tmsg[MPDC_CRYPTO_SYMMETRIC_HASH_SIZE] = { 0 };

		mlen = MPDC_CRYPTO_SYMMETRIC_HASH_SIZE;

		res = mpdc_signature_verify(tmsg, &mlen, signature, siglen, pubkey);

		if (res == true)
		{
			res = qsc_memutils_are_equal(message, tmsg, mlen);
		}
	}

	return res;
}

/** \cond */

#if defined(MPDC_DEBUG_TESTS_RUN)
static void get_encoded_sizes()
{
	mpdc_signature_keypair ckp = { 0 };
	mpdc_child_certificate child = { 0 };
	mpdc_signature_keypair skp = { 0 };
	mpdc_root_certificate root = { 0 };
	mpdc_certificate_expiration exp = { 0 };
	char cenc[MPDC_CHILD_CERTIFICATE_STRING_SIZE] = { 0 };
	char renc[MPDC_ROOT_CERTIFICATE_STRING_SIZE] = { 0 };
	char rname[MPDC_CERTIFICATE_ISSUER_SIZE] = "RDS-1";
	char name[MPDC_PROTOCOL_SET_SIZE] = { 0 };
	size_t len;

	mpdc_certificate_signature_generate_keypair(&skp);
	mpdc_certificate_expiration_set_days(&exp, 0, 30);
	mpdc_certificate_root_create(&root, (const uint8_t*)skp.pubkey, &exp, rname);

	mpdc_certificate_signature_generate_keypair(&ckp);
	mpdc_certificate_expiration_set_days(&exp, 0, 100);
	mpdc_certificate_child_create(&child, (const uint8_t*)ckp.pubkey, &exp, "Agent 1", mpdc_network_designation_agent);
	mpdc_certificate_root_sign(&child, &root, skp.prikey);

	qsc_consoleutils_print_safe("parameters: ");
	qsc_consoleutils_print_line(MPDC_CONFIG_STRING);

	len = qsc_encoding_base64_encoded_size(sizeof(skp.pubkey));
	qsc_consoleutils_print_safe("pk: ");
	qsc_consoleutils_print_uint((uint32_t)len);
	qsc_consoleutils_print_line("");

	len = qsc_encoding_base64_encoded_size(sizeof(child.csig));
	qsc_consoleutils_print_safe("sig: ");
	qsc_consoleutils_print_uint((uint32_t)len);
	qsc_consoleutils_print_line("");

	len = mpdc_certificate_child_encode(cenc, &child);
	qsc_consoleutils_print_safe("child: ");
	qsc_consoleutils_print_uint((uint32_t)len);
	qsc_consoleutils_print_line("");

	len = mpdc_certificate_root_encode(renc, &root);
	qsc_consoleutils_print_safe("root: ");
	qsc_consoleutils_print_uint((uint32_t)len);
	qsc_consoleutils_print_line("");
}

static void certificate_child_print(const mpdc_child_certificate* child)
{
	assert(child != NULL);

	char cenc[MPDC_CHILD_CERTIFICATE_STRING_SIZE] = { 0 };

	mpdc_certificate_child_encode(cenc, child);
	qsc_consoleutils_print_line(cenc);
	qsc_consoleutils_print_line("");
}

static void certificate_root_print(const mpdc_root_certificate* root)
{
	assert(root != NULL);

	char cenc[MPDC_ROOT_CERTIFICATE_STRING_SIZE] = { 0 };

	mpdc_certificate_root_encode(cenc, root);
	qsc_consoleutils_print_line(cenc);
	qsc_consoleutils_print_line("");
}

bool mpdc_certificate_functions_test()
{
	mpdc_signature_keypair skp = { 0 };
	mpdc_root_certificate root = { 0 };
	mpdc_certificate_expiration exp = { 0 };
	bool res;

	qsc_consoleutils_print_line("Printing encoded sizes of certificate fields");
	get_encoded_sizes();

	mpdc_certificate_signature_generate_keypair(&skp);
	mpdc_certificate_expiration_set_days(&exp, 0, 30);
	mpdc_certificate_root_create(&root, skp.pubkey, &exp, "RDS-1");
	res = mpdc_certificate_root_is_valid(&root);

	certificate_root_print(&root);

	if (res == true)
	{
		mpdc_root_certificate rcpy = { 0 };
		uint8_t srt[MPDC_CERTIFICATE_ROOT_SIZE] = { 0 };
		
		mpdc_certificate_root_serialize(srt, &root);
		mpdc_certificate_root_deserialize(&rcpy, srt);
		res = mpdc_certificate_root_compare(&root, &rcpy);

		if (res == true)
		{
			mpdc_signature_keypair ckp = { 0 };
			mpdc_child_certificate child = { 0 };
			mpdc_child_certificate ccpy = { 0 };

			mpdc_certificate_signature_generate_keypair(&ckp);
			mpdc_certificate_expiration_set_days(&exp, 0, 100);
			mpdc_certificate_child_create(&child, ckp.pubkey, &exp, "Agent 1", mpdc_network_designation_agent);
			mpdc_certificate_root_sign(&child, &root, skp.prikey);
			certificate_child_print(&child);
			res = mpdc_certificate_child_is_valid(&child);

			if (res == true)
			{
				res = mpdc_certificate_root_signature_verify(&child, &root);

				if (res == true)
				{
					uint8_t sct[MPDC_CERTIFICATE_CHILD_SIZE] = { 0 };

					mpdc_certificate_child_serialize(sct, &child);
					mpdc_certificate_child_deserialize(&ccpy, sct);
					res = mpdc_certificate_child_are_equal(&child, &ccpy);
				}
			}
		}
	}

	return res;
}

#endif

/** \endcond */
