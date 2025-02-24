#include "crypto.h"
#include "../../QSC/QSC/acp.h"
#include "../../QSC/QSC/cpuidex.h"
#include "../../QSC/QSC/intutils.h"
#include "../../QSC/QSC/memutils.h"
#include "../../QSC/QSC/netutils.h"
#include "../../QSC/QSC/rcs.h"
#include "../../QSC/QSC/scb.h"
#include "../../QSC/QSC/sha3.h"
#include "../../QSC/QSC/sysutils.h"

uint8_t* mpdc_crypto_secure_memory_allocate(size_t length)
{
	assert(length != 0);

	uint8_t* pblk;

	pblk = NULL;

	if (length != 0)
	{
		pblk = qsc_memutils_secure_malloc(length);

		if (pblk != NULL)
		{
			qsc_memutils_secure_erase(pblk, length);
		}
	}

	return pblk;
}

void mpdc_crypto_secure_memory_deallocate(uint8_t* block, size_t length)
{
	assert(block != NULL);
	assert(length != 0);

	if (block != NULL)
	{
		qsc_memutils_secure_erase(block, length);
		qsc_memutils_secure_free(block, length);
		block = NULL;
	}
}

void mpdc_crypto_generate_application_keychain(uint8_t* seed, size_t seedlen, const char* password, size_t passlen, const char* username, size_t userlen)
{
	assert(seed != NULL);
	assert(seedlen != 0);
	assert(password != NULL);
	assert(passlen != 0);
	assert(username != NULL);
	assert(userlen != 0);

	if (seed != NULL && seedlen != 0 && password != NULL && passlen != 0 && username != NULL && userlen != 0)
	{
		uint8_t salt[QSC_SHA3_256_HASH_SIZE] = { 0 };
		uint8_t phash[QSC_SHA3_256_HASH_SIZE] = { 0 };
		qsc_scb_state scbx = { 0 };

		mpdc_crypto_generate_application_salt(salt, sizeof(salt));
		qsc_cshake256_compute(phash, sizeof(phash), password, passlen, NULL, 0, username, userlen);

		/* use cost based kdf to generate the stored comparison value */
		qsc_scb_initialize(&scbx, phash, sizeof(phash), salt, sizeof(salt), MPDC_CRYPTO_PHASH_CPU_COST, MPDC_CRYPTO_PHASH_MEMORY_COST);
		qsc_scb_generate(&scbx, seed, seedlen);
		qsc_scb_dispose(&scbx);
	}
}

bool mpdc_crypto_decrypt_stream(uint8_t* output, const uint8_t* seed, const uint8_t* input, size_t length)
{
	assert(output != NULL);
	assert(seed != NULL);
	assert(input != NULL);
	assert(length != 0);

	bool res;

	res = false;

	if (output != NULL && seed != NULL && input != NULL && length != 0)
	{
		qsc_rcs_state ctx = { 0 };

		const qsc_rcs_keyparams kp = {
			.key = seed,
			.keylen = QSC_RCS256_KEY_SIZE,
			.nonce = (uint8_t*)seed + QSC_RCS256_KEY_SIZE,
			.info = NULL,
			.infolen = 0 };

		qsc_rcs_initialize(&ctx, &kp, false);
		res = qsc_rcs_transform(&ctx, output, input, length);
		qsc_rcs_dispose(&ctx);
	}

	return res;
}

void mpdc_crypto_encrypt_stream(uint8_t* output, const uint8_t* seed, const uint8_t* input, size_t length)
{
	assert(output != NULL);
	assert(seed != NULL);
	assert(input != NULL);
	assert(length != 0);

	qsc_rcs_state ctx = { 0 };

	if (output != NULL && seed != NULL && input != NULL && length != 0)
	{
		const qsc_rcs_keyparams kp = {
		.key = seed,
		.keylen = QSC_RCS256_KEY_SIZE,
		.nonce = (uint8_t*)seed + QSC_RCS256_KEY_SIZE,
		.info = NULL,
		.infolen = 0 };

		qsc_rcs_initialize(&ctx, &kp, true);
		qsc_rcs_transform(&ctx, output, input, length);
		qsc_rcs_dispose(&ctx);
	}
}

void mpdc_crypto_generate_application_salt(uint8_t* output, size_t outlen)
{
	assert(output != NULL);
	assert(outlen != 0);

	if (output != NULL && outlen != 0)
	{
		uint8_t buff[QSC_SYSUTILS_SYSTEM_NAME_MAX + QSC_USERNAME_SYSTEM_NAME_MAX + QSC_NETUTILS_MAC_ADDRESS_SIZE] = { 0 };
		size_t pos;

		pos = qsc_sysutils_computer_name(buff);
		pos += qsc_sysutils_user_name(buff + pos);

		qsc_netutils_get_mac_address(buff + pos);
		pos += QSC_NETUTILS_MAC_ADDRESS_SIZE;

		qsc_shake256_compute(output, outlen, buff, pos);
	}
}

void mpdc_crypto_generate_hash_code(char* output, const char* message, size_t msglen)
{
	assert(output != NULL);
	assert(message != NULL);
	assert(msglen != 0);

	if (output != NULL && message != NULL && msglen != 0)
	{
		qsc_sha3_compute256(output, message, msglen);
	}
}

void mpdc_crypto_generate_mac_code(char* output, size_t outlen, const char* message, size_t msglen, const char* key, size_t keylen)
{
	assert(output != NULL);
	assert(outlen != 0);
	assert(message != NULL);
	assert(msglen != 0);
	assert(key != NULL);
	assert(keylen != 0);

	if (output != NULL && outlen != 0 && message != NULL && msglen != 0 && key != NULL && keylen != 0)
	{
		qsc_kmac256_compute(output, outlen, message, msglen, key, keylen, NULL, 0);
	}
}

void mpdc_crypto_hash_password(char* output, size_t outlen, const char* username, size_t userlen, const char* password, size_t passlen)
{
	assert(output != NULL);
	assert(outlen != 0);
	assert(username != NULL);
	assert(userlen != 0);
	assert(password != NULL);
	assert(passlen != 0);

	if (output != NULL && outlen != 0 && username != NULL && userlen != 0 && password != NULL && passlen != 0)
	{
		uint8_t salt[MPDC_CRYPTO_SYMMETRIC_TOKEN_SIZE] = { 0 };

		mpdc_crypto_generate_application_salt(salt, sizeof(salt));
		qsc_kmac256_compute(output, outlen, username, userlen, password, passlen, salt, sizeof(salt));
	}
}

bool mpdc_crypto_password_minimum_check(const char* password, size_t passlen)
{
	assert(password != NULL);
	assert(passlen != 0);

	bool res;
	uint8_t hsp;
	uint8_t lsp;
	uint8_t nsp;

	res = false;
	hsp = 0;
	lsp = 0;
	nsp = 0;

	if (password != NULL && passlen != 0)
	{
		if (passlen >= MPDC_STORAGE_PASSWORD_MIN && passlen <= MPDC_STORAGE_PASSWORD_MAX)
		{
			for (size_t i = 0; i < passlen; ++i)
			{
				if (((uint8_t)password[i] >= 65 && (uint8_t)password[i] <= 90) ||
					((uint8_t)password[i] >= 97 && (uint8_t)password[i] <= 122))
				{
					++lsp;
				}

				if (((uint8_t)password[i] >= 33 && (uint8_t)password[i] <= 46) ||
					((uint8_t)password[i] >= 58 && (uint8_t)password[i] <= 64))
				{
					++hsp;
				}

				if ((uint8_t)password[i] >= 48 && (uint8_t)password[i] <= 57)
				{
					++nsp;
				}
			}

			if ((lsp > 0 && hsp > 0 && nsp > 0) && (lsp + hsp + nsp) >= 8)
			{
				res = true;
			}
		}
	}

	return res;
}

bool mpdc_crypto_password_verify(const char* username, size_t userlen, const char* password, size_t passlen, const char* hash, size_t hashlen)
{
	assert(username != NULL);
	assert(userlen != 0);
	assert(password != NULL);
	assert(passlen != 0);
	assert(hash != NULL);
	assert(hashlen != 0);

	bool res;

	res = false;

	if (username != NULL && userlen != 0 && password != NULL && passlen != 0 && hash != NULL && hashlen != 0)
	{
		char tmph[MPDC_CRYPTO_SYMMETRIC_HASH_SIZE] = { 0 };

		mpdc_crypto_hash_password(tmph, sizeof(tmph), username, userlen, password, passlen);
		res = qsc_memutils_are_equal(tmph, hash, hashlen);
	}

	return res;
}
