#include "crypto.h"
#include "acp.h"
#include "cpuidex.h"
#include "intutils.h"
#include "memutils.h"
#include "netutils.h"
#include "scb.h"
#include "sysutils.h"

uint8_t* mpdc_crypto_secure_memory_allocate(size_t length)
{
	MPDC_ASSERT(length != 0U);

	uint8_t* pblk;

	pblk = NULL;

	if (length != 0U)
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
	MPDC_ASSERT(block != NULL);
	MPDC_ASSERT(length != 0U);

	if (block != NULL && length != 0U)
	{
		qsc_memutils_secure_erase(block, length);
		qsc_memutils_secure_free(block, length);
		block = NULL;
	}
}

void mpdc_crypto_generate_application_keychain(uint8_t* seed, size_t seedlen, const char* password, size_t passlen, const char* username, size_t userlen)
{
	MPDC_ASSERT(seed != NULL);
	MPDC_ASSERT(seedlen != 0U);
	MPDC_ASSERT(password != NULL);
	MPDC_ASSERT(passlen != 0U);
	MPDC_ASSERT(username != NULL);
	MPDC_ASSERT(userlen != 0U);

	if (seed != NULL && seedlen != 0U && password != NULL && passlen != 0U && username != NULL && userlen != 0U)
	{
		uint8_t salt[QSC_SHA3_256_HASH_SIZE] = { 0 };
		uint8_t phash[QSC_SHA3_256_HASH_SIZE] = { 0 };
		qsc_scb_state scbx = { 0 };

		mpdc_crypto_generate_application_salt(salt, sizeof(salt));
		qsc_cshake256_compute(phash, sizeof(phash), (const uint8_t*)password, passlen, NULL, 0U, (const uint8_t*)username, userlen);

		/* use cost based kdf to generate the stored comparison value */
		qsc_scb_initialize(&scbx, phash, sizeof(phash), salt, sizeof(salt), MPDC_CRYPTO_PHASH_CPU_COST, MPDC_CRYPTO_PHASH_MEMORY_COST);
		qsc_scb_generate(&scbx, seed, seedlen);
		qsc_scb_dispose(&scbx);
	}
}

bool mpdc_crypto_decrypt_stream(uint8_t* output, const uint8_t* seed, const uint8_t* input, size_t length)
{
	MPDC_ASSERT(output != NULL);
	MPDC_ASSERT(seed != NULL);
	MPDC_ASSERT(input != NULL);
	MPDC_ASSERT(length != 0U);

	bool res;

	res = false;

	if (output != NULL && seed != NULL && input != NULL && length != 0U)
	{
		mpdc_cipher_state ctx = { 0 };

		const mpdc_cipher_keyparams kp = {
			.key = seed,
			.keylen = MPDC_CRYPTO_SYMMETRIC_KEY_SIZE,
			.nonce = (uint8_t*)seed + MPDC_CRYPTO_SYMMETRIC_KEY_SIZE,
			.info = NULL,
			.infolen = 0 };

		mpdc_cipher_initialize(&ctx, &kp, false);
		res = mpdc_cipher_transform(&ctx, output, input, length);
		mpdc_cipher_dispose(&ctx);
	}

	return res;
}

void mpdc_crypto_encrypt_stream(uint8_t* output, const uint8_t* seed, const uint8_t* input, size_t length)
{
	MPDC_ASSERT(output != NULL);
	MPDC_ASSERT(seed != NULL);
	MPDC_ASSERT(input != NULL);
	MPDC_ASSERT(length != 0U);

	mpdc_cipher_state ctx = { 0 };

	if (output != NULL && seed != NULL && input != NULL && length != 0U)
	{
		const mpdc_cipher_keyparams kp = {
		.key = seed,
		.keylen = MPDC_CRYPTO_SYMMETRIC_KEY_SIZE,
		.nonce = (uint8_t*)seed + MPDC_CRYPTO_SYMMETRIC_KEY_SIZE,
		.info = NULL,
		.infolen = 0U };

		mpdc_cipher_initialize(&ctx, &kp, true);
		mpdc_cipher_transform(&ctx, output, input, length);
		mpdc_cipher_dispose(&ctx);
	}
}

void mpdc_crypto_generate_application_salt(uint8_t* output, size_t outlen)
{
	MPDC_ASSERT(output != NULL);
	MPDC_ASSERT(outlen != 0U);

	if (output != NULL && outlen != 0U)
	{
		uint8_t buff[QSC_SYSUTILS_SYSTEM_NAME_MAX + QSC_USERNAME_SYSTEM_NAME_MAX + QSC_NETUTILS_MAC_ADDRESS_SIZE] = { 0U };
		size_t pos;

		pos = qsc_sysutils_computer_name((char*)buff);
		pos += qsc_sysutils_user_name((char*)buff + pos);

		qsc_netutils_get_mac_address(buff + pos);
		pos += QSC_NETUTILS_MAC_ADDRESS_SIZE;

		qsc_shake256_compute(output, outlen, buff, pos);
	}
}

void mpdc_crypto_generate_hash_code(uint8_t* output, const uint8_t* message, size_t msglen)
{
	MPDC_ASSERT(output != NULL);
	MPDC_ASSERT(message != NULL);
	MPDC_ASSERT(msglen != 0U);

	if (output != NULL && message != NULL && msglen != 0U)
	{
		qsc_sha3_compute256(output, message, msglen);
	}
}

void mpdc_crypto_generate_mac_code(uint8_t* output, size_t outlen, const uint8_t* message, size_t msglen, const uint8_t* key, size_t keylen)
{
	MPDC_ASSERT(output != NULL);
	MPDC_ASSERT(outlen != 0U);
	MPDC_ASSERT(message != NULL);
	MPDC_ASSERT(msglen != 0U);
	MPDC_ASSERT(key != NULL);
	MPDC_ASSERT(keylen != 0U);

	if (output != NULL && outlen != 0U && message != NULL && msglen != 0 && key != NULL && keylen != 0U)
	{
		qsc_kmac256_compute(output, outlen, message, msglen, key, keylen, NULL, 0U);
	}
}

void mpdc_crypto_hash_password(uint8_t* output, size_t outlen, const uint8_t* username, size_t userlen, const uint8_t* password, size_t passlen)
{
	MPDC_ASSERT(output != NULL);
	MPDC_ASSERT(outlen != 0U);
	MPDC_ASSERT(username != NULL);
	MPDC_ASSERT(userlen != 0U);
	MPDC_ASSERT(password != NULL);
	MPDC_ASSERT(passlen != 0U);

	if (output != NULL && outlen != 0U && username != NULL && userlen != 0U && password != NULL && passlen != 0U)
	{
		uint8_t salt[MPDC_CRYPTO_SYMMETRIC_TOKEN_SIZE] = { 0U };

		mpdc_crypto_generate_application_salt(salt, sizeof(salt));
		qsc_kmac256_compute(output, outlen, username, userlen, password, passlen, salt, sizeof(salt));
	}
}

bool mpdc_crypto_password_minimum_check(const char* password, size_t passlen)
{
	MPDC_ASSERT(password != NULL);
	MPDC_ASSERT(passlen != 0U);

	bool res;
	uint8_t hsp;
	uint8_t lsp;
	uint8_t nsp;

	res = false;
	hsp = 0;
	lsp = 0;
	nsp = 0;

	if (password != NULL && passlen != 0U)
	{
		if (passlen >= MPDC_STORAGE_PASSWORD_MIN && passlen <= MPDC_STORAGE_PASSWORD_MAX)
		{
			for (size_t i = 0U; i < passlen; ++i)
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

			if ((lsp > 0U && hsp > 0U && nsp > 0U) && (lsp + hsp + nsp) >= 8U)
			{
				res = true;
			}
		}
	}

	return res;
}

bool mpdc_crypto_password_verify(const uint8_t* username, size_t userlen, const uint8_t* password, size_t passlen, const uint8_t* hash, size_t hashlen)
{
	MPDC_ASSERT(username != NULL);
	MPDC_ASSERT(userlen != 0U);
	MPDC_ASSERT(password != NULL);
	MPDC_ASSERT(passlen != 0U);
	MPDC_ASSERT(hash != NULL);
	MPDC_ASSERT(hashlen != 0U);

	bool res;

	res = false;

	if (username != NULL && userlen != 0U && password != NULL && passlen != 0 && hash != NULL && hashlen != 0U)
	{
		uint8_t tmph[MPDC_CRYPTO_SYMMETRIC_HASH_SIZE] = { 0U };

		mpdc_crypto_hash_password(tmph, sizeof(tmph), (const uint8_t*)username, userlen, (const uint8_t*)password, passlen);
		res = qsc_memutils_are_equal(tmph, hash, hashlen);
	}

	return res;
}
