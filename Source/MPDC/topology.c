#include "topology.h"
#include "async.h"
#include "fileutils.h"
#include "intutils.h"
#include "memutils.h"
#include "sha3.h"
#include "stringutils.h"
#if defined(MPDC_DEBUG_MODE)
#	include "acp.h"
#endif

void mpdc_topology_address_from_issuer(char* address, const char* issuer, const mpdc_topology_list_state* list)
{
	MPDC_ASSERT(address != NULL);
	MPDC_ASSERT(issuer != NULL);
	MPDC_ASSERT(list != NULL);

	size_t clen;

	if (address != NULL && issuer != NULL && list != NULL && list->topology != NULL && list->count > 0)
	{
		for (size_t i = 0; i < list->count; ++i)
		{
			clen = qsc_stringutils_string_size(issuer);

			if (clen > 0)
			{
				mpdc_topology_node_state node = { 0 };

				if (mpdc_topology_list_item(list, &node, i) == true)
				{
					if (qsc_memutils_are_equal((const uint8_t*)node.issuer, (const uint8_t*)issuer, clen) == true)
					{
						qsc_memutils_copy(address, node.address, MPDC_CERTIFICATE_ADDRESS_SIZE);
						break;
					}
				}
			}
		}
	}
}

uint8_t* mpdc_topology_child_add_empty_node(mpdc_topology_list_state* list)
{
	MPDC_ASSERT(list != NULL);

	uint8_t* nptr;
	uint8_t* ttmp;
	size_t nctx;

	nptr = NULL;
	ttmp = NULL;

	if (list != NULL)
	{
		qsc_mutex mtx;

		mtx = qsc_async_mutex_lock_ex();

		nctx = list->count + 1;

		if (list->topology != NULL)
		{
			ttmp = qsc_memutils_realloc(list->topology, nctx * MPDC_NETWORK_TOPOLOGY_NODE_SIZE);

			if (ttmp != NULL)
			{
				list->topology = ttmp;
			}
		}
		else
		{
			list->topology = qsc_memutils_malloc(nctx * MPDC_NETWORK_TOPOLOGY_NODE_SIZE);
		}

		nptr = (uint8_t*)(list->topology + (list->count * MPDC_NETWORK_TOPOLOGY_NODE_SIZE));

		qsc_memutils_clear(nptr, MPDC_NETWORK_TOPOLOGY_NODE_SIZE);
		++list->count;

		qsc_async_mutex_unlock_ex(mtx);
	}

	return nptr;
}

void mpdc_topology_child_add_item(mpdc_topology_list_state* list, const mpdc_topology_node_state* node)
{
	MPDC_ASSERT(list != NULL);
	MPDC_ASSERT(node != NULL);

	uint8_t* nptr;

	if (list != NULL && node != NULL)
	{
		qsc_mutex mtx;

		mtx = qsc_async_mutex_lock_ex();

		mpdc_topology_node_remove_duplicate(list, node->issuer);

		nptr = mpdc_topology_child_add_empty_node(list);
		mpdc_topology_node_serialize(nptr, node);

		qsc_async_mutex_unlock_ex(mtx);
	}
}

bool mpdc_topology_canonical_to_issuer_name(char* issuer, size_t isslen, const char* domain, const char* cname)
{
	MPDC_ASSERT(issuer != NULL);
	MPDC_ASSERT(isslen != 0);
	MPDC_ASSERT(domain != NULL);
	MPDC_ASSERT(cname != NULL);

	size_t len;
	int64_t pos;
	bool res;

	const char EXT[] = ".ccert";
	const char SEP[] = "_";

	res = false;

	if (issuer != NULL && isslen != 0 && domain != NULL && cname != NULL)
	{
		len = qsc_stringutils_string_size(cname) + 
			qsc_stringutils_string_size(domain) + 
			qsc_stringutils_string_size(EXT) +
			qsc_stringutils_string_size(SEP);

		if (isslen >= len)
		{
			pos = qsc_stringutils_string_size(domain);
			qsc_stringutils_copy_substring(issuer, isslen, domain, pos);
			qsc_stringutils_concat_strings(issuer, isslen, SEP);
			qsc_stringutils_concat_strings(issuer, isslen, cname);
			qsc_stringutils_to_uppercase(issuer);
			qsc_stringutils_concat_strings(issuer, isslen, EXT);
			res = true;
		}
	}

	return res;
}

bool mpdc_topology_issuer_to_canonical_name(char* cname, size_t namelen, const char* issuer)
{
	MPDC_ASSERT(cname != NULL);
	MPDC_ASSERT(namelen != 0);
	MPDC_ASSERT(issuer != NULL);

	size_t len;
	int64_t pos;
	bool res;

	res = false;

	if (cname != NULL && namelen != 0 && issuer != NULL)
	{
		len = qsc_stringutils_string_size(issuer);

		if (len < namelen)
		{
			pos = qsc_stringutils_find_string(issuer, "_");

			if (pos > 0)
			{
				qsc_stringutils_copy_substring(cname, namelen, issuer, pos);
				qsc_stringutils_concat_strings(cname, namelen, ".");
				len = qsc_stringutils_find_string(issuer, ".");

				if (len > 0)
				{
					++pos;
					qsc_stringutils_copy_substring(cname + pos, namelen, issuer + pos, len - pos);
					qsc_stringutils_to_lowercase(cname);
					res = true;
				}
			}
		}
	}

	return res;
}

void mpdc_topology_child_register(mpdc_topology_list_state* list, const mpdc_child_certificate* ccert, const char* address)
{
	MPDC_ASSERT(list != NULL);
	MPDC_ASSERT(ccert != NULL);
	MPDC_ASSERT(address != NULL);

	mpdc_topology_node_state node = { 0 };
	uint8_t* nptr;

	nptr = NULL;

	if (list != NULL && ccert != NULL && address != NULL)
	{
		qsc_mutex mtx;

		mtx = qsc_async_mutex_lock_ex();

		mpdc_topology_node_remove_duplicate(list, ccert->issuer);

		qsc_memutils_copy(node.issuer, ccert->issuer, MPDC_CERTIFICATE_ISSUER_SIZE);
		qsc_memutils_copy(node.serial, ccert->serial, MPDC_CERTIFICATE_SERIAL_SIZE);
		qsc_memutils_copy(node.address, address, MPDC_CERTIFICATE_ADDRESS_SIZE);
		qsc_memutils_copy(&node.expiration, &ccert->expiration, MPDC_CERTIFICATE_EXPIRATION_SIZE);
		node.designation = ccert->designation;
		mpdc_certificate_child_hash(node.chash, ccert);

		nptr = mpdc_topology_child_add_empty_node(list);
		mpdc_topology_node_serialize(nptr, &node);

		qsc_async_mutex_unlock_ex(mtx);
	}
}

void mpdc_topology_list_clone(const mpdc_topology_list_state* tlist, mpdc_topology_list_state* tcopy)
{
	for (size_t i = 0; i < tlist->count; ++i)
	{
		mpdc_topology_node_state node = { 0 };
		uint8_t* nptr;

		if (mpdc_topology_list_item(tlist, &node, i) == true)
		{
			nptr = mpdc_topology_child_add_empty_node(tcopy);
			mpdc_topology_node_serialize(nptr, &node);
		}
	}
}

void mpdc_topology_list_deserialize(mpdc_topology_list_state* list, const uint8_t* input, size_t inplen)
{
	MPDC_ASSERT(list != NULL);
	MPDC_ASSERT(input != NULL);

	size_t cnt;
	size_t pos;

	if (list != NULL && input != NULL)
	{
		cnt = (size_t)qsc_intutils_le8to32(input);
		pos = sizeof(uint32_t);

		for (size_t i = 0; i < cnt; ++i)
		{
			mpdc_topology_node_state node = { 0 };
			uint8_t* nptr;

			if (pos >= inplen)
			{
				break;
			}

			mpdc_topology_node_deserialize(&node, input + pos);
			nptr = mpdc_topology_child_add_empty_node(list);
			mpdc_topology_node_serialize(nptr, &node);

			pos += MPDC_NETWORK_TOPOLOGY_NODE_SIZE;
		}
	}
}
 
void mpdc_topology_list_dispose(mpdc_topology_list_state* list)
{
	MPDC_ASSERT(list != NULL);

	if (list != NULL)
	{
		if (list->topology != NULL)
		{
			qsc_memutils_clear(list->topology, list->count * MPDC_NETWORK_TOPOLOGY_NODE_SIZE);
			qsc_memutils_alloc_free(list->topology);
			list->topology = NULL;
			list->count = 0;
		}
	}
}

void mpdc_topology_list_initialize(mpdc_topology_list_state* list)
{
	MPDC_ASSERT(list != NULL);

	if (list != NULL)
	{
		list->count = 0;
		list->topology = NULL;
	}
}

bool mpdc_topology_list_item(const mpdc_topology_list_state* list, mpdc_topology_node_state* node, size_t index)
{
	MPDC_ASSERT(list != NULL);
	MPDC_ASSERT(node != NULL);

	bool res;

	res = false;

	if (list != NULL && node != NULL && index < list->count)
	{
		const uint8_t* nptr;
		qsc_mutex mtx;

		mtx = qsc_async_mutex_lock_ex();

		nptr = (uint8_t*)(list->topology + (index * MPDC_NETWORK_TOPOLOGY_NODE_SIZE));
		mpdc_topology_node_deserialize(node, nptr);
		res = true;

		qsc_async_mutex_unlock_ex(mtx);
	}

	return res;
}

size_t mpdc_topology_list_remove_duplicates(mpdc_topology_list_state* list)
{
	MPDC_ASSERT(list != NULL);

	uint8_t* np1;
	uint8_t* np2;
	uint8_t* ntop;
	size_t ctr;
	size_t len;
	size_t pos;
	qsc_mutex mtx;

	ctr = 0;

	if (list != NULL)
	{
		mtx = qsc_async_mutex_lock_ex();

		pos = 0;
		len = list->count * MPDC_NETWORK_TOPOLOGY_NODE_SIZE;
		ntop = (uint8_t*)qsc_memutils_malloc(len);

		if (ntop != NULL)
		{
			uint8_t* ptmp;

			qsc_memutils_clear(ntop, len);

			for (size_t i = 0; i < list->count; ++i)
			{
				bool res;

				np1 = (uint8_t*)(list->topology + (i * MPDC_NETWORK_TOPOLOGY_NODE_SIZE));
				np2 = NULL;
				res = false;

				for (size_t j = i + 1; j < list->count; ++j)
				{
					np2 = (uint8_t*)(list->topology + (j * MPDC_NETWORK_TOPOLOGY_NODE_SIZE));

					if (qsc_memutils_are_equal(np1, np2, MPDC_NETWORK_TOPOLOGY_NODE_SIZE) == true)
					{
						res = true;
						break;
					}
				}

				if (res == false)
				{
					qsc_memutils_copy(ntop + pos, np1, MPDC_NETWORK_TOPOLOGY_NODE_SIZE);
					pos += MPDC_NETWORK_TOPOLOGY_NODE_SIZE;
					++ctr;
				}
			}

			ptmp = qsc_memutils_realloc(list->topology, ctr * MPDC_NETWORK_TOPOLOGY_NODE_SIZE);

			if (ptmp != NULL)
			{
				list->topology = ptmp;
				qsc_memutils_copy(list->topology, ntop, ctr * MPDC_NETWORK_TOPOLOGY_NODE_SIZE);
				list->count = (uint32_t)ctr;
			}

			qsc_memutils_alloc_free(ntop);
		}

		qsc_async_mutex_unlock_ex(mtx);
	}

	return ctr;
}

size_t mpdc_topology_list_server_count(const mpdc_topology_list_state* list, mpdc_network_designations ntype)
{
	MPDC_ASSERT(list != NULL);

	size_t cnt;

	cnt = 0;

	if (list != NULL)
	{
		for (size_t i = 0; i < list->count; ++i)
		{
			mpdc_topology_node_state ntmp = { 0 };

			if (mpdc_topology_list_item(list, &ntmp, i) == true)
			{
				if (ntmp.designation == ntype)
				{
					++cnt;
				}
			}
		}
	}

	return cnt;
}

size_t mpdc_topology_list_serialize(uint8_t* output, const mpdc_topology_list_state* list)
{
	MPDC_ASSERT(output != NULL);
	MPDC_ASSERT(list != NULL);

	size_t pos;

	pos = 0;

	if (output != NULL && list != NULL)
	{
		qsc_intutils_le32to8(output, list->count);
		pos += sizeof(uint32_t);

		for (size_t i = 0; i < list->count; ++i)
		{
			mpdc_topology_node_state node = { 0 };

			if (mpdc_topology_list_item(list, &node, i) == true)
			{
				mpdc_topology_node_serialize(output + pos, &node);
				pos += MPDC_NETWORK_TOPOLOGY_NODE_SIZE;
			}
		}
	}

	return pos;
}

size_t mpdc_topology_list_size(const mpdc_topology_list_state* list)
{
	MPDC_ASSERT(list != NULL);

	size_t rlen;

	rlen = 0;

	if (list != NULL)
	{
		if (list->count > 0)
		{
			rlen = sizeof(uint32_t) + (list->count * MPDC_NETWORK_TOPOLOGY_NODE_SIZE);
		}
	}

	return rlen;
}

size_t mpdc_topology_list_update_pack(uint8_t* output, const mpdc_topology_list_state* list, mpdc_network_designations ntype)
{
	MPDC_ASSERT(output != NULL);
	MPDC_ASSERT(list != NULL);

	size_t pos;

	pos = 0;

	if (output != NULL && list != NULL)
	{
		for (size_t i = 0; i < list->count; ++i)
		{
			mpdc_topology_node_state ntmp = { 0 };

			if (mpdc_topology_list_item(list, &ntmp, i) == true)
			{
				if (ntmp.designation == ntype || ntype == mpdc_network_designation_all)
				{
					mpdc_topology_node_serialize(output + pos, &ntmp);
					pos += MPDC_NETWORK_TOPOLOGY_NODE_SIZE;
				}
			}
		}
	}

	return pos;
}

size_t mpdc_topology_list_update_unpack(mpdc_topology_list_state* list, const uint8_t* input, size_t inplen)
{
	MPDC_ASSERT(list != NULL);
	MPDC_ASSERT(input != NULL);

	size_t cnt;
	size_t pos;

	cnt = 0;

	if (list != NULL && input != NULL && inplen >= MPDC_NETWORK_TOPOLOGY_NODE_SIZE)
	{
		pos = 0;
		cnt = inplen / MPDC_NETWORK_TOPOLOGY_NODE_SIZE;

		for (size_t i = 0; i < cnt; ++i)
		{
			mpdc_topology_node_state node = { 0 };
			uint8_t* nptr;

			mpdc_topology_node_deserialize(&node, input + pos);
			nptr = mpdc_topology_child_add_empty_node(list);
			mpdc_topology_node_serialize(nptr, &node);
			pos += MPDC_NETWORK_TOPOLOGY_NODE_SIZE;
		}
	}

	return cnt;
}

size_t mpdc_topology_ordered_server_list(mpdc_topology_list_state* olist, const mpdc_topology_list_state* tlist, mpdc_network_designations ntype)
{
	MPDC_ASSERT(olist != NULL);
	MPDC_ASSERT(tlist != NULL);

	size_t dcnt;
	size_t scnt;

	scnt = 0;

	if (olist != NULL && tlist != NULL)
	{
		qsc_list_state slst = { 0 };
		mpdc_topology_node_state node = { 0 };

		dcnt = mpdc_topology_list_server_count(tlist, ntype);

		if (dcnt > 0)
		{
			/* iterate through the topology list and add nodes of the device type */
			qsc_list_initialize(&slst, MPDC_CERTIFICATE_SERIAL_SIZE);

			for (size_t i = 0; i < tlist->count; ++i)
			{
				mpdc_topology_list_item(tlist, &node, i);

				if (node.designation == ntype || ntype == mpdc_network_designation_all)
				{
					qsc_list_add(&slst, node.serial);
				}
			}

			if (slst.count > 0)
			{
				uint8_t sern[MPDC_CERTIFICATE_SERIAL_SIZE] = { 0 };

				scnt = slst.count;

				/* sort the list of serial numbers */
				qsc_list_sort(&slst);

				/* fill the output topology state with nodes ordered by serial number  */
				for (size_t i = 0; i < slst.count; ++i)
				{
					qsc_list_item(&slst, sern, i);

					if (mpdc_topology_node_find(tlist, &node, sern) == true)
					{
						mpdc_topology_child_add_item(olist, &node);
					}
				}
			}
		}
	}

	return scnt;
}

void mpdc_topology_node_add_alias(mpdc_topology_node_state* node, const char* alias)
{
	MPDC_ASSERT(node != NULL);
	MPDC_ASSERT(alias != NULL);

	size_t apos;
	size_t ilen;

	if (node != NULL && alias != NULL && qsc_stringutils_string_size(alias) >= MPDC_TOPOLOGY_NODE_MINIMUM_ISSUER_SIZE)
	{
		qsc_mutex mtx;

		mtx = qsc_async_mutex_lock_ex();

		ilen = qsc_stringutils_string_size(node->issuer);

		if (ilen >= MPDC_TOPOLOGY_NODE_MINIMUM_ISSUER_SIZE)
		{
			apos = qsc_stringutils_find_string(node->issuer, MPDC_TOPOLOGY_ALIAS_DELIMITER);

			if (apos > 0)
			{
				qsc_memutils_clear(node->issuer + apos, ilen - apos);
				qsc_stringutils_concat_strings(node->issuer, MPDC_CERTIFICATE_ISSUER_SIZE, MPDC_TOPOLOGY_ALIAS_DELIMITER);
			}
		}

		qsc_stringutils_concat_strings(node->issuer, MPDC_CERTIFICATE_ISSUER_SIZE, alias);

		qsc_async_mutex_unlock_ex(mtx);
	}
}

bool mpdc_topology_nodes_are_equal(const mpdc_topology_node_state* a, const mpdc_topology_node_state* b)
{
	MPDC_ASSERT(a != NULL);
	MPDC_ASSERT(b != NULL);

	bool res;

	res = false;

	if (a != NULL && b != NULL)
	{
		if (qsc_memutils_are_equal((const uint8_t*)a->address, (const uint8_t*)b->address, MPDC_CERTIFICATE_ADDRESS_SIZE) == true)
		{
			if (qsc_memutils_are_equal(a->chash, b->chash, MPDC_CERTIFICATE_HASH_SIZE) == true)
			{
				if (qsc_memutils_are_equal(a->serial, b->serial, MPDC_CERTIFICATE_SERIAL_SIZE) == true)
				{
					if (qsc_memutils_are_equal((const uint8_t*)a->issuer, (const uint8_t*)b->issuer, MPDC_CERTIFICATE_ISSUER_SIZE) == true)
					{
						if (a->expiration.from == b->expiration.from && a->expiration.to == b->expiration.to)
						{
							if (a->designation == b->designation)
							{
								res = true;
							}
						}
					}
				}
			}
		}
	}

	return res;
}

void mpdc_topology_node_clear(mpdc_topology_node_state* node)
{
	MPDC_ASSERT(node != NULL);

	if (node != NULL)
	{
		qsc_memutils_clear(node->issuer, MPDC_CERTIFICATE_ISSUER_SIZE);
		qsc_memutils_clear(node->address, MPDC_CERTIFICATE_ADDRESS_SIZE);
		qsc_memutils_clear(node->chash, MPDC_CRYPTO_SYMMETRIC_HASH_SIZE);
		qsc_memutils_clear(node->serial, MPDC_CERTIFICATE_SERIAL_SIZE);
		node->expiration.from = 0;
		node->expiration.to = 0;
		node->designation = mpdc_network_designation_none;
	}
}

void mpdc_topology_node_copy(const mpdc_topology_node_state* source, mpdc_topology_node_state* destination)
{
	MPDC_ASSERT(source != NULL);
	MPDC_ASSERT(destination != NULL);

	if (source != NULL && destination != NULL)
	{
		qsc_memutils_copy(destination->issuer, source->issuer, MPDC_CERTIFICATE_ISSUER_SIZE);
		qsc_memutils_copy(destination->address, source->address, MPDC_CERTIFICATE_ADDRESS_SIZE);
		qsc_memutils_copy(destination->chash, source->chash, MPDC_CRYPTO_SYMMETRIC_HASH_SIZE);
		qsc_memutils_copy(destination->serial, source->serial, MPDC_CERTIFICATE_SERIAL_SIZE);
		destination->expiration.from = source->expiration.from;
		destination->expiration.to = source->expiration.to;
		destination->designation = source->designation;
	}
}

void mpdc_topology_node_deserialize(mpdc_topology_node_state* node, const uint8_t* input)
{
	MPDC_ASSERT(node != NULL);
	MPDC_ASSERT(input != NULL);

	size_t pos;
	
	if (node != NULL && input != NULL)
	{
		qsc_memutils_copy(node->issuer, input, MPDC_CERTIFICATE_ISSUER_SIZE);
		pos = MPDC_CERTIFICATE_ISSUER_SIZE;
		qsc_memutils_copy(node->serial, input + pos, MPDC_CERTIFICATE_SERIAL_SIZE);
		pos += MPDC_CERTIFICATE_SERIAL_SIZE;
		qsc_memutils_copy(node->address, input + pos, MPDC_CERTIFICATE_ADDRESS_SIZE);
		pos += MPDC_CERTIFICATE_ADDRESS_SIZE;
		qsc_memutils_copy(node->chash, input + pos, MPDC_CRYPTO_SYMMETRIC_HASH_SIZE);
		pos += MPDC_CRYPTO_SYMMETRIC_HASH_SIZE;
		node->expiration.from = qsc_intutils_le8to64(input + pos);
		pos += sizeof(uint64_t);
		node->expiration.to = qsc_intutils_le8to64(input + pos);
		pos += sizeof(uint64_t);
		node->designation = input[pos];
	}
}

bool mpdc_topology_node_find(const mpdc_topology_list_state* list, mpdc_topology_node_state* node, const uint8_t* serial)
{
	MPDC_ASSERT(list != NULL);
	MPDC_ASSERT(node != NULL);
	MPDC_ASSERT(serial != NULL);

	bool res;

	res = false;

	if (list != NULL && node != NULL && serial != NULL)
	{
		qsc_mutex mtx;

		mtx = qsc_async_mutex_lock_ex();

		for (size_t i = 0; i < list->count; ++i)
		{
			mpdc_topology_node_state ntmp = { 0 };

			if (mpdc_topology_list_item(list, &ntmp, i) == true)
			{
				if (qsc_memutils_are_equal_128(ntmp.serial, serial) == true)
				{
					mpdc_topology_node_copy(&ntmp, node);
					res = true;
					break;
				}
			}
		}

		qsc_async_mutex_unlock_ex(mtx);
	}

	return res;
}

bool mpdc_topology_node_find_address(const mpdc_topology_list_state* list, mpdc_topology_node_state* node, const char* address)
{
	MPDC_ASSERT(list != NULL);
	MPDC_ASSERT(node != NULL);
	MPDC_ASSERT(address != NULL);

	bool res;

	res = false;

	if (list != NULL && node != NULL && address != NULL)
	{
		qsc_mutex mtx;

		mtx = qsc_async_mutex_lock_ex();

		for (size_t i = 0; i < list->count; ++i)
		{
			mpdc_topology_node_state ntmp = { 0 };

			if (mpdc_topology_list_item(list, &ntmp, i) == true)
			{
				if (qsc_memutils_are_equal_128((const uint8_t*)ntmp.address, (const uint8_t*)address) == true)
				{
					mpdc_topology_node_copy(&ntmp, node);
					res = true;
					break;
				}
			}
		}
		
		qsc_async_mutex_unlock_ex(mtx);
	}

	return res;
}

bool mpdc_topology_node_find_alias(const mpdc_topology_list_state* list, mpdc_topology_node_state* node, const char* alias)
{
	MPDC_ASSERT(list != NULL);
	MPDC_ASSERT(node != NULL);
	MPDC_ASSERT(alias != NULL);

	bool res;

	res = false;

	if (list != NULL && node != NULL && alias != NULL && qsc_stringutils_string_size(alias) >= MPDC_TOPOLOGY_NODE_MINIMUM_ISSUER_SIZE)
	{
		qsc_mutex mtx;

		mtx = qsc_async_mutex_lock_ex();

		for (size_t i = 0; i < list->count; ++i)
		{
			mpdc_topology_node_state ntmp = { 0 };

			if (mpdc_topology_list_item(list, &ntmp, i) == true)
			{
				if (qsc_stringutils_string_contains(ntmp.issuer, alias) == true)
				{
					mpdc_topology_node_copy(&ntmp, node);
					res = true;
					break;
				}
			}
		}

		qsc_async_mutex_unlock_ex(mtx);
	}

	return res;
}

bool mpdc_topology_node_find_dla(const mpdc_topology_list_state* list, mpdc_topology_node_state* node)
{
	MPDC_ASSERT(list != NULL);
	MPDC_ASSERT(node != NULL);

	bool res;

	res = false;

	if (list != NULL && node != NULL)
	{
		qsc_mutex mtx;

		mtx = qsc_async_mutex_lock_ex();

		for (size_t i = 0; i < list->count; ++i)
		{
			mpdc_topology_node_state ntmp = { 0 };

			if (mpdc_topology_list_item(list, &ntmp, i) == true)
			{
				if (ntmp.designation == mpdc_network_designation_dla)
				{
					mpdc_topology_node_copy(&ntmp, node);
					res = true;
					break;
				}
			}
		}

		qsc_async_mutex_unlock_ex(mtx);
	}

	return res;
}

bool mpdc_topology_node_find_issuer(const mpdc_topology_list_state* list, mpdc_topology_node_state* node, const char* issuer)
{
	MPDC_ASSERT(list != NULL);
	MPDC_ASSERT(node != NULL);
	MPDC_ASSERT(issuer != NULL);

	size_t clen;
	bool res;

	res = false;

	if (list != NULL && node != NULL && issuer != NULL)
	{
		qsc_mutex mtx;

		mtx = qsc_async_mutex_lock_ex();
		clen = qsc_stringutils_string_size(issuer);

		if (clen >= MPDC_TOPOLOGY_NODE_MINIMUM_ISSUER_SIZE)
		{
			int64_t nlen;

			nlen = qsc_stringutils_find_string(issuer, MPDC_TOPOLOGY_ALIAS_DELIMITER);
			clen = (nlen > 0 && nlen < (int64_t)clen) ? (size_t)nlen : clen;

			for (size_t i = 0; i < list->count; ++i)
			{
				mpdc_topology_node_state ntmp = { 0 };

				if (mpdc_topology_list_item(list, &ntmp, i) == true)
				{
					if (qsc_memutils_are_equal((const uint8_t*)ntmp.issuer, (const uint8_t*)issuer, clen) == true)
					{
						mpdc_topology_node_copy(&ntmp, node);
						res = true;
						break;
					}
				}
			}
		}

		qsc_async_mutex_unlock_ex(mtx);
	}

	return res;
}

bool mpdc_topology_node_find_root(const mpdc_topology_list_state* list, mpdc_topology_node_state* node)
{
	MPDC_ASSERT(list != NULL);
	MPDC_ASSERT(node != NULL);
	
	bool res;

	res = false;

	if (list != NULL && node != NULL)
	{
		qsc_mutex mtx;

		mtx = qsc_async_mutex_lock_ex();

		for (size_t i = 0; i < list->count; ++i)
		{
			mpdc_topology_node_state ntmp = { 0 };

			if (mpdc_topology_list_item(list, &ntmp, i) == true)
			{
				if (ntmp.designation == mpdc_network_designation_rds)
				{
					mpdc_topology_node_copy(&ntmp, node);
					res = true;
					break;
				}
			}
		}

		qsc_async_mutex_unlock_ex(mtx);
	}

	return res;
}

bool mpdc_topology_node_exists(const mpdc_topology_list_state* list, const uint8_t* serial)
{
	MPDC_ASSERT(list != NULL);
	MPDC_ASSERT(serial != NULL);

	bool res;

	res = false;

	if (list != NULL && serial != NULL)
	{
		res = (mpdc_topology_node_get_index(list, serial) != MPDC_TOPOLOGY_NODE_NOT_FOUND);
	}

	return res;
}

int32_t mpdc_topology_node_get_index(const mpdc_topology_list_state* list, const uint8_t* serial)
{
	MPDC_ASSERT(list != NULL);
	MPDC_ASSERT(serial != NULL);

	int32_t res;

	res = MPDC_TOPOLOGY_NODE_NOT_FOUND;

	if (list != NULL && serial != NULL)
	{
		for (size_t i = 0; i < list->count; ++i)
		{
			mpdc_topology_node_state ntmp = { 0 };

			if (mpdc_topology_list_item(list, &ntmp, i) == true)
			{
				if (qsc_memutils_are_equal_128(ntmp.serial, serial) == true)
				{
					res = (int32_t)i;
					break;
				}
			}
		}
	}

	return res;
}

void mpdc_topology_node_remove(mpdc_topology_list_state* list, const uint8_t* serial)
{
	MPDC_ASSERT(list != NULL);
	MPDC_ASSERT(serial != NULL);

	int32_t lpos;
	int32_t npos;

	if (list != NULL && serial != NULL)
	{
		if (list->count > 0)
		{
			npos = mpdc_topology_node_get_index(list, serial);

			if (npos >= 0)
			{
				uint8_t* ttmp;

				lpos = list->count - 1;

				if (npos != lpos && lpos > 0)
				{
					qsc_memutils_copy(list->topology + (npos * MPDC_NETWORK_TOPOLOGY_NODE_SIZE), list->topology + (lpos * MPDC_NETWORK_TOPOLOGY_NODE_SIZE), MPDC_NETWORK_TOPOLOGY_NODE_SIZE);
				}

				qsc_memutils_clear(list->topology + (lpos * MPDC_NETWORK_TOPOLOGY_NODE_SIZE), MPDC_NETWORK_TOPOLOGY_NODE_SIZE);
				list->count -= 1;

				if (list->count > 0)
				{
					/* resize the array */
					ttmp = qsc_memutils_realloc(list->topology, list->count * MPDC_NETWORK_TOPOLOGY_NODE_SIZE);
				}
				else
				{
					/* array placeholder */
					ttmp = qsc_memutils_realloc(list->topology, sizeof(uint8_t));
				}

				if (ttmp != NULL)
				{
					list->topology = ttmp;
				}
			}
		}
	}
}

void mpdc_topology_node_remove_duplicate(mpdc_topology_list_state* list, const char* issuer)
{
	MPDC_ASSERT(list != NULL);
	MPDC_ASSERT(issuer != NULL);

	if (list != NULL && issuer != NULL)
	{
		mpdc_topology_node_state rnode = { 0 };

		if (mpdc_topology_node_find_issuer(list, &rnode, issuer) == true)
		{
			/* delete the node from the database */
			mpdc_topology_node_remove(list, rnode.serial);
		}
	}
}

size_t mpdc_topology_node_serialize(uint8_t* output, const mpdc_topology_node_state* node)
{
	MPDC_ASSERT(output != NULL);
	MPDC_ASSERT(node != NULL);

	size_t pos;
	
	pos = 0;

	if (output != NULL && node != NULL)
	{
		qsc_memutils_copy(output, node->issuer, MPDC_CERTIFICATE_ISSUER_SIZE);
		pos = MPDC_CERTIFICATE_ISSUER_SIZE;
		qsc_memutils_copy(output + pos, node->serial, MPDC_CERTIFICATE_SERIAL_SIZE);
		pos += MPDC_CERTIFICATE_SERIAL_SIZE;
		qsc_memutils_copy(output + pos, node->address, MPDC_CERTIFICATE_ADDRESS_SIZE);
		pos += MPDC_CERTIFICATE_ADDRESS_SIZE;
		qsc_memutils_copy(output + pos, node->chash, MPDC_CRYPTO_SYMMETRIC_HASH_SIZE);
		pos += MPDC_CRYPTO_SYMMETRIC_HASH_SIZE;
		qsc_intutils_le64to8(output + pos, node->expiration.from);
		pos += sizeof(uint64_t);
		qsc_intutils_le64to8(output + pos, node->expiration.to);
		pos += sizeof(uint64_t);
		output[pos] = (uint8_t)node->designation;
		pos += sizeof(uint8_t);
	}

	return pos;
}

bool mpdc_topology_node_verify_dla(const mpdc_topology_list_state* list, const mpdc_child_certificate* ccert)
{
	MPDC_ASSERT(list != NULL);
	MPDC_ASSERT(ccert != NULL);

	bool res;

	res = false;

	if (list != NULL && ccert != NULL)
	{
		mpdc_topology_node_state node = { 0 };

		if (mpdc_topology_node_find_dla(list, &node) == true)
		{
			uint8_t lhash[MPDC_CERTIFICATE_HASH_SIZE] = { 0 };

			mpdc_certificate_child_hash(lhash, ccert);
			res = (qsc_memutils_are_equal(lhash, node.chash, MPDC_CERTIFICATE_HASH_SIZE) == true);
		}
	}

	return res;
}

bool mpdc_topology_node_verify_issuer(const mpdc_topology_list_state* list, const mpdc_child_certificate* ccert, const char* issuer)
{
	MPDC_ASSERT(list != NULL);
	MPDC_ASSERT(ccert != NULL);
	MPDC_ASSERT(issuer != NULL);

	bool res;

	res = false;

	if (list != NULL && ccert != NULL && issuer != NULL)
	{
		mpdc_topology_node_state node = { 0 };

		if (mpdc_topology_node_find_issuer(list, &node, issuer) == true)
		{
			uint8_t lhash[MPDC_CERTIFICATE_HASH_SIZE] = { 0 };

			mpdc_certificate_child_hash(lhash, ccert);
			res = (qsc_memutils_are_equal(lhash, node.chash, MPDC_CERTIFICATE_HASH_SIZE) == true);
		}
	}

	return res;
}

bool mpdc_topology_node_verify_root(const mpdc_topology_list_state* list, const mpdc_root_certificate* rcert)
{
	MPDC_ASSERT(list != NULL);
	MPDC_ASSERT(rcert != NULL);

	bool res; 

	res = false;

	if (list != NULL && rcert != NULL)
	{
		mpdc_topology_node_state node = { 0 };

		if (mpdc_topology_node_find_root(list, &node) == true)
		{
			uint8_t lhash[MPDC_CERTIFICATE_HASH_SIZE] = { 0 };

			mpdc_certificate_root_hash(lhash, rcert);
			res = (qsc_memutils_are_equal(lhash, node.chash, MPDC_CERTIFICATE_HASH_SIZE) == true);
		}
	}

	return res;
}

void mpdc_topology_root_register(mpdc_topology_list_state* list, const mpdc_root_certificate* rcert, const char* address)
{
	MPDC_ASSERT(list != NULL);
	MPDC_ASSERT(rcert != NULL);
	MPDC_ASSERT(address != NULL);

	mpdc_topology_node_state node = { 0 };
	uint8_t* nptr;
	
	if (list != NULL && rcert != NULL && address != NULL)
	{
		qsc_memutils_copy(node.issuer, rcert->issuer, MPDC_CERTIFICATE_ISSUER_SIZE);
		qsc_memutils_copy(node.serial, rcert->serial, MPDC_CERTIFICATE_SERIAL_SIZE);
		qsc_memutils_copy(node.address, address, MPDC_CERTIFICATE_ADDRESS_SIZE);
		mpdc_certificate_root_hash(node.chash, rcert);
		qsc_memutils_copy(&node.expiration, &rcert->expiration, sizeof(mpdc_certificate_expiration));
		node.designation = mpdc_network_designation_rds;

		nptr = mpdc_topology_child_add_empty_node(list);
		mpdc_topology_node_serialize(nptr, &node);
	}
}

size_t mpdc_topology_list_to_string(const mpdc_topology_list_state* list, char* output, size_t outlen)
{
	MPDC_ASSERT(list != NULL);
	MPDC_ASSERT(output != NULL);
	MPDC_ASSERT(outlen != 0);

	size_t slen;
	size_t spos;

	spos = 0;

	if (list != NULL && output != NULL && outlen != 0)
	{
		if (list->count * MPDC_TOPOLOGY_NODE_ENCODED_SIZE <= outlen)
		{
			for (size_t i = 0; i < list->count; ++i)
			{
				mpdc_topology_node_state ntmp = { 0 };

				mpdc_topology_list_item(list, &ntmp, i);
				slen = mpdc_topology_node_encode(&ntmp, output + spos);
				spos += slen;
			}
		}
	}

	return spos;
}

size_t mpdc_topology_node_encode(const mpdc_topology_node_state* node, char output[MPDC_TOPOLOGY_NODE_ENCODED_SIZE])
{
	size_t slen;
	size_t spos;

	spos = 0;

	if (node != NULL)
	{
		char dtm[QSC_TIMESTAMP_STRING_SIZE] = { 0 };

		slen = qsc_stringutils_string_size(MPDC_CHILD_CERTIFICATE_ISSUER_PREFIX);
		qsc_memutils_copy(output, MPDC_CHILD_CERTIFICATE_ISSUER_PREFIX, slen);
		spos += slen;
		slen = qsc_stringutils_string_size(node->issuer);
		qsc_memutils_copy(output + spos, node->issuer, slen);
		spos += slen;
		output[spos] = '\n';
		++spos;

		slen = qsc_stringutils_string_size(MPDC_CHILD_CERTIFICATE_ADDRESS_PREFIX);
		qsc_memutils_copy(output + spos, MPDC_CHILD_CERTIFICATE_ADDRESS_PREFIX, slen);
		spos += slen;

		if (qsc_ipinfo_get_address_type(node->address) == qsc_ipinfo_address_type_ipv4)
		{
			slen = qsc_stringutils_string_size(node->address);
			qsc_memutils_copy(output + spos, (uint8_t*)node->address, slen);
			spos += slen;
			output[spos] = '\n';
			++spos;
		}
		else
		{
			slen = qsc_stringutils_string_size(node->address);
			qsc_memutils_copy(output + spos, node->address, slen);
			spos += slen;
			output[spos] = '\n';
			++spos;
		}

		slen = qsc_stringutils_string_size(MPDC_ROOT_CERTIFICATE_HASH_PREFIX);
		qsc_memutils_copy(output + spos, MPDC_ROOT_CERTIFICATE_HASH_PREFIX, slen);
		spos += slen;
		qsc_intutils_bin_to_hex(node->chash, output + spos, MPDC_CERTIFICATE_HASH_SIZE);
		qsc_stringutils_to_uppercase(output + spos);
		slen = MPDC_CERTIFICATE_HASH_SIZE * 2;
		spos += slen;
		output[spos] = '\n';
		++spos;

		slen = qsc_stringutils_string_size(MPDC_CHILD_CERTIFICATE_SERIAL_PREFIX);
		qsc_memutils_copy(output + spos, MPDC_CHILD_CERTIFICATE_SERIAL_PREFIX, slen);
		spos += slen;
		qsc_intutils_bin_to_hex(node->serial, output + spos, MPDC_CERTIFICATE_SERIAL_SIZE);
		qsc_stringutils_to_uppercase(output + spos);
		slen = MPDC_CERTIFICATE_SERIAL_SIZE * 2;
		spos += slen;
		output[spos] = '\n';
		++spos;

		slen = qsc_stringutils_string_size(MPDC_CHILD_CERTIFICATE_DESIGNATION_PREFIX);
		qsc_memutils_copy(output + spos, MPDC_CHILD_CERTIFICATE_DESIGNATION_PREFIX, slen);
		spos += slen;
		spos += mpdc_certificate_designation_encode(output + spos, node->designation);
		output[spos] = '\n';
		++spos;

		slen = qsc_stringutils_string_size(MPDC_CHILD_CERTIFICATE_VALID_FROM_PREFIX);
		qsc_memutils_copy(output + spos, MPDC_CHILD_CERTIFICATE_VALID_FROM_PREFIX, slen);
		spos += slen;
		qsc_timestamp_seconds_to_datetime(node->expiration.from, dtm);
		slen = sizeof(dtm) - 1;
		qsc_memutils_copy(output + spos, dtm, slen);
		spos += slen;
		slen = qsc_stringutils_string_size(MPDC_CHILD_CERTIFICATE_EXPIRATION_TO_PREFIX);
		qsc_memutils_copy(output + spos, MPDC_CHILD_CERTIFICATE_EXPIRATION_TO_PREFIX, slen);
		spos += slen;
		qsc_timestamp_seconds_to_datetime(node->expiration.to, dtm);
		slen = sizeof(dtm) - 1;
		qsc_memutils_copy(output + spos, dtm, slen);
		spos += slen;
		output[spos] = '\n';
		++spos;
	}

	return spos;
}

void mpdc_topology_from_file(const char* fpath, mpdc_topology_list_state* list)
{
	MPDC_ASSERT(fpath != NULL);
	MPDC_ASSERT(list != NULL);

	uint8_t* lbuf;
	size_t flen;

	if (fpath != NULL && list != NULL)
	{
		if (qsc_fileutils_exists(fpath) == true)
		{
			flen = qsc_fileutils_get_size(fpath);

			if (flen > 0)
			{
				lbuf = (uint8_t*)qsc_memutils_malloc(flen);

				if (lbuf != NULL)
				{
					qsc_fileutils_copy_file_to_stream(fpath, (char*)lbuf, flen);
					mpdc_topology_list_deserialize(list, lbuf, flen);
					qsc_memutils_alloc_free(lbuf);
				}
			}
		}
	}
}

void mpdc_topology_to_file(const mpdc_topology_list_state* list, const char* fpath)
{
	MPDC_ASSERT(list != NULL);
	MPDC_ASSERT(fpath != NULL);

	uint8_t* pbuf;
	size_t flen;

	if (list != NULL && fpath != NULL)
	{
		flen = sizeof(uint32_t) + (list->count * MPDC_NETWORK_TOPOLOGY_NODE_SIZE);
		pbuf = (uint8_t*)qsc_memutils_malloc(flen);

		if (pbuf != NULL)
		{
			mpdc_topology_list_serialize(pbuf, list);
			qsc_fileutils_copy_stream_to_file(fpath, (const char*)pbuf, flen);
			qsc_memutils_alloc_free(pbuf);
		}
	}
}

#if defined(MPDC_DEBUG_MODE)
typedef struct topology_device_package
{
	mpdc_signature_keypair akp;
	mpdc_signature_keypair ckp;
	mpdc_signature_keypair dkp;
	mpdc_signature_keypair mkp;
	mpdc_signature_keypair rkp;
	mpdc_child_certificate acrt;
	mpdc_child_certificate ccrt;
	mpdc_child_certificate dcrt;
	mpdc_child_certificate mcrt;
	mpdc_root_certificate root;
	mpdc_topology_node_state ande;
	mpdc_topology_node_state and2;
	mpdc_topology_node_state and3;
	mpdc_topology_node_state and4;
	mpdc_topology_node_state and5;
	mpdc_topology_node_state and6;
	mpdc_topology_node_state and7;
	mpdc_topology_node_state and8;
	mpdc_topology_node_state cnde;
	mpdc_topology_node_state dnde;
	mpdc_topology_node_state mnde;
	mpdc_topology_list_state list;
} topology_device_package;

static void topology_load_child_node(mpdc_topology_list_state* list, mpdc_topology_node_state* node, const mpdc_child_certificate* ccert)
{
	uint8_t ipa[MPDC_CERTIFICATE_ADDRESS_SIZE] = { 192, 168, 1 };

	qsc_acp_generate(ipa + 3, 1);
	mpdc_topology_child_register(list, ccert, ipa);
	mpdc_topology_node_find(list, node, (const uint8_t*)ccert->serial);
}

static void topology_device_destroy(topology_device_package* spkg)
{
	mpdc_topology_list_dispose(&spkg->list);
}

static void topology_device_instantiate(topology_device_package* spkg)
{
	mpdc_certificate_expiration exp = { 0 };

	/* generate the root certificate */
	mpdc_certificate_signature_generate_keypair(&spkg->rkp);
	mpdc_certificate_expiration_set_days(&exp, 0, 30);
	mpdc_certificate_root_create(&spkg->root, spkg->rkp.pubkey, &exp, "XYZ/RDS-1:rds1.xyz.com");
	
	/* create the agent responder */
	mpdc_certificate_signature_generate_keypair(&spkg->akp);
	mpdc_certificate_expiration_set_days(&exp, 0, 100);
	mpdc_certificate_child_create(&spkg->acrt, spkg->akp.pubkey, &exp, "XYZ/Agent-1:agent1.xyz.com", mpdc_network_designation_agent);
	mpdc_certificate_root_sign(&spkg->acrt, &spkg->root, spkg->rkp.prikey);
	topology_load_child_node(&spkg->list, &spkg->ande, &spkg->acrt);

	/* agent copies for list test */
	mpdc_certificate_child_create(&spkg->acrt, spkg->akp.pubkey, &exp, "XYZ/Agent-2:agent2.xyz.com", mpdc_network_designation_agent);
	topology_load_child_node(&spkg->list, &spkg->and2, &spkg->acrt);
	mpdc_certificate_child_create(&spkg->acrt, spkg->akp.pubkey, &exp, "XYZ/Agent-3:agent3.xyz.com", mpdc_network_designation_agent);
	topology_load_child_node(&spkg->list, &spkg->and3, &spkg->acrt);
	mpdc_certificate_child_create(&spkg->acrt, spkg->akp.pubkey, &exp, "XYZ/Agent-4:agent4.xyz.com", mpdc_network_designation_agent);
	topology_load_child_node(&spkg->list, &spkg->and4, &spkg->acrt);
	mpdc_certificate_child_create(&spkg->acrt, spkg->akp.pubkey, &exp, "XYZ/Agent-5:agent5.xyz.com", mpdc_network_designation_agent);
	topology_load_child_node(&spkg->list, &spkg->and5, &spkg->acrt);
	mpdc_certificate_child_create(&spkg->acrt, spkg->akp.pubkey, &exp, "XYZ/Agent-6:agent6.xyz.com", mpdc_network_designation_agent);
	topology_load_child_node(&spkg->list, &spkg->and6, &spkg->acrt);
	mpdc_certificate_child_create(&spkg->acrt, spkg->akp.pubkey, &exp, "XYZ/Agent-7:agent7.xyz.com", mpdc_network_designation_agent);
	topology_load_child_node(&spkg->list, &spkg->and7, &spkg->acrt);
	mpdc_certificate_child_create(&spkg->acrt, spkg->akp.pubkey, &exp, "XYZ/Agent-8:agent8.xyz.com", mpdc_network_designation_agent);
	topology_load_child_node(&spkg->list, &spkg->and8, &spkg->acrt);

	/* create a client */
	mpdc_certificate_signature_generate_keypair(&spkg->ckp);
	mpdc_certificate_expiration_set_days(&exp, 0, 100);
	mpdc_certificate_child_create(&spkg->ccrt, spkg->ckp.pubkey, &exp, "XYZ/Client-1:client1.xyz.com", mpdc_network_designation_client);
	mpdc_certificate_root_sign(&spkg->ccrt, &spkg->root, spkg->rkp.prikey);
	topology_load_child_node(&spkg->list, &spkg->cnde, &spkg->ccrt);

	/* create the dla */
	mpdc_certificate_signature_generate_keypair(&spkg->dkp);
	mpdc_certificate_expiration_set_days(&exp, 0, 100);
	mpdc_certificate_child_create(&spkg->dcrt, spkg->dkp.pubkey, &exp, "XYZ/DLA-1:dla1.xyz.com", mpdc_network_designation_dla);
	mpdc_certificate_root_sign(&spkg->dcrt, &spkg->root, spkg->rkp.prikey);
	topology_load_child_node(&spkg->list, &spkg->dnde, &spkg->dcrt);

	/* create the server requestor */
	mpdc_certificate_signature_generate_keypair(&spkg->mkp);
	mpdc_certificate_expiration_set_days(&exp, 0, 100);
	mpdc_certificate_child_create(&spkg->mcrt, spkg->mkp.pubkey, &exp, "XYZ/MAS-1:mas1.xyz.com", mpdc_network_designation_mas);
	mpdc_certificate_root_sign(&spkg->mcrt, &spkg->root, spkg->rkp.prikey);
	topology_load_child_node(&spkg->list, &spkg->mnde, &spkg->mcrt);
}

static bool topology_find_test(topology_device_package* spkg)
{
	mpdc_topology_node_state tand = { 0 };
	mpdc_topology_node_state tmnd = { 0 };
	bool res;

	res = false;

	/* test find related functions */
	mpdc_topology_node_find(&spkg->list, &tand, spkg->ande.serial);

	if (mpdc_topology_nodes_are_equal(&tand, &spkg->ande) == true)
	{
		mpdc_topology_node_find_alias(&spkg->list, &tmnd, "mas1.xyz.com");

		if (mpdc_topology_nodes_are_equal(&tmnd, &spkg->mnde) == true)
		{
			mpdc_topology_node_find_issuer(&spkg->list, &tand, spkg->ande.issuer);

			if (mpdc_topology_nodes_are_equal(&tand, &spkg->ande) == true)
			{
				mpdc_topology_node_add_alias(&spkg->cnde, "client.xyz.com");

				if (qsc_stringutils_string_contains(spkg->cnde.issuer, "client.xyz.com") == true)
				{
					res = true;
				}
			}
		}
	}

	return res;
}

static bool topology_serialization_test(topology_device_package* spkg)
{
	mpdc_topology_list_state lstc = { 0 };
	mpdc_topology_node_state itma;
	mpdc_topology_node_state itmb;
	uint8_t* lbuf;
	size_t mlen;
	bool res;
	
	res = false;
	mlen = sizeof(uint32_t) + (spkg->list.count * MPDC_NETWORK_TOPOLOGY_NODE_SIZE);
	lbuf = (uint8_t*)qsc_memutils_malloc(mlen);

	if (lbuf != NULL)
	{
		mpdc_topology_list_serialize(lbuf, &spkg->list);
		mpdc_topology_list_initialize(&lstc);
		mpdc_topology_list_deserialize(&lstc, lbuf, mlen);
		qsc_memutils_alloc_free(lbuf);
		res = true;

		for (size_t i = 0; i < lstc.count; ++i)
		{
			if (mpdc_topology_list_item(&lstc, &itma, i) == true)
			{
				if (mpdc_topology_list_item(&spkg->list, &itmb, i) == true)
				{
					if (mpdc_topology_nodes_are_equal(&itma, &itmb) == false)
					{
						res = false;
						break;
					}				
				}
			}
		}

		if (res == true)
		{
			mpdc_topology_node_state ncpy = { 0 };
			uint8_t nser[MPDC_NETWORK_TOPOLOGY_NODE_SIZE] = { 0 };

			for (size_t i = 0; i < lstc.count; ++i)
			{
				if (mpdc_topology_list_item(&lstc, &itma, i) == true)
				{
					mpdc_topology_node_serialize(nser, &itma);
					mpdc_topology_node_deserialize(&ncpy, nser);

					if (mpdc_topology_nodes_are_equal(&itma, &ncpy) == false)
					{
						res = false;
						break;
					}
				}
			}
		}

		mpdc_topology_list_dispose(&lstc);
	}

	return res;
}

static bool topology_sorted_list_test(topology_device_package* spkg)
{
	mpdc_topology_list_state olst = { 0 };
	mpdc_topology_node_state itma;
	mpdc_topology_node_state itmb;
	size_t acnt;
	size_t ncnt;
	bool res;

	/* test the count */
	acnt = mpdc_topology_list_server_count(&spkg->list, mpdc_network_designation_agent);
	ncnt = mpdc_topology_ordered_server_list(&olst, &spkg->list, mpdc_network_designation_agent);

	res = (acnt == ncnt);

	if (res == true)
	{
		/* test the sort */
		for (size_t i = 0; i < olst.count - 1; ++i)
		{
			mpdc_topology_list_item(&olst, &itma, i);
			mpdc_topology_list_item(&olst, &itmb, i + 1);

			if (qsc_memutils_greater_than_le128(itma.serial, itmb.serial) == false)
			{
				res = false;
				break;
			}
		}

		mpdc_topology_list_dispose(&olst);
	}

	return res;
}

bool mpdc_topology_functions_test(void)
{
	topology_device_package spkg = { 0 };
	bool res;

	res = false;
	topology_device_instantiate(&spkg);

	/* test the find functions */
	if (topology_find_test(&spkg) == true)
	{
		/* test add, remove, and serialization functions */
		if (topology_serialization_test(&spkg) == true)
		{
			/* test sort and ordered list */
			if (topology_sorted_list_test(&spkg) == true)
			{
				res = true;
			}
		}
	}

	topology_device_destroy(&spkg);

	return res;
}
#endif
