#include "trust.h"

void mpdc_trust_clear(mpdc_device_trust* device)
{
	assert(device != NULL);

	if (device != NULL)
	{
		qsc_memutils_clear(device->address, MPDC_DLA_IP_MAX);
		qsc_memutils_clear(device->domain, MPDC_NETWORK_DOMAIN_NAME_MAX_SIZE);
		qsc_memutils_clear(device->name, MPDC_AGENT_NAME_MAX_SIZE);
		device->dtrust = 0;
		device->bandwidth = 0;
		device->isipv6 = false;
		device->local = false;
	}
}

void mpdc_trust_deserialize(mpdc_device_trust* device, const uint8_t* input)
{
	assert(device != NULL);
	assert(input != NULL);

	size_t len;
	size_t pos;

	// TODO: check this
	if (input != NULL && device != NULL)
	{
		pos = 0;
		len = MPDC_DLA_IP_MAX;
		qsc_memutils_copy(device->address, input, len);
		pos += len;
		len = MPDC_NETWORK_DOMAIN_NAME_MAX_SIZE;
		qsc_memutils_copy(device->address, input + pos, len);
		pos += len;
		len = MPDC_AGENT_NAME_MAX_SIZE;
		qsc_memutils_copy(device->name, input + pos, len);
		pos += len;
		len = sizeof(uint64_t);
		device->dtrust = qsc_intutils_le8to64(input + pos);
		pos += len;
		len = sizeof(uint32_t);
		device->bandwidth = qsc_intutils_le8to32(input + pos);
		pos += len;
		device->isipv6 = (bool)input[pos];
		++pos;
		device->local = (bool)input[pos];
	}
}

void mpdc_trust_serialize(uint8_t* output, size_t outlen, const mpdc_device_trust* device)
{
	assert(output != NULL);
	assert(outlen != 0);
	assert(device != NULL);

	if (device != NULL && output != NULL)
	{
		const size_t PLEN = MPDC_DLA_IP_MAX +
			MPDC_NETWORK_DOMAIN_NAME_MAX_SIZE +
			MPDC_AGENT_NAME_MAX_SIZE +
			sizeof(uint64_t) + sizeof(bool) + sizeof(bool);
		size_t len;
		size_t pos;

		if (outlen >= PLEN)
		{
			pos = 0;
			len = MPDC_DLA_IP_MAX;
			qsc_memutils_copy(output, device->address, len);
			pos += len;
			len = MPDC_NETWORK_DOMAIN_NAME_MAX_SIZE;
			qsc_memutils_copy(output + pos, device->address, len);
			pos += len;
			len = MPDC_AGENT_NAME_MAX_SIZE;
			qsc_memutils_copy(output + pos, device->name, len);
			pos += len;
			len = sizeof(uint64_t);
			qsc_intutils_le64to8(output + pos, device->dtrust);
			pos += len;
			len = sizeof(uint32_t);
			qsc_intutils_le32to8(output + pos, device->bandwidth);
			pos += len;
			output[pos] = (uint8_t)device->isipv6;
			++pos;
			output[pos] = (uint8_t)device->local;
		}
	}
}
