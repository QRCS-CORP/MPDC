#include "appclt.h"
#include "mpdc.h"
#include "client.h"

int main(void)
{
	int32_t ret;

	ret = mpdc_client_start_server();

	return ret;
}
