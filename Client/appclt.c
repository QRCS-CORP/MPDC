#include "appclt.h"
#include "../MPDC/mpdc.h"
#include "../MPDC/client.h"

int main(void)
{
	int32_t ret;

	ret = mpdc_client_start_server();

	return ret;
}
