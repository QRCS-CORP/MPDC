#include "appdla.h"
#include "../MPDC/dla.h"

int main(void)
{
	int32_t ret;

	ret = mpdc_dla_start_server();

	return ret;
}
