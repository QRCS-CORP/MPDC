#include "appmas.h"
#include "mas.h"

int main(void)
{
	int32_t ret;

	ret = mpdc_mas_start_server();

	return ret;
}
