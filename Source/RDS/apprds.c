#include "apprds.h"
#include "rds.h"
#if defined(MPDC_DEBUG_TESTS_RUN)
#	include "collection.h"
#	include "consoleutils.h"
#	include "certificate.h"
#	include "mpdc.h"
#endif

int main(void)
{
	mpdc_rds_start_server();

	return 0;
}
