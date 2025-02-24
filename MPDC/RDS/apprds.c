#include "apprds.h"
#include "../MPDC/rds.h"
#if defined(MPDC_DEBUG_TESTS_RUN)
#	include "../../QSC/QSC/collection.h"
#	include "../../QSC/QSC/consoleutils.h"
#	include "../MPDC/certificate.h"
#	include "../MPDC/mpdc.h"
#endif

int main(void)
{
	mpdc_rds_start_server();

	return 0;
}
