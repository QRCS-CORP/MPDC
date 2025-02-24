#include "appagt.h"
#include "../MPDC/agent.h"
#include "../MPDC/certificate.h"
#include "../MPDC/mpdc.h"
#if defined(MPDC_DEBUG_TESTS_RUN)
#	include "../../QSC/QSC/consoleutils.h"
#	include "../MPDC/network.h"
#	include "../MPDC/topology.h"
#endif

int main(void)
{
	int32_t ret;

#if defined(MPDC_DEBUG_TESTS_RUN)

	ret = -1;

	if (mpdc_network_protocols_test() == true)
	{
		if (mpdc_certificate_functions_test() == true)
		{
			if (mpdc_topology_functions_test() == true)
			{
				ret = mpdc_agent_start_server();
			}
			else
			{
				qsc_consoleutils_print_line("Failed the topology functions tests.");
			}
		}
		else
		{
			qsc_consoleutils_print_line("Failed the certificate functions tests.");
		}
	}
	else
	{
		qsc_consoleutils_print_line("Failed the network exchange tests.");
	}

	if (ret == -1)
	{
		qsc_consoleutils_print_line("Agent failed the debug test. Press any key to close..");
		qsc_consoleutils_get_wait();
	}

#else

	ret = mpdc_agent_start_server();

#endif

	return ret;
}
