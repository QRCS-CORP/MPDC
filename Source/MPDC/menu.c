#include "menu.h"
#include "logger.h"
#include "resources.h"
#include "consoleutils.h"
#include "fileutils.h"
#include "folderutils.h"
#include "stringutils.h"

const char* mpdc_menu_get_prompt(mpdc_console_modes mode)
{
	return MPDC_APPLICATION_MODE_STRINGS[(size_t)mode];
}

void mpdc_menu_print_error(mpdc_protocol_errors error, mpdc_console_modes mode, const char* host)
{
	MPDC_ASSERT(host != NULL);

	const char* msg;

	if (host != NULL)
	{
		msg = mpdc_protocol_error_to_string(error);

		if (msg != NULL)
		{
			mpdc_menu_print_prompt(mode, host);
			qsc_consoleutils_print_line(msg);
		}
	}
}

void mpdc_menu_print_message(const char* message, mpdc_console_modes mode, const char* host)
{
	MPDC_ASSERT(message != NULL);
	MPDC_ASSERT(host != NULL);

	if (message != NULL && host != NULL)
	{
		mpdc_menu_print_prompt(mode, host);

		if (qsc_stringutils_string_size(message) > 0)
		{
			qsc_consoleutils_print_line(message);
		}
	}
}

bool mpdc_menu_print_message_confirm(const char* message, mpdc_console_modes mode, const char* host)
{
	MPDC_ASSERT(message != NULL);
	MPDC_ASSERT(host != NULL);

	char ans;
	bool res;

	res = false;

	if (message != NULL && host != NULL)
	{
		mpdc_menu_print_message(message, mode, host);
		mpdc_menu_print_prompt(mode, host);
		ans = qsc_consoleutils_get_char();

		if (ans == 'y' || ans == 'Y')
		{
			res = true;
		}
	}

	return res;
}

void mpdc_menu_print_prompt_text(const char* message, mpdc_console_modes mode, const char* host)
{
	MPDC_ASSERT(message != NULL);
	MPDC_ASSERT(host != NULL);

	if (message != NULL && host != NULL)
	{
		mpdc_menu_print_prompt(mode, host);

		if (qsc_stringutils_string_size(message) > 0)
		{
			qsc_consoleutils_print_safe(message);
		}
	}
}

void mpdc_menu_print_text(const char* message)
{
	MPDC_ASSERT(message != NULL);

	if (message != NULL)
	{
		if (qsc_stringutils_string_size(message) > 0)
		{
			qsc_consoleutils_print_safe(message);
		}
	}
}

void mpdc_menu_print_text_line(const char* message)
{
	MPDC_ASSERT(message != NULL);

	if (message != NULL)
	{
		if (qsc_stringutils_string_size(message) > 0)
		{
			qsc_consoleutils_print_line(message);
		}
	}
}

bool mpdc_menu_print_predefined_message_confirm(mpdc_application_messages msgnum, mpdc_console_modes mode, const char* host)
{
	MPDC_ASSERT(host != NULL);

	char ans[8] = { 0 };
	bool res;

	res = false;

	if (host != NULL)
	{
		mpdc_menu_print_predefined_message(msgnum, mode, host);
		mpdc_menu_print_prompt(mode, host);

		if (qsc_consoleutils_get_line(ans, sizeof(ans)) > 0)
		{
			if (ans[0] == 'y' || ans[0] == 'Y')
			{
				res = true;
			}
		}
	}

	return res;
}

void mpdc_menu_print_predefined_message(mpdc_application_messages msgnum, mpdc_console_modes mode, const char* host)
{
	MPDC_ASSERT(host != NULL);

	if (host != NULL)
	{
		mpdc_menu_print_prompt(mode, host);
		qsc_consoleutils_print_line(MPDC_APPLICATION_MESSAGE_STRINGS[(size_t)msgnum]);
	}
}

void mpdc_menu_print_predefined_text(mpdc_application_messages msgnum, mpdc_console_modes mode, const char* host)
{
	MPDC_ASSERT(host != NULL);

	if (host != NULL)
	{
		mpdc_menu_print_prompt(mode, host);
		qsc_consoleutils_print_safe(MPDC_APPLICATION_MESSAGE_STRINGS[(size_t)msgnum]);
	}
}

void mpdc_menu_print_prompt(mpdc_console_modes mode, const char* host)
{
	MPDC_ASSERT(host != NULL);

	char pmt[MPDC_STORAGE_PROMPT_MAX + 1] = { 0 };

	if (host != NULL)
	{
		qsc_stringutils_concat_and_copy(pmt, sizeof(pmt), host, MPDC_APPLICATION_MODE_STRINGS[(size_t)mode]);
		qsc_consoleutils_print_safe(pmt);
	}
}

void mpdc_menu_print_prompt_empty(void)
{
	qsc_consoleutils_print_safe("mpdc> ");
}
