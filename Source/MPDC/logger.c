#include "logger.h"
#include "resources.h"
#include "async.h"
#include "fileutils.h"
#include "folderutils.h"
#include "memutils.h"
#include "stringutils.h"
#include "timestamp.h"

static const char NLINE[2U] = { 10U, 0U };

void logger_default_path(char* path, size_t pathlen)
{
	MPDC_ASSERT(path != NULL);
	MPDC_ASSERT(pathlen != 0U);

	if (path != NULL && pathlen != 0U)
	{
		bool res;

		qsc_folderutils_get_directory(qsc_folderutils_directories_user_documents, path);
		qsc_folderutils_append_delimiter(path);
		qsc_stringutils_concat_strings(path, pathlen, MPDC_LOGGER_PATH);
		res = qsc_folderutils_directory_exists(path);

		if (res == false)
		{
			res = qsc_folderutils_create_directory(path);
		}

		if (res == true)
		{
			qsc_folderutils_append_delimiter(path);
			qsc_stringutils_concat_strings(path, pathlen, MPDC_LOGGER_FILE);
		}
	}
}

void mpdc_logger_initialize(const char* path)
{
	MPDC_ASSERT(path != NULL);

	if (path != NULL)
	{
		if (qsc_fileutils_exists(path) == false)
		{
			mpdc_logger_reset(path);
		}
	}
}

bool mpdc_logger_dispose(const char* path)
{
	MPDC_ASSERT(path != NULL);

	bool res;

	res = false;

	if (path != NULL)
	{
		res = qsc_fileutils_exists(path);

		if (res == true)
		{
			res = qsc_fileutils_delete(path);
		}
	}

	return res;
}

bool mpdc_logger_erase_all(const char* path)
{
	MPDC_ASSERT(path != NULL);

	bool res;

	res = false;

	if (path != NULL)
	{
		res = qsc_fileutils_exists(path);

		if (res == true)
		{
			qsc_fileutils_erase(path);
		}
	}

	return res;
}

bool mpdc_logger_exists(const char* path)
{
	MPDC_ASSERT(path != NULL);

	bool res;

	res = false;

	if (path != NULL)
	{
		if (qsc_stringutils_is_empty(path) == false)
		{
			res = qsc_fileutils_exists(path);
		}
	}

	return res;
}

size_t mpdc_logger_get_size(const char* path)
{
	MPDC_ASSERT(path != NULL);

	size_t len;

	len = 0U;

	if (path != NULL)
	{
		if (qsc_fileutils_exists(path) == true)
		{
			len = qsc_fileutils_get_size(path);
		}
	}

	return len;
}

void mpdc_logger_reset(const char* path)
{
	MPDC_ASSERT(path != NULL);

	if (path != NULL)
	{
		if (mpdc_logger_exists(path) == true)
		{
			qsc_fileutils_erase(path);
		}
		else
		{
			qsc_fileutils_create(path);
		}
	}
}

size_t mpdc_logger_write_message(const char* path, const char* message, size_t msglen)
{
	MPDC_ASSERT(path != NULL);
	MPDC_ASSERT(message != NULL);
	MPDC_ASSERT(msglen != 0U);

	size_t len;

	len = 0U;

	if (path != NULL && message != NULL && msglen != 0U)
	{
		if (qsc_fileutils_exists(path) == true)
		{
			qsc_mutex mtx;
				
			mtx = qsc_async_mutex_lock_ex();

			if (qsc_fileutils_append_to_file(path, message, msglen) == true)
			{
				qsc_fileutils_append_to_file(path, NLINE, 1U);
				len = msglen + 1;
			}

			qsc_async_mutex_unlock_ex(mtx);
		}
	}

	return len;
}

size_t mpdc_logger_write_decorated_message(const char* path, mpdc_application_messages msgtype, const char* message, size_t msglen)
{
	MPDC_ASSERT(path != NULL);

	size_t idx;
	size_t len;

	len = 0U;

	if (path != NULL)
	{
		if (qsc_fileutils_exists(path) == true)
		{
			char lmsg[MPDC_STORAGE_MESSAGE_MAX] = { 0 };

			idx = (size_t)msgtype;
			qsc_stringutils_copy_string(lmsg, sizeof(lmsg), MPDC_APPLICATION_MESSAGE_STRINGS[idx]);

			if (message != NULL && msglen != 0U)
			{
				qsc_stringutils_concat_strings(lmsg, sizeof(lmsg), message);
			}

			len = mpdc_logger_write_message(path, lmsg, qsc_stringutils_string_size(lmsg));
		}
	}

	return len;
}

size_t mpdc_logger_write_decorated_time_stamped_message(const char* path, mpdc_application_messages msgtype, const char* message, size_t msglen)
{
	MPDC_ASSERT(path != NULL);

	size_t len;

	len = 0U;

	if (path != NULL)
	{
		char lmsg[MPDC_STORAGE_MESSAGE_MAX] = { 0 };
		size_t idx;
		
		idx = (size_t)msgtype;
		len = mpdc_logger_time_stamp(lmsg, sizeof(lmsg));
		qsc_stringutils_concat_strings(lmsg, sizeof(lmsg), MPDC_APPLICATION_MESSAGE_STRINGS[idx]);

		if (message != NULL && msglen != 0U)
		{
			qsc_stringutils_concat_strings(lmsg, sizeof(lmsg), message);
		}

		len += mpdc_logger_write_message(path, lmsg, qsc_stringutils_string_size(lmsg));
	}

	return len;
}

size_t mpdc_logger_write_time_stamped_message(const char* path, const char* message, size_t msglen)
{
	MPDC_ASSERT(path != NULL);

	size_t len;

	len = 0U;

	if (path != NULL)
	{
		char lmsg[MPDC_STORAGE_MESSAGE_MAX] = { 0 };

		len = mpdc_logger_time_stamp(lmsg, sizeof(lmsg));

		if (len > 0U)
		{
			qsc_stringutils_concat_strings(lmsg, sizeof(lmsg), message);
		}

		if (message != NULL && msglen != 0U)
		{
			qsc_stringutils_concat_strings(lmsg, sizeof(lmsg), message);
		}

		len = mpdc_logger_write_message(path, lmsg, qsc_stringutils_string_size(lmsg));
	}

	return len;
}

size_t mpdc_logger_read_all(const char* path, char* output, size_t outlen)
{
	MPDC_ASSERT(path != NULL);
	MPDC_ASSERT(output != NULL);
	MPDC_ASSERT(outlen != 0U);

	size_t len;

	len = 0U;

	if (path != NULL && output != NULL && outlen != 0U)
	{
		if (qsc_fileutils_exists(path) == true)
		{
			qsc_mutex mtx;

			mtx = qsc_async_mutex_lock_ex();
			len = qsc_fileutils_copy_file_to_stream(path, output, outlen);
			qsc_async_mutex_unlock_ex(mtx);
		}
	}

	return len;
}

int64_t mpdc_logger_read_line(const char* path, char* output, size_t outlen, size_t linenum)
{
	MPDC_ASSERT(path != NULL);
	MPDC_ASSERT(output != NULL);
	MPDC_ASSERT(outlen != 0U);

	int64_t len;

	len = 0;

	if (path != NULL && output != NULL && outlen != 0U)
	{
		if (qsc_fileutils_exists(path) == true)
		{
			qsc_mutex mtx;

			mtx = qsc_async_mutex_lock_ex();
			len = qsc_fileutils_read_line(path, output, outlen, linenum);
			qsc_async_mutex_unlock_ex(mtx);
		}
	}

	return len;
}

size_t mpdc_logger_time_stamp(char* output, size_t outlen)
{
	MPDC_ASSERT(output != NULL);
	MPDC_ASSERT(outlen != 0U);

	size_t len;

	len = 0U;

	if (output != NULL && outlen != 0U)
	{
		char tsc[QSC_TIMESTAMP_STRING_SIZE] = { 0 };

		qsc_timestamp_current_datetime(tsc);
		len = qsc_stringutils_string_size(tsc);

		if (len > 0U)
		{
			len = len <= outlen ? len : outlen;
			qsc_memutils_copy(output, tsc, len);
		}
	}

	return len;
}
