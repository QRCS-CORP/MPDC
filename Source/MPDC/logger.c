#include "logger.h"
#include "resources.h"
#include "async.h"
#include "fileutils.h"
#include "folderutils.h"
#include "memutils.h"
#include "stringutils.h"
#include "timestamp.h"

static const char NLINE[2] = { 10, 0 };

void logger_default_path(char* path, size_t pathlen)
{
	assert(path != NULL);
	assert(pathlen != 0);

	if (path != NULL && pathlen != 0)
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
	assert(path != NULL);

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
	assert(path != NULL);

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
	assert(path != NULL);

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
	assert(path != NULL);

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
	assert(path != NULL);

	size_t len;

	len = 0;

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
	assert(path != NULL);

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
	assert(path != NULL);
	assert(message != NULL);
	assert(msglen != 0);

	size_t len;

	len = 0;

	if (path != NULL && message != NULL && msglen != 0)
	{
		if (qsc_fileutils_exists(path) == true)
		{
			qsc_mutex mtx;
				
			mtx = qsc_async_mutex_lock_ex();

			if (qsc_fileutils_append_to_file(path, message, msglen) == true)
			{
				qsc_fileutils_append_to_file(path, NLINE, 1);
				len = msglen + 1;
			}

			qsc_async_mutex_unlock_ex(mtx);
		}
	}

	return len;
}

size_t mpdc_logger_write_decorated_message(const char* path, mpdc_application_messages msgtype, const char* message, size_t msglen)
{
	assert(path != NULL);

	size_t idx;
	size_t len;

	len = 0;

	if (path != NULL)
	{
		if (qsc_fileutils_exists(path) == true)
		{
			char lmsg[MPDC_STORAGE_MESSAGE_MAX] = { 0 };

			idx = (size_t)msgtype;
			qsc_stringutils_copy_string(lmsg, sizeof(lmsg), MPDC_APPLICATION_MESSAGE_STRINGS[idx]);

			if (message != NULL && msglen != 0)
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
	assert(path != NULL);

	size_t len;

	len = 0;

	if (path != NULL)
	{
		char lmsg[MPDC_STORAGE_MESSAGE_MAX] = { 0 };
		size_t idx;
		
		idx = (size_t)msgtype;
		len = mpdc_logger_time_stamp(lmsg, sizeof(lmsg));
		qsc_stringutils_concat_strings(lmsg, sizeof(lmsg), MPDC_APPLICATION_MESSAGE_STRINGS[idx]);

		if (message != NULL && msglen != 0)
		{
			qsc_stringutils_concat_strings(lmsg, sizeof(lmsg), message);
		}

		len += mpdc_logger_write_message(path, lmsg, qsc_stringutils_string_size(lmsg));
	}

	return len;
}

size_t mpdc_logger_write_time_stamped_message(const char* path, const char* message, size_t msglen)
{
	assert(path != NULL);

	size_t len;

	len = 0;

	if (path != NULL)
	{
		char lmsg[MPDC_STORAGE_MESSAGE_MAX] = { 0 };

		len = mpdc_logger_time_stamp(lmsg, sizeof(lmsg));

		if (len > 0)
		{
			qsc_stringutils_concat_strings(lmsg, sizeof(lmsg), message);
		}

		if (message != NULL && msglen != 0)
		{
			qsc_stringutils_concat_strings(lmsg, sizeof(lmsg), message);
		}

		len = mpdc_logger_write_message(path, lmsg, qsc_stringutils_string_size(lmsg));
	}

	return len;
}

size_t mpdc_logger_read_all(const char* path, char* output, size_t outlen)
{
	assert(path != NULL);
	assert(output != NULL);
	assert(outlen != 0);

	size_t len;

	len = 0;

	if (path != NULL && output != NULL && outlen != 0)
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
	assert(path != NULL);
	assert(output != NULL);
	assert(outlen != 0);

	int64_t len;

	len = 0;

	if (path != NULL && output != NULL && outlen != 0)
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
	assert(output != NULL);
	assert(outlen != 0);

	size_t len;

	len = 0;

	if (output != NULL && outlen != 0)
	{
		char tsc[QSC_TIMESTAMP_STRING_SIZE] = { 0 };

		qsc_timestamp_current_datetime(tsc);
		len = qsc_stringutils_string_size(tsc);

		if (len > 0)
		{
			len = len <= outlen ? len : outlen;
			qsc_memutils_copy(output, tsc, len);
		}
	}

	return len;
}
