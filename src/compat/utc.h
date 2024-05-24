/*
 * SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2011-2013 Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 */

#ifndef BABELTRACE_COMPAT_UTC_H
#define BABELTRACE_COMPAT_UTC_H

#include <time.h>

/* If set, use GNU or BSD timegm(3) */
#if defined(_BSD_SOURCE) || defined(_SVID_SOURCE)

static inline
time_t bt_timegm(struct tm *tm)
{
	return timegm(tm);
}

#elif defined(__MINGW32__)

static inline
time_t bt_timegm(struct tm *tm)
{
	return _mkgmtime(tm);
}

#else

#include <errno.h>

/*
 * This is a simple implementation of timegm() it just turns the "struct tm" into
 * a GMT time_t. It does not normalize any of the fields of the "struct tm", nor
 * does it set tm_wday or tm_yday.
 */

static inline
int bt_leapyear(int year)
{
    return ((year % 4) == 0 && ((year % 100) != 0 || (year % 400) == 0));
}

static inline
time_t bt_timegm(struct tm *tm)
{
	int year, month, total_days;

	int monthlen[2][12] = {
		/* Days per month for a regular year */
		{ 31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31 },
		/* Days per month for a leap year */
		{ 31, 29, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31 },
	};

	if ((tm->tm_mon >= 12) ||
			(tm->tm_mday >= 32) ||
			(tm->tm_hour >= 24) ||
			(tm->tm_min >= 60) ||
			(tm->tm_sec >= 61)) {
		errno = EOVERFLOW;
		return (time_t) -1;
	}

	/* Add 365 days for each year since 1970 */
	total_days = 365 * (tm->tm_year - 70);

	/* Add one day for each leap year since 1970 */
	for (year = 70; year < tm->tm_year; year++) {
		if (bt_leapyear(1900 + year)) {
			total_days++;
		}
	}

	/* Add days for each remaining month */
	for (month = 0; month < tm->tm_mon; month++) {
		total_days += monthlen[bt_leapyear(1900 + year)][month];
	}

	/* Add remaining days */
	total_days += tm->tm_mday - 1;

	return ((((total_days * 24) + tm->tm_hour) * 60 + tm->tm_min) * 60 + tm->tm_sec);
}

#endif

#endif /* BABELTRACE_COMPAT_UTC_H */
