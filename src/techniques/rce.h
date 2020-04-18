#ifndef __RCE_H__
#define __RCE_H__

#include "techniques/auth-log-poison.h"
#include "techniques/datawrap.h"
#include "techniques/php-input.h"

enum {
	auth_log_tech,
	php_input_tech,
	datawrap_tech,
	proc_environ_tech
};

#endif
