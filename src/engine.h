#ifndef ENGINE_H
#define ENGINE_H

#include "sscep.h"

#ifdef WIN32
#define CAPI_CMD_STORE_NAME		(ENGINE_CMD_BASE + 12) //this is the basic command to change the storename
#define CAPI_CMD_STORE_FLAGS	(ENGINE_CMD_BASE + 13) //this is used to set the storelocation
#endif

ENGINE *scep_engine_init(ENGINE *e);
ENGINE *scep_engine_load_dynamic(ENGINE *e);
void sscep_engine_read_key(EVP_PKEY **key, char *id, ENGINE *e);
void sscep_engine_read_key_old(EVP_PKEY **key, char *id, ENGINE *e);
void sscep_engine_read_key_new(EVP_PKEY **key, char *id, ENGINE *e);
void sscep_engine_report_error(void);

#ifdef WIN32
void sscep_engine_read_key_capi(EVP_PKEY **key, char *id, ENGINE *e, char *storename);
#endif
#endif /* ENGINE_H */
