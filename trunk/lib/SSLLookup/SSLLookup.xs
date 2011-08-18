#include "EXTERN.h"
#include "perl.h"
#include "XSUB.h"

#include "mod_perl.h"
#include "modperl_xs_typedefs.h"

typedef request_rec * Apache__SSLLookup;

APR_DECLARE_OPTIONAL_FN(char *, ssl_var_lookup,
                        (apr_pool_t *, server_rec *,
                         conn_rec *, request_rec *,
                         char *));

APR_DECLARE_OPTIONAL_FN(int, ssl_is_https, (conn_rec *));

APR_DECLARE_OPTIONAL_FN(const char *, ssl_ext_lookup,
                        (apr_pool_t *p, conn_rec *c, int peer,
                         const char *oidnum));

static APR_OPTIONAL_FN_TYPE(ssl_var_lookup) *perl_ssl_lookup = NULL;
static APR_OPTIONAL_FN_TYPE(ssl_is_https)   *perl_is_https   = NULL;
static APR_OPTIONAL_FN_TYPE(ssl_ext_lookup) *perl_ext_lookup = NULL;

static int get_ssl_functions(apr_pool_t *p, apr_pool_t *plog,
                             apr_pool_t *ptemp, server_rec *s)
{

  perl_ssl_lookup = APR_RETRIEVE_OPTIONAL_FN(ssl_var_lookup);
  perl_is_https   = APR_RETRIEVE_OPTIONAL_FN(ssl_is_https);
  perl_ext_lookup = APR_RETRIEVE_OPTIONAL_FN(ssl_ext_lookup);

  return OK;
}

static const char * const aszPre[] = { "mod_ssl.c", NULL };

MODULE = Apache::SSLLookup     PACKAGE = Apache::SSLLookup

PROTOTYPES: DISABLE

  BOOT:
    ap_hook_post_config(get_ssl_functions, aszPre, NULL, APR_HOOK_MIDDLE);

SV *
new(self, r)
  SV * self
  Apache2::RequestRec r

  INIT:
    MP_dTHX;      /* interpreter selection */

    SV *obj = newSV(0);
    HV *hv  = newHV();

    self = self;  /* satisfy warnings */

  CODE:
    /* bless { _r => $r }, $class */
    hv_store(hv, "_r", 2,
             modperl_ptr2obj(aTHX_ "Apache2::RequestRec", r), FALSE);
    obj = newRV_noinc((SV *)hv);
    sv_bless(obj, gv_stashpv("Apache::SSLLookup", TRUE));

    RETVAL = obj;

  OUTPUT:
    RETVAL

int
is_https(r)
  Apache::SSLLookup r

  CODE:
    RETVAL = 0;

    if (perl_is_https) {
      MP_TRACE_a(MP_FUNC, "seeing if request for %s is under SSL", r->uri);

      RETVAL = perl_is_https(r->connection);
    }

  OUTPUT:
    RETVAL

char *
ssl_lookup(r, var)
  Apache::SSLLookup r
  char *var

  CODE:
    RETVAL = Nullch;

    if (perl_ssl_lookup) {
      MP_TRACE_a(MP_FUNC, "looking for SSL variable '%s'", var);

      RETVAL = perl_ssl_lookup(r->pool, r->server, r->connection, r, var);
    }

  OUTPUT:
    RETVAL

const char *
ext_lookup(r, oid, peer = 0)
  Apache::SSLLookup r
  const char *oid
  int peer

  CODE:
    RETVAL = Nullch;

    if (perl_ext_lookup) {
      MP_TRACE_a(MP_FUNC, "retrieving SSL certificate '%s' from the %s",
                          oid, peer ? "client" : "server");

      RETVAL = perl_ext_lookup(r->pool, r->connection, peer, oid);
    }

  OUTPUT:
    RETVAL

BOOT:
    av_push(perl_get_av("Apache::SSLLookup::ISA",TRUE), newSVpv("Apache2::RequestRec",19));
