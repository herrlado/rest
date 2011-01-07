#ifndef PHP_REST_H
#define PHP_REST_H

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "php.h"
#include "php_ini.h"
#include "php_globals.h"
#include "zend_API.h"
#include "zend_exceptions.h"

#include "ext/json/php_json.h"
#include "ext/pcre/php_pcre.h"
#include "ext/standard/info.h"
#include "ext/standard/url.h"
#include "ext/standard/php_string.h"
#include "ext/standard/php_smart_str.h"
#include "ext/standard/php_array.h"
#include "ext/standard/php_http.h"

extern zend_module_entry rest_module_entry;
#define phpext_rest_ptr &rest_module_entry

extern void rest_url_append_uri(char *uri, HashTable *args, smart_str *url, zend_bool encode TSRMLS_DC);

extern zend_class_entry *rest_route_exception;
extern zend_class_entry *rest_unsupported_method_exception;
extern zend_class_entry *restresponse_class_entry;

#ifdef PHP_WIN32
#	define PHP_REST_API __declspec(dllexport)
#elif defined(__GNUC__) && __GNUC__ >= 4
#	define PHP_REST_API __attribute__ ((visibility("default")))
#else
#	define PHP_REST_API
#endif

#ifdef ZTS
#include "TSRM.h"
#endif

PHP_MINIT_FUNCTION(rest);
PHP_MSHUTDOWN_FUNCTION(rest);
PHP_RINIT_FUNCTION(rest);
PHP_RSHUTDOWN_FUNCTION(rest);
PHP_MINFO_FUNCTION(rest);

/** RestClient class methods */
PHP_METHOD(RestClient, __construct);

PHP_METHOD(RestClient, skipSSLCheck);
PHP_METHOD(RestClient, setDebugMode);
PHP_METHOD(RestClient, setRequestEncoding);

PHP_METHOD(RestClient, setUriParams);
PHP_METHOD(RestClient, addUriParam);
PHP_METHOD(RestClient, removeUriParam);

PHP_METHOD(RestClient, setQueryParams);
PHP_METHOD(RestClient, addQueryParam);
PHP_METHOD(RestClient, removeQueryParam);

PHP_METHOD(RestClient, setPostVars);
PHP_METHOD(RestClient, addPostVar);
PHP_METHOD(RestClient, removePostVar);

PHP_METHOD(RestClient, setHeaders);
PHP_METHOD(RestClient, addHeader);
PHP_METHOD(RestClient, removeHeader);

PHP_METHOD(RestClient, setAuthData);
PHP_METHOD(RestClient, setProxyData);

PHP_METHOD(RestClient, fetch);
PHP_METHOD(RestClient, head);
PHP_METHOD(RestClient, options);
PHP_METHOD(RestClient, get);
PHP_METHOD(RestClient, post);
PHP_METHOD(RestClient, put);
PHP_METHOD(RestClient, delete);

/** RestServer class methods */
PHP_METHOD(RestServer, __construct);
PHP_METHOD(RestServer, addRoute);
PHP_METHOD(RestServer, handle);
PHP_METHOD(RestServer, setCallbackHandler);
PHP_METHOD(RestServer, setErrorHandler);
PHP_METHOD(RestServer, handleRequestUri);
PHP_METHOD(RestServer, handleQueryParam);

#if (PHP_MAJOR_VERSION == 5 && PHP_MINOR_VERSION > 2) || PHP_MAJOR_VERSION > 5
#   define REST_ARGINFO
#else
#   define REST_ARGINFO static
#endif

#define METHOD_HEAD         "HEAD"
#define METHOD_OPTIONS      "OPTIONS"
#define METHOD_GET          "GET"
#define METHOD_POST         "POST"
#define METHOD_PUT          "PUT"
#define METHOD_DELETE       "DELETE"

#define IS_METHOD(_method1, _method2) !strcmp(_method1, _method2)
#define IS_HEAD(_method)    IS_METHOD(_method, METHOD_HEAD)
#define IS_GET(_method)     IS_METHOD(_method, METHOD_GET)
#define IS_POST(_method)    IS_METHOD(_method, METHOD_POST)
#define IS_PUT(_method)     IS_METHOD(_method, METHOD_PUT)
#define IS_DELETE(_method)  IS_METHOD(_method, METHOD_DELETE)
#define IS_OPTIONS(_method) IS_METHOD(_method, METHOD_OPTIONS)

#define REST_ROUTE_PATTERN_DEFAULT      "(?P<%s>(?:/?[^/]*))"
#define REST_ROUTE_PATTERN_TOKENS       "(?:/.+)+"
#define REST_ROUTE_PATTERN_ALPHA_TOKENS "(?:/[-\\w]+)+"
#define REST_ROUTE_PATTERN_DIGIT_TOKENS "(?:/\\d+)+"

#define RETURN_THIS() \
    zval_ptr_dtor(return_value_ptr); \
    zval_add_ref(&this_ptr); \
    *return_value_ptr = this_ptr;

#define PROP(_obj, _name, _value) \
    zend_hash_find(Z_OBJPROP_P(_obj), _name, strlen(_name) + 1, (void **)&_value)

#define GET_PROP(_obj, _name, _value) \
    PROP(_obj, _name, _value) == SUCCESS

#define ARRVAL_P(_arr, _name, _value) \
    zend_hash_find(Z_ARRVAL_P(_arr), _name, strlen(_name) + 1, (void **)&_value)

#define ARRVAL_PP(_arr, _name, _value) \
    zend_hash_find(Z_ARRVAL_PP(_arr), _name, strlen(_name) + 1, (void **)&_value)

#define GET_ARRVAL(_arr, _name, _value) \
    ARRVAL_PP(_arr, _name, _value) == SUCCESS

#define HTVAL(_arr, _name, _value) \
    zend_hash_find(_arr, _name, strlen(_name) + 1, (void **)&_value)

#define GET_HTVAL(_arr, _name, _value) \
    HTVAL(_arr, _name, _value) == SUCCESS

/* 
  	Declare any global variables you may need between the BEGIN
	and END macros here:     

ZEND_BEGIN_MODULE_GLOBALS(rest)
	long  global_value;
	char *global_string;
ZEND_END_MODULE_GLOBALS(rest)
*/

/* In every utility function you add that needs to use variables 
   in php_rest_globals, call TSRMLS_FETCH(); after declaring other 
   variables used by that function, or better yet, pass in TSRMLS_CC
   after the last function argument and declare your utility function
   with TSRMLS_DC after the last declared argument.  Always refer to
   the globals in your function as REST_G(variable).  You are 
   encouraged to rename these macros something shorter, see
   examples in any other php module directory.
*/

#ifdef ZTS
#define REST_G(v) TSRMG(rest_globals_id, zend_rest_globals *, v)
#else
#define REST_G(v) (rest_globals.v)
#endif

#endif	/* PHP_REST_H */

#define REST_CLIENT_METHOD(_method) PHP_METHOD(RestClient, _method)
#define REST_SERVER_METHOD(_method) PHP_METHOD(RestServer, _method)

/*
 * Local variables:
 * tab-width: 4
 * c-basic-offset: 4
 * End:
 * vim600: noet sw=4 ts=4 fdm=marker
 * vim<600: noet sw=4 ts=4
 */