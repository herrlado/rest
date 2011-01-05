#include "php_rest.h"

/* If you declare any globals in php_rest.h uncomment this:
 ZEND_DECLARE_MODULE_GLOBALS(rest)
 */

/* True global resources - no need for thread safety here */
/* static int le_rest; */

/* {{{ rest_functions[]
 *
 * Every user visible function must have an entry in rest_functions[].
 */
const zend_function_entry rest_functions[] = {
    {NULL, NULL, NULL}
};
/* }}} */

/* {{{ rest_module_entry
 */
zend_module_entry rest_module_entry = {
#if ZEND_MODULE_API_NO >= 20010901
	STANDARD_MODULE_HEADER,
#endif
	"rest",
	rest_functions,
	PHP_MINIT(rest),
	NULL,
	NULL,
	NULL,
	PHP_MINFO(rest),
#if ZEND_MODULE_API_NO >= 20010901
	"0.1", /* Replace with version number for your extension */
#endif
	STANDARD_MODULE_PROPERTIES
};
/* }}} */

#ifdef COMPILE_DL_REST
ZEND_GET_MODULE(rest)
#endif

/* {{{ PHP_MINFO_FUNCTION
 */
PHP_MINFO_FUNCTION(rest)
{
	php_info_print_table_start();
	php_info_print_table_header(2, "rest support", "enabled");
	php_info_print_table_end();
}
/* }}} */

zend_class_entry *rest_route_exception;
zend_class_entry *restresponse_class_entry;
zend_class_entry *restclient_class_entry;

static function_entry restclient_class_functions[] = {
    ZEND_ME(RestClient,        __construct, NULL, ZEND_ACC_PUBLIC | ZEND_ACC_CTOR)
    ZEND_ME(RestClient,       skipSSLCheck, NULL, ZEND_ACC_PUBLIC)
    ZEND_ME(RestClient,       setDebugMode, NULL, ZEND_ACC_PUBLIC)
    ZEND_ME(RestClient, setRequestEncoding, NULL, ZEND_ACC_PUBLIC)
    ZEND_ME(RestClient,       setUriParams, NULL, ZEND_ACC_PUBLIC)
    ZEND_ME(RestClient,        addUriParam, NULL, ZEND_ACC_PUBLIC)
    ZEND_ME(RestClient,     removeUriParam, NULL, ZEND_ACC_PUBLIC)
    ZEND_ME(RestClient,     setQueryParams, NULL, ZEND_ACC_PUBLIC)
    ZEND_ME(RestClient,      addQueryParam, NULL, ZEND_ACC_PUBLIC)
    ZEND_ME(RestClient,   removeQueryParam, NULL, ZEND_ACC_PUBLIC)
    ZEND_ME(RestClient,        setPostVars, NULL, ZEND_ACC_PUBLIC)
    ZEND_ME(RestClient,         addPostVar, NULL, ZEND_ACC_PUBLIC)
    ZEND_ME(RestClient,      removePostVar, NULL, ZEND_ACC_PUBLIC)
    ZEND_ME(RestClient,         setHeaders, NULL, ZEND_ACC_PUBLIC)
    ZEND_ME(RestClient,          addHeader, NULL, ZEND_ACC_PUBLIC)
    ZEND_ME(RestClient,       removeHeader, NULL, ZEND_ACC_PUBLIC)
    ZEND_ME(RestClient,        setAuthData, NULL, ZEND_ACC_PUBLIC)
    ZEND_ME(RestClient,       setProxyData, NULL, ZEND_ACC_PUBLIC)
    ZEND_ME(RestClient,              fetch, NULL, ZEND_ACC_PUBLIC)
    ZEND_ME(RestClient,               head, NULL, ZEND_ACC_PUBLIC)
    ZEND_ME(RestClient,            options, NULL, ZEND_ACC_PUBLIC)
    ZEND_ME(RestClient,                get, NULL, ZEND_ACC_PUBLIC)
    ZEND_ME(RestClient,               post, NULL, ZEND_ACC_PUBLIC)
    ZEND_ME(RestClient,                put, NULL, ZEND_ACC_PUBLIC)
    ZEND_ME(RestClient,             delete, NULL, ZEND_ACC_PUBLIC)
    {NULL, NULL, NULL}
};

REST_ARGINFO
ZEND_BEGIN_ARG_INFO_EX(rest_add_route_arginfo, 0, 1, 0)
    ZEND_ARG_ARRAY_INFO(0, "route", 0)
ZEND_END_ARG_INFO ()

zend_class_entry *restserver_class_entry;

static function_entry restserver_class_functions[] = {
    ZEND_ME(RestServer,      __construct, NULL, ZEND_ACC_PUBLIC | ZEND_ACC_CTOR)
    ZEND_ME(RestServer,         addRoute, rest_add_route_arginfo, ZEND_ACC_PUBLIC)
    ZEND_ME(RestServer,           handle, NULL, ZEND_ACC_PUBLIC)
    ZEND_ME(RestServer, handleRequestUri, NULL, ZEND_ACC_PUBLIC)
    ZEND_ME(RestServer, handleQueryParam, NULL, ZEND_ACC_PUBLIC)
    {NULL, NULL, NULL}
};

PHP_MINIT_FUNCTION(rest)
{
    zend_class_entry client_class_entry;
    INIT_CLASS_ENTRY(client_class_entry, "RestClient", restclient_class_functions);    
    restclient_class_entry = zend_register_internal_class(&client_class_entry TSRMLS_CC);
    
    zend_class_entry response_class_entry;
    INIT_CLASS_ENTRY(response_class_entry, "RestResponse", NULL);    
    restresponse_class_entry = zend_register_internal_class(&response_class_entry TSRMLS_CC);
    
    zend_class_entry server_class_entry;
    INIT_CLASS_ENTRY(server_class_entry, "RestServer", restserver_class_functions);    
    restserver_class_entry = zend_register_internal_class(&server_class_entry TSRMLS_CC);
    
    zend_class_entry route_exception_ce;
    INIT_CLASS_ENTRY(route_exception_ce, "RestRouteException", NULL);    
    rest_route_exception = zend_register_internal_class_ex(&route_exception_ce, 
                                                           (zend_class_entry *) zend_exception_get_default(TSRMLS_C), 
                                                           NULL TSRMLS_CC);
    
    zend_declare_property_null(rest_route_exception, "route", sizeof("route") - 1, ZEND_ACC_PUBLIC TSRMLS_CC);
    
    REGISTER_STRING_CONSTANT("REST_HTTP_METHOD_HEAD",       METHOD_HEAD, CONST_CS | CONST_PERSISTENT);
    REGISTER_STRING_CONSTANT("REST_HTTP_METHOD_OPTIONS", METHOD_OPTIONS, CONST_CS | CONST_PERSISTENT);
    REGISTER_STRING_CONSTANT("REST_HTTP_METHOD_GET",         METHOD_GET, CONST_CS | CONST_PERSISTENT);
	REGISTER_STRING_CONSTANT("REST_HTTP_METHOD_POST",       METHOD_POST, CONST_CS | CONST_PERSISTENT);
	REGISTER_STRING_CONSTANT("REST_HTTP_METHOD_PUT",         METHOD_PUT, CONST_CS | CONST_PERSISTENT);
	REGISTER_STRING_CONSTANT("REST_HTTP_METHOD_DELETE",   METHOD_DELETE, CONST_CS | CONST_PERSISTENT);
    
    REGISTER_STRING_CONSTANT("REST_ROUTE_PATTERN_DEFAULT",           REST_ROUTE_PATTERN_DEFAULT, CONST_CS | CONST_PERSISTENT);
    REGISTER_STRING_CONSTANT("REST_ROUTE_PATTERN_TOKENS",             REST_ROUTE_PATTERN_TOKENS, CONST_CS | CONST_PERSISTENT);
    REGISTER_STRING_CONSTANT("REST_ROUTE_PATTERN_ALPHA_TOKENS", REST_ROUTE_PATTERN_ALPHA_TOKENS, CONST_CS | CONST_PERSISTENT);
    REGISTER_STRING_CONSTANT("REST_ROUTE_PATTERN_DIGIT_TOKENS", REST_ROUTE_PATTERN_DIGIT_TOKENS, CONST_CS | CONST_PERSISTENT);
    
    return SUCCESS;
}

void rest_url_append_uri(char *uri, HashTable *args, smart_str *url, zend_bool encode TSRMLS_DC)
{
    zval **token;
    char  *key;
    int    i; 
    int    start; 
    int    uri_len = strlen(uri); 
    int    encoded_len;
    
    if (strlen(uri) == 1 && *uri == '/') {
        return;
    }
    
    if (uri[0] != '/') {
        smart_str_appendl(url, "/", 1);
    }
    
    if (args != NULL) {
        for (i = 0, start = 0; i < uri_len; i++) {
            
            if (uri[i] == '{') {
                smart_str_appendl(url, uri + start, i - start);
                start = ++i;
            } else if (uri[i] == '}') {
                key = emalloc(i - start + 1);
                strncpy(key, uri + start, i - start);
                key[i - start] = '\0';
                
                if (args != NULL && GET_HTVAL(args, key, token)) {
                    if (encode) {
                        smart_str_appends(url, php_raw_url_encode(Z_STRVAL_PP(token), Z_STRLEN_PP(token), &encoded_len));
                    } else {
                        smart_str_appends(url, Z_STRVAL_PP(token));
                    }
                    
                } else {
                    smart_str_appendl(url, uri + start - 1, i - start + 2);
                }
                
                start = ++i;
                efree(key);
            }
            
        }
        
        if (start < uri_len) {
            smart_str_appendl(url, uri + start, uri_len - start);
        }
    } else {
        smart_str_appendl(url, uri, uri_len);
    }
}
