#include <string.h>
#include <curl/curl.h>
#include "php_rest.h"

#define DEFAULT_CHARSET      "UTF-8"
#define DEFAULT_CONTENT_TYPE "application/x-www-form-urlencoded"
#define MAX_KEY_VAL_LEN      512L
#define JSON_MAX_DEPTH       512

#define MERGED_HASHTABLE(merged, name, inst_args, meth_args) \
    ALLOC_HASHTABLE(merged); \
    zend_hash_init(merged, 0, NULL, ZVAL_PTR_DTOR, 0); \
    params_merge(merged, name, inst_args, meth_args TSRMLS_CC);

#define GET_INSTANCE_ARGS(this_ptr, args_prop, inst_args) \
    if (GET_PROP(this_ptr, "args", args_prop) && Z_TYPE_PP(args_prop) == IS_ARRAY) { \
        SEPARATE_ZVAL(args_prop); \
        inst_args = Z_ARRVAL_PP(args_prop); \
    } else { \
        inst_args = NULL; \
    }

#define GET_METHOD_ARGS(args, meth_args) \
    if (Z_TYPE_P(args) == IS_ARRAY) { \
        SEPARATE_ZVAL(&args); \
        meth_args = Z_ARRVAL_P(args); \
    } else { \
        meth_args = NULL; \
    }

static size_t curl_header_available(char *data, size_t size, size_t nmemb, void *ctx);
static size_t curl_body_available(char *body, size_t size, size_t nmemb, void *ctx);

static void params_merge(HashTable *dest, char *name, HashTable *inst_args, HashTable *meth_args TSRMLS_DC);

static void url_append_url(zval *this_ptr, smart_str *url TSRMLS_DC);
static void url_append_uri_zval(char *uri, HashTable *args, smart_str *url TSRMLS_DC);
static void url_append_query(HashTable *inst_args, HashTable *meth_args, smart_str *url TSRMLS_DC);

static void curl_set_request_data(CURL *curl, char *key, HashTable *inst_args, HashTable *meth_args TSRMLS_DC);
static void curl_set_auth(CURL *curl, HashTable *inst_args, HashTable *meth_args TSRMLS_DC);
static void curl_set_proxy(CURL *curl, HashTable *inst_args, HashTable *meth_args TSRMLS_DC);
static void curl_append_headers(CURL *curl, 
                                struct curl_slist **slist, 
                                HashTable *inst_args, 
                                HashTable *meth_args, 
                                zval *this_ptr,
                                char *method, 
                                char *method_override TSRMLS_DC);

static void fetch(zval *return_value, 
                  zval *this_ptr, 
                  zval *uri, 
                  zval *args, 
                  zend_bool decode, 
                  char *method, 
                  char *method_override TSRMLS_DC);

REST_CLIENT_METHOD(__construct) 
{
    zval *url;
    zval *args = NULL;
    zval *copy;
    
    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "z|a", &url, &args) != SUCCESS) {
		RETURN_FALSE;
	}
    
    add_property_stringl(this_ptr, "url", Z_STRVAL_P(url), Z_STRLEN_P(url), 1);
    add_property_stringl(this_ptr, "charset", DEFAULT_CHARSET, strlen(DEFAULT_CHARSET), 1);
    add_property_bool(this_ptr, "skipSSLCheck", 0);
    add_property_bool(this_ptr, "debugMode", 0);
    
    if (args == NULL) {
        MAKE_STD_ZVAL(args);
        array_init(args);
        add_property_zval(this_ptr, "args", args);
    } else {
        MAKE_STD_ZVAL(copy);
        *copy = *args;
        zval_copy_ctor(copy);
        add_property_zval(this_ptr, "args", copy);
    }
}

REST_CLIENT_METHOD(skipSSLCheck) 
{
    zend_bool flag;
    
    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "b", &flag) != SUCCESS) {
		RETURN_FALSE;
	}
    
    add_property_bool(this_ptr, "skipSSLCheck", flag);
}

REST_CLIENT_METHOD(setDebugMode) 
{
    zend_bool flag;
    
    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "b", &flag) != SUCCESS) {
		RETURN_FALSE;
	}
    
    add_property_bool(this_ptr, "debugMode", flag);
}

REST_CLIENT_METHOD(setRequestEncoding) 
{
    zval *encoding;
    
    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "z", &encoding) != SUCCESS) {
		RETURN_FALSE;
	}
    
    add_property_zval(this_ptr, "charset", encoding);
}

inline static void _setParams(INTERNAL_FUNCTION_PARAMETERS, char *hash_key)
{
    zval  *value = NULL;
    zval **args;
    
    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "a", &value) != SUCCESS) {
		RETURN_FALSE;
	}
    
    if (GET_PROP(this_ptr, "args", args)) {
        SEPARATE_ZVAL(&value);
        zval_add_ref(&value);
        add_assoc_zval(*args, hash_key, value);
    }
}

inline static void _addParam(INTERNAL_FUNCTION_PARAMETERS, char *hash_key)
{
    zval  *value = NULL;
    zval **args;
    zval **arr;
    zval  *new;
    char  *key;
    int    keylen;
    
    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "sz", &key, &keylen, &value) != SUCCESS) {
		RETURN_FALSE;
	}
    
    if (GET_PROP(this_ptr, "args", args)) {
        if (!(GET_ARRVAL(args, hash_key, arr))) {
            MAKE_STD_ZVAL(new);
            array_init(new);
            add_assoc_zval(*args, hash_key, new);
            arr = &new;
        }
        
        if (Z_TYPE_P(value) == IS_ARRAY) {
            SEPARATE_ZVAL(&value);
            zval_add_ref(&value);
            add_assoc_zval(*arr, key, value);
        } else if (Z_TYPE_P(value) == IS_OBJECT) {
            zval_add_ref(&value);
            add_assoc_zval(*arr, key, value);
        } else {
            convert_to_string_ex(&value);
            add_assoc_string(*arr, key, Z_STRVAL_P(value), 1);
        }
    }
}

inline static void _removeParam(INTERNAL_FUNCTION_PARAMETERS, char *hash_key)
{
    zval **args;
    zval **arr;
    char  *key;
    int    keylen;
    
    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "s", &key, &keylen) != SUCCESS) {
		RETURN_FALSE;
	}
    
    if (GET_PROP(this_ptr, "args", args)) {
        if (GET_ARRVAL(args, hash_key, arr)) {
            if (zend_hash_exists(Z_ARRVAL_PP(arr), key, keylen + 1)) {
                zend_hash_del(Z_ARRVAL_PP(arr), key, keylen + 1);
            }
        }
    }
}

REST_CLIENT_METHOD(setUriParams) {
    _setParams(INTERNAL_FUNCTION_PARAM_PASSTHRU, "#uri");
}

REST_CLIENT_METHOD(addUriParam) {
    _addParam(INTERNAL_FUNCTION_PARAM_PASSTHRU, "#uri");
}

REST_CLIENT_METHOD(removeUriParam) {
    _removeParam(INTERNAL_FUNCTION_PARAM_PASSTHRU, "#uri");
}

REST_CLIENT_METHOD(setQueryParams) {
    _setParams(INTERNAL_FUNCTION_PARAM_PASSTHRU, "#query");
}

REST_CLIENT_METHOD(addQueryParam) {
    _addParam(INTERNAL_FUNCTION_PARAM_PASSTHRU, "#query");
}

REST_CLIENT_METHOD(removeQueryParam) {
    _removeParam(INTERNAL_FUNCTION_PARAM_PASSTHRU, "#query");
}

REST_CLIENT_METHOD(setPostVars) {
    _setParams(INTERNAL_FUNCTION_PARAM_PASSTHRU, "#post");
}

REST_CLIENT_METHOD(addPostVar) {
    _addParam(INTERNAL_FUNCTION_PARAM_PASSTHRU, "#post");
}

REST_CLIENT_METHOD(removePostVar) {
    _removeParam(INTERNAL_FUNCTION_PARAM_PASSTHRU, "#post");
}

REST_CLIENT_METHOD(setHeaders) {
    _setParams(INTERNAL_FUNCTION_PARAM_PASSTHRU, "#header");
}

REST_CLIENT_METHOD(addHeader) {
    _addParam(INTERNAL_FUNCTION_PARAM_PASSTHRU, "#header");
}

REST_CLIENT_METHOD(removeHeader) {
    _removeParam(INTERNAL_FUNCTION_PARAM_PASSTHRU, "#header");
}

REST_CLIENT_METHOD(setAuthData) {
    _setParams(INTERNAL_FUNCTION_PARAM_PASSTHRU, "#auth");
}

REST_CLIENT_METHOD(setProxyData) {
    _setParams(INTERNAL_FUNCTION_PARAM_PASSTHRU, "#proxy");
}

REST_CLIENT_METHOD(fetch) 
{
    zval      *uri;
    zval      *args = NULL;
    zval      *copy = NULL; 
    zend_bool  decode = 0;
    char      *method;
    char      *method_actual;
    char      *method_override = NULL;
    int        method_len;
    
    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "sz|ab", &method, &method_len, &uri, &args, &decode) != SUCCESS) {
		RETURN_FALSE;
	}
    
    if (IS_GET(method) || IS_POST(method) || IS_HEAD(method)) {
        method_actual = method;
    } else {
        method_actual = METHOD_POST;
        method_override = method;
    }
    
    if (args != NULL) {
        MAKE_STD_ZVAL(copy);
        *copy = *args;
        zval_copy_ctor(copy);
    }
    
    fetch(return_value, this_ptr, uri, copy, decode, method_actual, method_override TSRMLS_DC);
}

inline static void _fetch(INTERNAL_FUNCTION_PARAMETERS, char *method, char *method_override)
{
    zval      *uri = NULL;
    zval      *args = NULL;
    zval      *copy = NULL;
    zend_bool  decode = 0;
    
    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "z|ab", &uri, &args, &decode) != SUCCESS) {
        RETURN_FALSE;
    }
    
    if (args != NULL) {
        MAKE_STD_ZVAL(copy);
        *copy = *args;
        zval_copy_ctor(copy);
    }
    
    fetch(return_value, this_ptr, uri, copy, decode, method, method_override TSRMLS_CC);
}

REST_CLIENT_METHOD(head)
{
    _fetch(INTERNAL_FUNCTION_PARAM_PASSTHRU, METHOD_HEAD, NULL);
}

REST_CLIENT_METHOD(options)
{
    _fetch(INTERNAL_FUNCTION_PARAM_PASSTHRU, METHOD_OPTIONS, NULL);
}

REST_CLIENT_METHOD(get)
{
    _fetch(INTERNAL_FUNCTION_PARAM_PASSTHRU, METHOD_GET, NULL);
}

REST_CLIENT_METHOD(post)
{
    _fetch(INTERNAL_FUNCTION_PARAM_PASSTHRU, METHOD_POST, NULL);
}

REST_CLIENT_METHOD(put)
{
    _fetch(INTERNAL_FUNCTION_PARAM_PASSTHRU, METHOD_PUT, NULL);
}

REST_CLIENT_METHOD(delete)
{
    _fetch(INTERNAL_FUNCTION_PARAM_PASSTHRU, METHOD_DELETE, NULL);
}

static void url_append_url(zval *this_ptr, smart_str *url TSRMLS_DC)
{
    zval    **zurl;
    zval    **args;
    php_url  *u;
    
    if (GET_PROP(this_ptr, "url", zurl)) {
        u = php_url_parse_ex(Z_STRVAL_PP(zurl), Z_STRLEN_PP(zurl));
        
        if (u->scheme && *u->scheme) {
            smart_str_appends(url, u->scheme);
            smart_str_appends(url, "://");
        }
        
        if (u->user && *u->user) {
            smart_str_appends(url, u->user);
            smart_str_appends(url, ":");
            
            if (u->pass && *u->pass) {
                smart_str_appends(url, u->pass);
            }
            
            smart_str_appends(url, "@");
        }
        
        if (u->host && *u->host) {
            smart_str_appends(url, u->host);
        }
        
        if (u->port) {
            smart_str_appends(url, ":");
            smart_str_append_unsigned(url, u->port);
        }
        
        if (u->path && *u->path) {
            if (GET_PROP(this_ptr, "args", args)) {
                url_append_uri_zval(u->path, Z_ARRVAL_PP(args), url TSRMLS_CC);
            }
        }
        
        php_url_free(u);
    }
}

static void url_append_uri_zval(char *uri, HashTable *args, smart_str *url TSRMLS_DC)
{
    zval **uriargs;
    
    if (GET_HTVAL(args, "#uri", uriargs)) {
        rest_url_append_uri(uri, Z_ARRVAL_PP(uriargs), url, 1 TSRMLS_CC); 
    } else {
        rest_url_append_uri(uri, NULL, url, 1 TSRMLS_CC);  
    }
    
}

static void url_append_query(HashTable *inst_args, HashTable *meth_args, smart_str *url TSRMLS_DC)
{
    HashTable *merged;
    smart_str  query_str = {0};
    
    MERGED_HASHTABLE(merged, "#query", inst_args, meth_args);
    
    php_url_encode_hash_ex(merged, &query_str, NULL, 0, NULL, 0, NULL, 0, NULL, "&" TSRMLS_CC);
    smart_str_0(&query_str);
    
    if (query_str.len > 0) {
        smart_str_appendl(url, "?", 1);
        smart_str_appendl(url, query_str.c, query_str.len);
    }
    
    smart_str_free(&query_str);
}

static void params_merge(HashTable *dest, char *name, HashTable *inst_args, HashTable *meth_args TSRMLS_DC)
{
    zval **args1;
    zval **args2;
    
    if (inst_args != NULL && GET_HTVAL(inst_args, name, args1) && Z_TYPE_PP(args1) == IS_ARRAY) {
        php_array_merge(dest, Z_ARRVAL_PP(args1), 0 TSRMLS_CC);
    }
    
    if (meth_args != NULL && GET_HTVAL(meth_args, name, args2) && Z_TYPE_PP(args2) == IS_ARRAY) {
        php_array_merge(dest, Z_ARRVAL_PP(args2), 0 TSRMLS_CC);
    }
}

static void curl_append_headers(CURL *curl, 
                                struct curl_slist **slist, 
                                HashTable *inst_args, 
                                HashTable *meth_args, 
                                zval *this_ptr,
                                char *method, 
                                char *method_override TSRMLS_DC)
{
    
    HashTable  *merged;
    smart_str   slist_headers = {0};
    zval      **value;
    zval      **charset;
    zval      **tmp;
    zval       *xmethod;
    zval       *content_type;
    ulong       idx;
    
    MERGED_HASHTABLE(merged, "#header", inst_args, meth_args);
    
    if (IS_POST(method) && GET_HTVAL(merged, "Content-Type", tmp)) {
        MAKE_STD_ZVAL(content_type);
        ZVAL_STRING(content_type, DEFAULT_CONTENT_TYPE, 1);
        zend_hash_update(merged, "Content-Type", sizeof("Content-Type"), &content_type, sizeof(zval*), NULL);
    }
    
    if (method_override != NULL && !IS_POST(method)) {
        MAKE_STD_ZVAL(xmethod);
        ZVAL_STRING(xmethod, method_override, 1);
        zend_hash_update(merged, "X-HTTP-Method-Override", sizeof("X-HTTP-Method-Override"), &xmethod, sizeof(zval*), NULL);
    }
    
    if (zend_hash_num_elements(merged)) {
        while (zend_hash_get_current_data(merged, (void **)&value) == SUCCESS) {
            char *key;
            uint  key_len;
            
            zend_hash_get_current_key_ex(merged, &key, &key_len, &idx, 0, NULL);
            zend_hash_move_forward(merged);
            
            smart_str_appendl(&slist_headers, key, key_len - 1);
            smart_str_appends(&slist_headers, ": ");
            smart_str_appendl(&slist_headers, Z_STRVAL_PP(value), Z_STRLEN_PP(value));
            
            if (strcasecmp(key, "content-type") == 0) {
                if (GET_PROP(this_ptr, "charset", charset)) {
                    smart_str_appends(&slist_headers, "; charset=");
                    smart_str_appendl(&slist_headers, Z_STRVAL_PP(charset), Z_STRLEN_PP(charset));
                    zval_ptr_dtor(charset);
                }
            }
            
            smart_str_0(&slist_headers);
            *slist = curl_slist_append(*slist, slist_headers.c);
            
            zval_ptr_dtor(value);
            smart_str_free(&slist_headers);
        }
        
        if (slist) {
            curl_easy_setopt(curl, CURLOPT_HTTPHEADER, *slist);
        }
    }
    
    zend_hash_destroy(merged);
}

static void curl_set_request_data(CURL *curl, char *key, HashTable *inst_args, HashTable *meth_args TSRMLS_DC)
{
    HashTable  *merged = NULL;
    zval      **zpostdata = NULL;
    smart_str   postdata = {0};
    char       *encoded;
    int         encoded_len;
    
    if (meth_args != NULL && GET_HTVAL(meth_args, key, zpostdata) && Z_TYPE_PP(zpostdata) == IS_STRING) {
        if (Z_STRLEN_PP(zpostdata) == 0 && inst_args != NULL) {
            zend_hash_find(inst_args, key, strlen(key) + 1, (void **)&zpostdata);
        }
    }
    
    if (zpostdata != NULL && Z_TYPE_PP(zpostdata) == IS_STRING) {
        smart_str_appendl(&postdata, Z_STRVAL_PP(zpostdata), Z_STRLEN_PP(zpostdata));
    } else {
        MERGED_HASHTABLE(merged, key, inst_args, meth_args);
        
        if (merged != NULL && zend_hash_num_elements(merged) > 0) {
            php_url_encode_hash_ex(merged, &postdata, NULL, 0, NULL, 0, NULL, 0, NULL, "&" TSRMLS_CC);
        }
    }
    
    smart_str_0(&postdata);
    
    if (postdata.len) {
        encoded = php_str_to_str(postdata.c, postdata.len, "+", 1, "%20", 3, &encoded_len);
        
        curl_easy_setopt(curl,    CURLOPT_POSTFIELDS, encoded);
		curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, encoded_len);
        
        smart_str_free(&postdata);
    }
}

static void curl_set_auth(CURL *curl, HashTable *inst_args, HashTable *meth_args TSRMLS_DC) 
{
    HashTable  *merged;
    zval      **user;
    zval      **pass;
    smart_str   userpwd = {0};
    
    MERGED_HASHTABLE(merged, "#auth", inst_args, meth_args);
    
    if (GET_HTVAL(merged, "user", user)) {
        smart_str_appendl(&userpwd, Z_STRVAL_PP(user), Z_STRLEN_PP(user));
        smart_str_appends(&userpwd, ":");
        
        if (GET_HTVAL(merged, "pass", pass)) {
            smart_str_appendl(&userpwd, Z_STRVAL_PP(pass), Z_STRLEN_PP(pass));
        }
        
        smart_str_0(&userpwd);
        
        if (userpwd.len > 1) {
            curl_easy_setopt(curl, CURLOPT_HTTPAUTH, CURLAUTH_ANY);
            curl_easy_setopt(curl,  CURLOPT_USERPWD, userpwd.c);
        }
        
        smart_str_free(&userpwd);
    }
}

static void curl_set_proxy(CURL *curl, HashTable *inst_args, HashTable *meth_args TSRMLS_DC) 
{
    HashTable  *merged;
    zval      **host; 
    zval      **user;
    zval      **pass;
    smart_str   userpwd = {0};
    
    MERGED_HASHTABLE(merged, "#proxy", inst_args, meth_args);
    
    if (GET_HTVAL(merged, "host", host)) {
        curl_easy_setopt(curl, CURLOPT_PROXY, Z_STRVAL_PP(host));
        
        if (GET_HTVAL(merged, "user", user)) {
            smart_str_appendl(&userpwd, Z_STRVAL_PP(user), Z_STRLEN_PP(user));
            smart_str_appends(&userpwd, ":");
            
            if (GET_HTVAL(merged, "pass", pass)) {
                smart_str_appendl(&userpwd, Z_STRVAL_PP(pass), Z_STRLEN_PP(pass));
            }
            
            smart_str_0(&userpwd);
            
            if (userpwd.len > 1) {
                curl_easy_setopt(curl, CURLOPT_PROXYUSERPWD, userpwd.c);
                curl_easy_setopt(curl,    CURLOPT_PROXYAUTH, CURLAUTH_BASIC | CURLAUTH_NTLM);
            }
            
            smart_str_free(&userpwd);
        }
    }
}

static size_t curl_header_available(char *data, size_t size, size_t nmemb, void *ctx)
{    
    zval   **headers;
    zval    *context = (zval *)ctx;
    size_t   length = size * nmemb;
    char    *header = data;
    char     key[MAX_KEY_VAL_LEN];
    char     value[MAX_KEY_VAL_LEN];
    int      i;
    TSRMLS_FETCH();
    
    if (strncasecmp(data, "HTTP", 4) != 0) {
        for (i = 0; i < length; i++) {
            if (header[i] == ':') {
                strncpy(key, header, i);
                key[i] = '\0';
                
                strncpy(value, header + i + 2, length - i - 3);
                value[length - i - 3] = '\0';
                
                if (GET_PROP(context, "headers", headers)) {
                    add_assoc_string(*headers, key, value, 1);
                }
                
                break;
            }
        }
    }
    
    return length;
}

static size_t curl_body_available(char *body_ptr, size_t size, size_t nmemb, void *ctx)
{
    zval      **body;
    zval       *context = (zval *)ctx;
    smart_str   body_str = {0};
    size_t      length = size * nmemb;
    TSRMLS_FETCH();
    
    if (GET_PROP(context, "body", body) && Z_TYPE_PP(body) == IS_STRING) {
        smart_str_appendl(&body_str, Z_STRVAL_PP(body), Z_STRLEN_PP(body));
    }
    
    smart_str_appendl(&body_str, body_ptr, length);
    smart_str_0(&body_str);
    zend_update_property_stringl(restresponse_class_entry, context, "body", sizeof("body") - 1, body_str.c, body_str.len TSRMLS_CC);
    smart_str_free(&body_str);
    
    return length;
}

inline static void decode_with_user_function(char *fn_name, zval **arg0, zval **decoded TSRMLS_DC)
{
    zval  *fn;
    zval **args[1];
    
    MAKE_STD_ZVAL(fn);
    ZVAL_STRING(fn, fn_name, 0);
    args[0] = arg0;
    
    call_user_function_ex(EG(function_table), NULL, fn, decoded, 1, args, 0, NULL TSRMLS_CC);
}

static void decode_response(zval *return_value TSRMLS_DC)
{
    zval **headers;
    zval **body;
    zval **content_type;
    zval  *decoded = NULL;
    
    if (GET_PROP(return_value, "headers", headers) && 
        GET_ARRVAL(headers, "Content-Type", content_type) &&
        GET_PROP(return_value, "body", body) && 
        Z_TYPE_PP(body) == IS_STRING) {
        
        if (strncasecmp(Z_STRVAL_PP(content_type), "application/json", strlen("application/json")) == 0) {
#if (PHP_VERSION_ID >= 50210)
            MAKE_STD_ZVAL(decoded);
            php_json_decode(decoded, Z_STRVAL_PP(body), Z_STRLEN_PP(body), 0, JSON_MAX_DEPTH TSRMLS_CC);
#else
            decode_with_user_function("json_decode", body, &decoded TSRMLS_CC);
#endif
        } else if (strncasecmp(Z_STRVAL_PP(content_type), "text/xml", strlen("text/xml")) == 0) {
            decode_with_user_function("simplexml_load_string", body, &decoded TSRMLS_CC);
        }
        
        if (decoded != NULL) {
            add_property_zval(return_value, "decoded", decoded);
        }   
    }
}

static void fetch(zval *return_value, 
                  zval *this_ptr, 
                  zval *uri, 
                  zval *args, 
                  zend_bool decode, 
                  char *method, 
                  char *method_override TSRMLS_DC)
{
    HashTable          *inst_args;
    HashTable          *meth_args;
    zval               *response_headers;
    zval              **args_prop;
    struct curl_slist  *slist = NULL;
    CURL               *curl;
    smart_str           url = {0};
    long                response_code = -1;
    
    GET_INSTANCE_ARGS(this_ptr, args_prop, inst_args);
    GET_METHOD_ARGS(args, meth_args);
    
    url_append_url(this_ptr, &url TSRMLS_CC);
    url_append_uri_zval(Z_STRVAL_P(uri), meth_args, &url TSRMLS_CC);
    url_append_query(inst_args, meth_args, &url TSRMLS_CC);
    
    smart_str_0(&url);
    
    object_init_ex(return_value, restresponse_class_entry);
    add_property_stringl(return_value, "url", url.c, url.len, 1);
    
    MAKE_STD_ZVAL(response_headers);
    array_init(response_headers);
    add_property_zval(return_value, "headers", response_headers);
    
    curl = curl_easy_init();
    
    curl_easy_setopt(curl,            CURLOPT_URL, url.c);
    curl_easy_setopt(curl,        CURLOPT_VERBOSE, 1);
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1);
    curl_easy_setopt(curl, CURLOPT_HEADERFUNCTION, curl_header_available);
    curl_easy_setopt(curl,    CURLOPT_WRITEHEADER, return_value);
    curl_easy_setopt(curl,  CURLOPT_WRITEFUNCTION, curl_body_available);
    curl_easy_setopt(curl,      CURLOPT_WRITEDATA, return_value);
    
    if (IS_POST(method)) {
        if (method_override == NULL) {
            curl_set_request_data(curl, "#post", inst_args, meth_args TSRMLS_CC);
        } else if (IS_PUT(method)) {
            curl_set_request_data(curl, "#put", inst_args, meth_args TSRMLS_CC);
        }
    }
    
    curl_append_headers(curl, &slist, inst_args, meth_args, this_ptr, method, method_override TSRMLS_CC);
    curl_set_proxy(curl, inst_args, meth_args TSRMLS_CC);
    curl_set_auth(curl, inst_args, meth_args TSRMLS_CC);
    
    if (IS_HEAD(method) || IS_OPTIONS(method)) {
        curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, method);
        curl_easy_setopt(curl,        CURLOPT_HEADER, 1);
        curl_easy_setopt(curl,        CURLOPT_NOBODY, 1);
    }
    
    curl_easy_perform(curl);
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &response_code);
    add_property_long(return_value, "code", response_code);
    
    if (decode) {
        decode_response(return_value TSRMLS_CC);
    }
    
    zend_hash_destroy(inst_args);
    zend_hash_destroy(meth_args);
    curl_slist_free_all(slist);
    curl_easy_cleanup(curl);
    smart_str_free(&url);
}
