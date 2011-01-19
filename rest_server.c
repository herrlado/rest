#include <string.h>
#include "zend.h"
#include "zend_API.h"
#include "zend_builtin_functions.h"
#include "zend_interfaces.h"
#include "zend_exceptions.h"
#include "zend_vm.h"
#include "php_rest.h"

static void throw_exception(zend_class_entry *base, char *message, zval *route TSRMLS_DC);
static void throw_exception_ex(zend_class_entry *base, zval *route TSRMLS_DC, char *format, ...);
static void normalize_path(char *input, zval **path TSRMLS_DC);
static char *normalize_token(char *key, char *value);
static void parse_path(char *path, HashTable *pathargs, zval *route TSRMLS_DC);
static void add_route(zval *this_ptr, zval *route TSRMLS_DC);
static void resolve_request_method(char **method TSRMLS_DC);
static void invoke_route_callback(zval *callback, zval *matches, zval **ret_val TSRMLS_DC);
static void handle(zval *this_ptr, zval *return_value, int return_value_used, char *path, int path_len TSRMLS_DC);
static void handle_internal(INTERNAL_FUNCTION_PARAMETERS, char *method);
static zend_bool validate_and_normalize_matches(zval *route, zval *matches TSRMLS_DC);

static char *user_callback_keys[] = {"#get", "#post", "#put", "#delete"};

REST_SERVER_METHOD(__construct) 
{
    zval *endpoint;
    char *input;
    int   input_len;
    
    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "s", &input, &input_len) != SUCCESS) {
        RETURN_FALSE;
    }
    
    normalize_path(input, &endpoint TSRMLS_CC);
    add_property_stringl(this_ptr, "endpoint", Z_STRVAL_P(endpoint), Z_STRLEN_P(endpoint), 1);
    zval_ptr_dtor(&endpoint);
    
    add_property_null(this_ptr, "routes");
    add_property_null(this_ptr, "filters");
}

REST_SERVER_METHOD(addRoute) 
{
    zval *route;
    
    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "a/", &route) != SUCCESS) {
        RETURN_FALSE;
    }
    
    add_route(this_ptr, route TSRMLS_CC);
    
    RETURN_THIS();
}

REST_SERVER_METHOD(addNamedRoute) 
{
    zval *route;
    char *name;
    int   name_len;
    
    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "sa/", &name, &name_len, &route) != SUCCESS) {
        RETURN_FALSE;
    }
    
    add_assoc_stringl(route, "#name", name, name_len, 1);
    add_route(this_ptr, route TSRMLS_CC);
    
    RETURN_THIS();
}

REST_SERVER_METHOD(addFilter) 
{
    zval **filters;
    zval  *filter;
    char  *callback_name;
    
    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "z/", &filter) != SUCCESS) {
        RETURN_FALSE;
    }
    
    if (!zend_is_callable(filter, 0, &callback_name TSRMLS_CC)) {
        if (callback_name) {
            efree(callback_name);
        }
        
        zend_class_entry *parent = (zend_class_entry *) zend_get_error_exception(TSRMLS_C);
        zval             *exception;
        
        MAKE_STD_ZVAL(exception);
        object_init_ex(exception, rest_invalid_filter_exception);
        
        zend_update_property_string(parent, exception, "message", sizeof("message") - 1, 
                                    "Invalid callback!" TSRMLS_CC);
        zend_update_property(parent, exception, "filter", sizeof("filter") - 1, filter TSRMLS_CC);
        zend_throw_exception_object(exception TSRMLS_CC);
        
        return;
    }
    
    if (callback_name) {
        efree(callback_name);
    }
    
    PROP(this_ptr, "filters", filters);
    
    if (Z_TYPE_PP(filters) == IS_NULL) {
        array_init(*filters);
    }
    
    zval_add_ref(&filter);
    add_next_index_zval(*filters, filter);
    
    RETURN_THIS();
}

REST_SERVER_METHOD(handle) 
{
    char *path;
    int   path_len;
    
    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "s", &path, &path_len) != SUCCESS) {
        RETURN_FALSE;
    }
    
    handle(this_ptr, return_value, return_value_used, path, path_len TSRMLS_CC);
}

REST_SERVER_METHOD(handleRequestUri) 
{
    zval    **server;
    zval    **value;
    zval    **endpoint;
    zval     *req_uri;
    zval     *path;
    php_url  *url;
    char     *tmp;
    
    HTVAL(EG(active_symbol_table), "_SERVER", server);
    HTVAL(Z_ARRVAL_PP(server), "REQUEST_URI", value);
    
    url = php_url_parse_ex(Z_STRVAL_PP(value), Z_STRLEN_PP(value));
    normalize_path(url->path, &path TSRMLS_CC);
    php_url_free(url);
    
    if (GET_PROP(this_ptr, "endpoint", endpoint)) {
        if (strncmp(Z_STRVAL_P(path), Z_STRVAL_PP(endpoint), Z_STRLEN_PP(endpoint)) == 0) {
            tmp = estrdup(Z_STRVAL_P(path) + Z_STRLEN_PP(endpoint));
            normalize_path(tmp, &req_uri TSRMLS_CC);
            efree(tmp);
        } else {
            MAKE_STD_ZVAL(req_uri);
            ZVAL_STRING(req_uri, Z_STRVAL_P(path), 1);
        }
    }
    
    handle(this_ptr, return_value, return_value_used, Z_STRVAL_P(req_uri), Z_STRLEN_P(req_uri) TSRMLS_CC);
}

REST_SERVER_METHOD(handleQueryParam) 
{
    zval **get;
    zval **tmp;
    zval  *path;
    char  *param_name;
    int    param_name_len;
    
    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "s", &param_name, &param_name_len) != SUCCESS) {
        RETURN_FALSE;
    }
    
    HTVAL(EG(active_symbol_table), "_GET", get);
    
    if (GET_HTVAL(Z_ARRVAL_PP(get), param_name, tmp)) {
        normalize_path(Z_STRVAL_PP(tmp), &path TSRMLS_CC);
        handle(this_ptr, return_value, return_value_used, Z_STRVAL_P(path), Z_STRLEN_P(path) TSRMLS_CC);
    }
}

REST_SERVER_METHOD(get) 
{
    handle_internal(INTERNAL_FUNCTION_PARAM_PASSTHRU, "#get");
}

REST_SERVER_METHOD(put) 
{
    handle_internal(INTERNAL_FUNCTION_PARAM_PASSTHRU, "#put");
}

REST_SERVER_METHOD(post) 
{
    handle_internal(INTERNAL_FUNCTION_PARAM_PASSTHRU, "#post");
}

REST_SERVER_METHOD(delete) 
{
    handle_internal(INTERNAL_FUNCTION_PARAM_PASSTHRU, "#delete");
}

static void throw_exception(zend_class_entry *base, char *message, zval *route TSRMLS_DC) 
{
    zend_class_entry *parent = (zend_class_entry *) zend_get_error_exception(TSRMLS_C);
    zval             *exception;
    
    MAKE_STD_ZVAL(exception);
    object_init_ex(exception, base);
    
    zend_update_property_string(parent, exception, "message", sizeof("message") - 1, message TSRMLS_CC);
    
    if (route != NULL) {
        zend_update_property(parent, exception, "route", sizeof("route") - 1, route TSRMLS_CC);
    }
    
    zend_throw_exception_object(exception TSRMLS_CC);
}

static void throw_exception_ex(zend_class_entry *base, zval *route TSRMLS_DC, char *format, ...)
{
    zend_class_entry *parent = (zend_class_entry *) zend_get_error_exception(TSRMLS_C);
    zval             *exception;
    va_list           arg;
    char             *message;
    
    va_start(arg, format);
    vspprintf(&message, 0, format, arg);
    va_end(arg);
    
    MAKE_STD_ZVAL(exception);
    object_init_ex(exception, base);
    
    zend_update_property_string(parent, exception, "message", sizeof("message") - 1, message TSRMLS_CC);
    efree(message);
    
    if (route != NULL) {
        zend_update_property(parent, exception, "route", sizeof("route") - 1, route TSRMLS_CC);
    }
    
    zend_throw_exception_object(exception TSRMLS_CC);
}

static void normalize_path(char *input, zval **path TSRMLS_DC)
{
    smart_str  result = {0};
    char      *trimmed;
    
    smart_str_appends(&result, "/");
    trimmed = php_trim(input, strlen(input), "/", 1, NULL, 3 TSRMLS_CC);
    smart_str_appends(&result, trimmed);
    efree(trimmed);
    
    smart_str_0(&result);
    
    MAKE_STD_ZVAL(*path);
    ZVAL_STRINGL(*path, result.c, result.len, 1);
    
    smart_str_free(&result);
}

static char *normalize_token(char *key, char *value)
{
    char      *prefix = "(?P<";
    char      *normalized;
    smart_str  result = {0};
    
    if (strncmp(value, prefix, strlen(prefix)) != 0) {
        
        if (strcmp(value, REST_ROUTE_PATTERN_TOKENS) == 0 ||
            strcmp(value, REST_ROUTE_PATTERN_ALPHA_TOKENS) == 0 ||
            strcmp(value, REST_ROUTE_PATTERN_DIGIT_TOKENS) == 0) {
            
            smart_str_appends(&result, "?");
        }
        
        smart_str_appends(&result, prefix);
        smart_str_appendl(&result, key, strlen(key));
        smart_str_appends(&result, ">");
        smart_str_appendl(&result, value, strlen(value));
        smart_str_appends(&result, ")");
    } else {
        smart_str_appendl(&result, value, strlen(value));
    }
    
    smart_str_0(&result);
    normalized = estrdup(result.c);
    smart_str_free(&result);
    
    return normalized;
}

static void parse_path(char *path, HashTable *pathargs, zval *route TSRMLS_DC)
{
    zval *handlers;
    char *regex = REST_ROUTE_PATTERN_DEFAULT;
    int   regex_len = strlen(regex) + 1;
    int   i;
    int   start;
    int   path_len = strlen(path);
    
    MAKE_STD_ZVAL(handlers);
    array_init(handlers);
    
    for (i = 0, start = 0; i < path_len; i++) {
        if (path[i] == '{') {
            start = ++i;
        } else if (path[i] == '}') {
            zval **value;
            zval  *tmp;
            int    key_len = i - start + 1;
            char   key[key_len];
            char   buf[regex_len + key_len];
            char  *callback_name;
            char  *normalized;
            
            strncpy(key, path + start, i - start);
            key[i - start] = '\0';
            
            MAKE_STD_ZVAL(tmp);
            
            if (GET_HTVAL(pathargs, key, value)) {                
                if (zend_is_callable(*value, 0, &callback_name TSRMLS_CC)) {
                    snprintf(buf, regex_len + key_len, regex, key);
                    ZVAL_STRING(tmp, buf, 1);
                    add_assoc_zval(handlers, key, *value);
                } else if (Z_TYPE_PP(value) == IS_STRING) {
                    normalized = normalize_token(key, Z_STRVAL_PP(value));
                    ZVAL_STRING(tmp, normalized, 1);
                    efree(normalized);
                }
                
                if (callback_name) {
                    efree(callback_name);
                }
            } else {
                snprintf(buf, regex_len + key_len, regex, key);
                ZVAL_STRING(tmp, buf, 1);
            }
            
            zend_hash_update(pathargs, key, strlen(key) + 1, &tmp, sizeof(zval *), NULL);
            
            start = ++i;
        }
    }
    
    add_assoc_zval(route, "#handlers", handlers);
}

static void add_route(zval *this_ptr, zval *route TSRMLS_DC)
{
    zval        pathargs;
    zval      **tokens;
    zval      **routes;
    zval      **tmp;
    zval       *path;
    zval      **name;
    zval      **callback;
    char       *callback_name;
    smart_str   uri = {0};
    int         i;
    int         has_callback = 0;
    
    for (i = 0; i < 4; i++) {
        if (GET_HTVAL(Z_ARRVAL_P(route), user_callback_keys[i], callback)) {
            has_callback = 1;
            
            if (!zend_is_callable(*callback, 0, &callback_name TSRMLS_CC)) {
                if (callback_name) {
                    efree(callback_name);
                }
                throw_exception(rest_route_exception, "Route doesn't contain callback!", route TSRMLS_CC);
                return;
            }
            
            if (callback_name) {
                efree(callback_name);
            }
        }
    }
    
    if (!has_callback) {
        throw_exception(rest_route_exception, "Route doesn't contain callback!", route TSRMLS_CC);
    }
    
    if (GET_HTVAL(Z_ARRVAL_P(route), "#tokens", tokens)) {
        pathargs = **tokens;
        zval_copy_ctor(&pathargs);
    } else {
        array_init(&pathargs);
    }
    
    if (GET_HTVAL(Z_ARRVAL_P(route), "#path", tmp) && Z_TYPE_PP(tmp) == IS_STRING) {
        if (!zend_hash_exists(Z_ARRVAL_P(route), "#name", sizeof("#name"))) {
            add_assoc_stringl(route, "#name", Z_STRVAL_PP(tmp), Z_STRLEN_PP(tmp), 1);
        }
        
        normalize_path(Z_STRVAL_PP(tmp), &path TSRMLS_CC);
        parse_path(Z_STRVAL_P(path), Z_ARRVAL(pathargs), route TSRMLS_CC);
    } else {
        throw_exception(rest_route_exception, 
                        "Invalid route, please specify path string using #path key", 
                        route TSRMLS_CC);
        return;
    }
    
    smart_str_appends(&uri, "~^");
    rest_url_append_uri(Z_STRVAL_P(path), Z_ARRVAL(pathargs), &uri, 0 TSRMLS_CC);
    smart_str_appends(&uri, "$~");
    zval_ptr_dtor(&path);
    
    smart_str_0(&uri);
    add_assoc_stringl(route, "#expr", uri.c, uri.len, 1);
    smart_str_free(&uri);
    
    PROP(this_ptr, "routes", routes);
    HTVAL(Z_ARRVAL_P(route), "#name", name);
    
    if (Z_TYPE_PP(routes) != IS_ARRAY) {
        array_init(*routes);
    }
    
    zval_add_ref(&route);
    add_assoc_zval(*routes, Z_STRVAL_PP(name), route);
    
    zval_dtor(&pathargs);
}

static void resolve_request_method(char **method TSRMLS_DC)
{
    zval **server;
    zval **req_method;
    zval **overriden;
    smart_str resolved = {0};
    
    smart_str_appends(&resolved, "#");
    
    if (HTVAL(EG(active_symbol_table), "_SERVER", server) && ARRVAL_PP(server, "REQUEST_METHOD", req_method)) {
        if (IS_POST(Z_STRVAL_PP(req_method))) {
            if (GET_ARRVAL(server, "HTTP_X_HTTP_METHOD_OVERRIDE", overriden)) {
                smart_str_appendl(&resolved, Z_STRVAL_PP(overriden), Z_STRLEN_PP(overriden));
            }
        } else {
            smart_str_appendl(&resolved, Z_STRVAL_PP(req_method), Z_STRLEN_PP(req_method));
        }
    } else {
        smart_str_appends(&resolved, "get");
    }
    
    smart_str_0(&resolved);
    
    *method = estrdup(resolved.c);
    php_strtolower(*method, resolved.len);
    
    smart_str_free(&resolved);
}

inline static int _call_user_func(zval *callback, zval ***args, int arg_count, zval **ret_val TSRMLS_DC)
{
    return call_user_function_ex(EG(function_table), NULL, callback, ret_val, arg_count, args, 0, NULL TSRMLS_CC);
}

static void invoke_route_callback(zval *callback, zval *matches, zval **ret_val TSRMLS_DC)
{
    zval ***fnargs;
    
    fnargs = (zval ***) safe_emalloc(sizeof(zval **), 1, 0);
    fnargs[0] = &matches;
    
    if (_call_user_func(callback, fnargs, 1, ret_val TSRMLS_CC) == FAILURE) {
        
    }
    
    efree(fnargs);
}

static zend_bool validate_and_normalize_matches(zval *route, zval *matches TSRMLS_DC) {
    zval ***fnargs;
    zval  **handlers;
    zval  **callback;
    zval  **value;
    zval   *tokens;
    zval   *ret_val;
    zval    delim;
    char   *key;
    int     key_type;
    uint    key_len;
    ulong   num_index;
    
    HTVAL(Z_ARRVAL_P(route), "#handlers", handlers);
    ZVAL_STRING(&delim, "/", 1);
    
    zend_hash_internal_pointer_reset_ex(Z_ARRVAL_P(matches), NULL);
    while (zend_hash_get_current_data(Z_ARRVAL_P(matches), (void **)&value) == SUCCESS) {
        key_type = zend_hash_get_current_key_ex(Z_ARRVAL_P(matches), &key, &key_len, &num_index, 0, NULL);
        
        if (key_type == HASH_KEY_IS_STRING) {
            if (*(Z_STRVAL_PP(value)) == '/') {
                MAKE_STD_ZVAL(tokens);
                array_init(tokens);
                
                php_explode(&delim, *value, tokens, 100);
                zend_hash_index_del(Z_ARRVAL_P(tokens), 0);
                zval_dtor(*value);
                array_init(*value);
                INIT_PZVAL(*value);
                
                php_array_merge(Z_ARRVAL_PP(value), Z_ARRVAL_P(tokens), 0 TSRMLS_CC);
                zval_ptr_dtor(&tokens);
            }
            
            if (Z_TYPE_PP(handlers) == IS_ARRAY && GET_ARRVAL(handlers, key, callback)) {
                fnargs = (zval ***) safe_emalloc(sizeof(zval **), 1, 0);
                fnargs[0] = value;
                
                if (_call_user_func(*callback, fnargs, 1, &ret_val TSRMLS_CC) == SUCCESS) {
                    if (Z_TYPE_P(ret_val) == IS_BOOL && !Z_BVAL_P(ret_val)) {
                        efree(fnargs);
                        zval_dtor(&delim);
                        zval_ptr_dtor(&ret_val);
                        
                        throw_exception_ex(rest_route_exception, 
                                           route TSRMLS_CC,
                                           "Validation error for token '%s'",
                                           key);
                        return 0;
                    } else {
                        SEPARATE_ZVAL(&ret_val);
                        add_assoc_zval(matches, key, ret_val);
                    }
                } else {
                    
                }
                
                efree(fnargs);
            }
        }
        
        zend_hash_move_forward(Z_ARRVAL_P(matches));
    }
    
    zval_dtor(&delim);
    
    return 1;
}

static zend_bool apply_filters(zval *this_ptr, zval *route, zval *matches TSRMLS_DC) {
    zval   *ret_val = NULL;
    zval  **filters;
    zval  **callback;
    zval ***fnargs;
    
    if (GET_PROP(this_ptr, "filters", filters) && 
        Z_TYPE_PP(filters) == IS_ARRAY && 
        zend_hash_num_elements(Z_ARRVAL_PP(filters)) > 0) {
        
        while (zend_hash_get_current_data(Z_ARRVAL_PP(filters), (void **)&callback) == SUCCESS) {
            fnargs = (zval ***) safe_emalloc(sizeof(zval **), 2, 0);
            
            fnargs[0] = &route;
            fnargs[1] = &matches;
            
            if (_call_user_func(*callback, fnargs, 2, &ret_val TSRMLS_CC) == SUCCESS) {
                if (ret_val != NULL && Z_TYPE_P(ret_val) == IS_ARRAY) {
                    SEPARATE_ZVAL(&ret_val);
                    REPLACE_ZVAL_VALUE(&matches, ret_val, 1);
                    zval_ptr_dtor(&ret_val);
                }
            } else {
                
            }
            
            zend_hash_move_forward(Z_ARRVAL_PP(filters));
            efree(fnargs);
        }
    }
    
    return 1;
}

zend_bool is_match_key_assoc(HashTable *ht, void *pData, zend_hash_key *hash_key, void *pParam)
{
    return (hash_key->arKey && hash_key->nKeyLength);
}

static void handle(zval *this_ptr, zval *return_value, int return_value_used, char *path, int path_len TSRMLS_DC)
{
    pcre_cache_entry  *pce;
    HashPosition       pos;
    zval             **routes;
    zval              *ret_val;
    zval             **route;
    zval             **expr;
    zval             **callback;
    zval              *args;
    char              *method;
    int                found = 0;
    zend_bool          filtered = 0;
    
    resolve_request_method(&method TSRMLS_CC);
    PROP(this_ptr, "routes", routes);
    
    for(zend_hash_internal_pointer_reset_ex(Z_ARRVAL_PP(routes), &pos);
        zend_hash_has_more_elements_ex(Z_ARRVAL_PP(routes), &pos) == SUCCESS && !found;
        zend_hash_move_forward_ex(Z_ARRVAL_PP(routes), &pos)) {
        
        if (zend_hash_get_current_data_ex(Z_ARRVAL_PP(routes), (void**)&route, &pos) == SUCCESS) {
            ARRVAL_PP(route, "#expr", expr);
            
            if ((pce = pcre_get_compiled_regex_cache(Z_STRVAL_PP(expr), Z_STRLEN_PP(expr) TSRMLS_CC)) != NULL) {
                zval *matches;
                zval *result;
                
                MAKE_STD_ZVAL(result);
                MAKE_STD_ZVAL(matches);
                
                php_pcre_match_impl(pce, path, path_len, result, matches, 0, 1, 0, 0 TSRMLS_CC);
                
                if (Z_LVAL_P(result) > 0) {        
                    if (GET_ARRVAL(route, method, callback)) {
                        MAKE_STD_ZVAL(args);
                        array_init(args);
                        INIT_PZVAL(args);
                        
                        if (zend_hash_num_elements(Z_ARRVAL_P(matches)) > 0) {
                            if (validate_and_normalize_matches(*route, matches TSRMLS_CC)) {
                                zend_hash_merge_ex(Z_ARRVAL_P(args), Z_ARRVAL_P(matches), 
                                                   (copy_ctor_func_t) zval_add_ref, sizeof(zval*), 
                                                   (merge_checker_func_t) is_match_key_assoc, NULL);
                                
                                filtered = apply_filters(this_ptr, *route, args TSRMLS_CC);
                            }
                        }
                        
                        if (filtered) {
                            invoke_route_callback(*callback, args, &ret_val TSRMLS_CC);
                            
                            if (return_value_used) {
                                COPY_PZVAL_TO_ZVAL(*return_value, ret_val);
                            }
                            
                            zval_ptr_dtor(&ret_val);
                        }
                        
                        zval_ptr_dtor(&args);
                    } else {
                        throw_exception_ex(rest_unsupported_method_exception, 
                                           *route TSRMLS_CC,
                                           "There is no callback bound to specified HTTP method %s",
                                           method);
                        return;
                    }
                    
                    found = 1;
                }
                
                zval_ptr_dtor(&result);
                zval_ptr_dtor(&matches);
            }
        }
    }
    
    efree(method);
}

static void handle_internal(INTERNAL_FUNCTION_PARAMETERS, char *method)
{
    zval  *ret_val;
    zval  *route_params;
    zval  *data;
    zval  *query_params;
    zval **routes;
    zval **route;
    zval **callback;
    char  *route_name;
    int    route_name_len;
    
    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "sa/a!/|a!/", 
                              &route_name, &route_name_len, &route_params, &data, &query_params) != SUCCESS) {
        RETURN_FALSE;
    }
    
    PROP(this_ptr, "routes", routes);
    
    if (!(GET_ARRVAL(routes, route_name, route))) {
        throw_exception_ex(rest_route_exception, 
                           NULL TSRMLS_CC,
                           "There is no route with specified name %s",
                           route_name);
        return;
    }
    
    if (!(GET_ARRVAL(route, method, callback))) {
        throw_exception_ex(rest_unsupported_method_exception, 
                           *route TSRMLS_CC,
                           "There is no callback bound to specified HTTP method %s",
                           method);
        return;
    }
    
    if (Z_TYPE_P(query_params) != IS_ARRAY) {
        array_init(query_params);
    }
    
    if (strcmp(method, "#put") == 0 || strcmp(method, "#post") == 0) {
        ZEND_SET_SYMBOL(EG(active_symbol_table), "_GET",  query_params);
        ZEND_SET_SYMBOL(EG(active_symbol_table), "_POST", data);
    } else {
        ZEND_SET_SYMBOL(EG(active_symbol_table), "_GET", data);
    }
    
    invoke_route_callback(*callback, route_params, &ret_val TSRMLS_CC);
    
    if (return_value_used) {
        COPY_PZVAL_TO_ZVAL(*return_value, ret_val);
    }
    
    zval_ptr_dtor(&ret_val);
}
