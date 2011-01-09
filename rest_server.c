#include <string.h>
#include "php_rest.h"

static void throw_exception(zend_class_entry *base, char *message, zval *route TSRMLS_DC);
static void throw_exception_ex(zend_class_entry *base, zval *route TSRMLS_DC, char *format, ...);
static void normalize_path(char *input, zval **path TSRMLS_DC);
static char *normalize_token(char *key, char *value);
static void parse_path(char *path, HashTable *pathargs TSRMLS_DC);
static void add_route(zval *this_ptr, zval *route TSRMLS_DC);
static void resolve_request_method(char **method TSRMLS_DC);
static void invoke_route_callback(zval *callback, zval *matches, zval **ret_val TSRMLS_DC);
static void handle(zval *this_ptr, zval *return_value, int return_value_used, char *path, int path_len TSRMLS_DC);
static void handle_internal(INTERNAL_FUNCTION_PARAMETERS, char *method);

static char *user_callback_keys[] = {"#get", "#post", "#put", "#delete"};

REST_SERVER_METHOD(__construct) 
{
    zval *routes;
    zval *endpoint;
    char *input;
    int   input_len;
    
    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "s", &input, &input_len) != SUCCESS) {
		RETURN_FALSE;
	}
    
    normalize_path(input, &endpoint);
    
    add_property_stringl(this_ptr, "endpoint", Z_STRVAL_P(endpoint), Z_STRLEN_P(endpoint), 1);
    
    MAKE_STD_ZVAL(routes);
    array_init(routes);
    
    add_property_zval(this_ptr, "routes", routes);
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

REST_SERVER_METHOD(handle) 
{
    char *path;
    int   path_len;
    
    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "s", &path, &path_len) != SUCCESS) {
		RETURN_FALSE;
	}
    
    handle(this_ptr, return_value, return_value_used, path, path_len);
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
    normalize_path(url->path, &path);
    php_url_free(url);
    
    if (GET_PROP(this_ptr, "endpoint", endpoint)) {
        if (strncmp(Z_STRVAL_P(path), Z_STRVAL_PP(endpoint), Z_STRLEN_PP(endpoint)) == 0) {
            tmp = estrdup(Z_STRVAL_P(path) + Z_STRLEN_PP(endpoint));
            normalize_path(tmp, &req_uri);
            efree(tmp);
        } else {
            MAKE_STD_ZVAL(req_uri);
            ZVAL_STRING(req_uri, Z_STRVAL_P(path), 1);
        }
    }
    
    handle(this_ptr, return_value, return_value_used, Z_STRVAL_P(req_uri), Z_STRLEN_P(req_uri));
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
        normalize_path(Z_STRVAL_PP(tmp), &path);
        handle(this_ptr, return_value, return_value_used, Z_STRVAL_P(path), Z_STRLEN_P(path));
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
    zend_class_entry *parent = (zend_class_entry *) zend_get_error_exception();
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
    zend_class_entry *parent = (zend_class_entry *) zend_get_error_exception();
    zval             *exception;
    va_list           arg;
    char             *message;
    
    va_start(arg, format);
    zend_vspprintf(&message, 0, format, arg);
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
    ZVAL_STRING(*path, result.c, 1);
    
    smart_str_free(&result);
}

static char *normalize_token(char *key, char *value)
{
    char      *prefix = "(?P<";
    char      *normalized;
    smart_str  result = {0};
    
    if (strncmp(value, prefix, strlen(prefix)) != 0 || strncmp(value, prefix, strlen(prefix)) != 0) {
        
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

static void parse_path(char *path, HashTable *pathargs TSRMLS_DC)
{
    char *regex = REST_ROUTE_PATTERN_DEFAULT;
    int   regex_len = strlen(regex) + 1;
    int   i;
    int   start;
    int   path_len = strlen(path);
    
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
                if (Z_TYPE_PP(value) == IS_STRING && !zend_is_callable(*value, 0, &callback_name TSRMLS_CC)) {
                    normalized = normalize_token(key, Z_STRVAL_PP(value));
                    ZVAL_STRING(tmp, normalized, 1);
                    efree(normalized);
                }
            } else {
                snprintf(buf, regex_len + key_len, regex, key);
                ZVAL_STRING(tmp, buf, 1);
            }
            
            zend_hash_update(pathargs, key, strlen(key) + 1, &tmp, sizeof(zval *), NULL);
            
            start = ++i;
        }
    }
}

static void add_route(zval *this_ptr, zval *route TSRMLS_DC)
{
    HashTable  *pathargs;
    zval      **tokens;
    zval      **routes;
    zval       *copy;
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
                efree(callback_name);
                throw_exception_ex(rest_route_exception, 
                                   route TSRMLS_CC,
                                   "Invalid callback bound to request method %s",
                                   user_callback_keys[i]);
                return;
            }
            
            efree(callback_name);
        }
    }
    
    if (!has_callback) {
        throw_exception(rest_route_exception, "Route doesn't contain callback!", route TSRMLS_CC);
    }
    
    MAKE_STD_ZVAL(copy);
    *copy = *route;
    zval_copy_ctor(copy);
    zval_dtor(route);
    
    ALLOC_HASHTABLE(pathargs);
    zend_hash_init(pathargs, 0, NULL, ZVAL_PTR_DTOR, 0);
    
    if (GET_HTVAL(Z_ARRVAL_P(copy), "#tokens", tokens)) {
        php_array_merge(pathargs, Z_ARRVAL_PP(tokens), 0 TSRMLS_CC);
    }
    
    if (GET_HTVAL(Z_ARRVAL_P(copy), "#path", tmp) && Z_TYPE_PP(tmp) == IS_STRING) {
        if (!zend_hash_exists(Z_ARRVAL_P(copy), "#name", sizeof("#name"))) {
            add_assoc_stringl(copy, "#name", Z_STRVAL_PP(tmp), Z_STRLEN_PP(tmp), 1);
        }
        
        normalize_path(Z_STRVAL_PP(tmp), &path);
        parse_path(Z_STRVAL_P(path), pathargs TSRMLS_CC);
    } else {
        throw_exception(rest_route_exception, 
                        "Invalid route, please specify path string using #path key", 
                        route TSRMLS_CC);
        return;
    }
    
    smart_str_appends(&uri, "~^");
    rest_url_append_uri(Z_STRVAL_P(path), pathargs, &uri, 0 TSRMLS_CC);
    smart_str_appends(&uri, "$~");
    
    smart_str_0(&uri);
    add_assoc_stringl(copy, "#expr", uri.c, uri.len, 1);
    smart_str_free(&uri);
    
    PROP(this_ptr, "routes", routes);
    HTVAL(Z_ARRVAL_P(copy), "#name", name);

    zend_hash_update(Z_ARRVAL_PP(routes), Z_STRVAL_PP(name), Z_STRLEN_PP(name) + 1, &copy, sizeof(zval*), NULL);
}

static void resolve_request_method(char **method TSRMLS_DC)
{
    zval **server;
    zval **req_method;
    zval **overriden;
    smart_str resolved = {0};
    
    HTVAL(EG(active_symbol_table), "_SERVER", server);
    ARRVAL_PP(server, "REQUEST_METHOD", req_method);
    
    smart_str_appends(&resolved, "#");
    
    if (IS_POST(Z_STRVAL_PP(req_method))) {
        if (GET_ARRVAL(server, "HTTP_X_HTTP_METHOD_OVERRIDE", overriden)) {
            smart_str_appendl(&resolved, Z_STRVAL_PP(overriden), Z_STRLEN_PP(overriden));
        }
    } else {
        smart_str_appendl(&resolved, Z_STRVAL_PP(req_method), Z_STRLEN_PP(req_method));
    }
    
    smart_str_0(&resolved);
    
    *method = estrdup(resolved.c);
    php_strtolower(*method, resolved.len);
    
    smart_str_free(&resolved);
}

static void invoke_route_callback(zval *callback, zval *matches, zval **ret_val TSRMLS_DC)
{
    HashPosition   pos;
    HashPosition   pos1;
    zval          *delim;
    zval          *args;
    zval          *copy;
    zval          *tokens;
    zval         **token;
    zval         **value;
    zval         **fnargs[1];
    uint           keylen;
    ulong          idx;
    int            type;
    char          *key;

    MAKE_STD_ZVAL(delim);
    ZVAL_STRINGL(delim, "/", 1, 1);
    
    MAKE_STD_ZVAL(args);
    array_init(args);
    
    for(zend_hash_internal_pointer_reset_ex(Z_ARRVAL_P(matches), &pos);
        zend_hash_has_more_elements_ex(Z_ARRVAL_P(matches), &pos) == SUCCESS;
        zend_hash_move_forward_ex(Z_ARRVAL_P(matches), &pos)) {
        
        type = zend_hash_get_current_key_ex(Z_ARRVAL_P(matches), &key, &keylen, &idx, 0, &pos);
        
        if (type == HASH_KEY_IS_STRING && zend_hash_get_current_data_ex(Z_ARRVAL_P(matches), (void**)&value, &pos) == SUCCESS) {
            MAKE_STD_ZVAL(copy);
            
            if (*(Z_STRVAL_PP(value)) == '/') {
                MAKE_STD_ZVAL(tokens);
                array_init(tokens);
                array_init(copy);
                php_explode(delim, *value, tokens, 100);
                zend_hash_index_del(Z_ARRVAL_P(tokens), 0);
                
                zend_hash_internal_pointer_reset_ex(Z_ARRVAL_P(tokens), &pos1);
                while (zend_hash_get_current_data_ex(Z_ARRVAL_P(tokens), (void **)&token, &pos1) == SUCCESS) {
                    zval_add_ref(token);
                    zend_hash_next_index_insert(Z_ARRVAL_P(copy), token, sizeof(zval *), NULL);
                    zend_hash_move_forward_ex(Z_ARRVAL_P(tokens), &pos1);
                }                
            } else {
                COPY_PZVAL_TO_ZVAL(*copy, *value);
            }

            add_assoc_zval(args, key, copy);
        }
    }
    
    fnargs[0] = &args;
    
    if (Z_TYPE_P(callback) == IS_STRING) {
        call_user_function_ex(EG(function_table), NULL, callback, ret_val, 1, fnargs, 0, NULL TSRMLS_CC);
    } else if (Z_TYPE_P(callback) == IS_ARRAY) {
        zval **object;
        zval **method;
        
        zend_hash_index_find(Z_ARRVAL_P(callback), 0, (void **) &object);
        zend_hash_index_find(Z_ARRVAL_P(callback), 1, (void **) &method);
        
        call_user_function_ex(EG(function_table), object, *method, ret_val, 1, fnargs, 0, NULL TSRMLS_CC);
    }
    
    zval_ptr_dtor(fnargs[0]);
}

static void handle(zval *this_ptr, zval *return_value, int return_value_used, char *path, int path_len)
{
    pcre_cache_entry  *pce;
    HashPosition       pos;
    zval             **routes;
    zval              *ret_val;
    zval             **route;
    zval             **expr;
    zval             **callback;
    zval              *matches;
    zval              *result;
    char              *method;
    int                found = 0;
    
    resolve_request_method(&method TSRMLS_CC);
    PROP(this_ptr, "routes", routes);
    
    for(zend_hash_internal_pointer_reset_ex(Z_ARRVAL_PP(routes), &pos);
        zend_hash_has_more_elements_ex(Z_ARRVAL_PP(routes), &pos) == SUCCESS && !found;
        zend_hash_move_forward_ex(Z_ARRVAL_PP(routes), &pos)) {
        
        if (zend_hash_get_current_data_ex(Z_ARRVAL_PP(routes), (void**)&route, &pos) == SUCCESS) {
            ARRVAL_PP(route, "#expr", expr);
            
            if ((pce = pcre_get_compiled_regex_cache(Z_STRVAL_PP(expr), Z_STRLEN_PP(expr) TSRMLS_CC)) != NULL) {
                MAKE_STD_ZVAL(result);
                MAKE_STD_ZVAL(matches);
                array_init(matches);
                
                php_pcre_match_impl(pce, path, path_len, result, matches, 0, 1, 0, 0 TSRMLS_CC);
                
                if (zend_hash_num_elements(Z_ARRVAL_P(matches)) > 0) {
                    if (GET_ARRVAL(route, method, callback)) {
                        invoke_route_callback(*callback, matches, &ret_val TSRMLS_CC);
                        
                        if (return_value_used) {
                            COPY_PZVAL_TO_ZVAL(*return_value, ret_val);
                        }
                        
                        zval_ptr_dtor(&ret_val);
                    } else {
                        throw_exception_ex(rest_unsupported_method_exception, 
                                           *route TSRMLS_CC,
                                           "There is no callback bound to specified HTTP method %s",
                                           method);
                        return;
                    }
                    
                    found = 1;
                }
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