#include <string.h>
#include "php_rest.h"

static void handle_exception(char *message, zval *route);
static void normalize_path(char *input, zval **path TSRMLS_DC);
static char *normalize_token(char *key, char *value);
static void parse_path(char *path, HashTable *pathargs TSRMLS_DC);
static void add_route(zval *this_ptr, zval *route TSRMLS_DC);
static void resolve_request_method(char **method TSRMLS_DC);
static void invoke_route_callback(zval *callback, zval *matches, zval **ret_val TSRMLS_DC);
static void route(zval *this_ptr, zval *return_value, int return_value_used, char *path, int path_len);

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
    zval  *route;
    
    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "a/", &route) != SUCCESS) {
		RETURN_FALSE;
	}
    
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
    
    route(this_ptr, return_value, return_value_used, path, path_len);
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
    
    GET_HTVAL(EG(active_symbol_table), "_SERVER", server);
    GET_HTVAL(Z_ARRVAL_PP(server), "REQUEST_URI", value);
    
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
    
    route(this_ptr, return_value, return_value_used, Z_STRVAL_P(req_uri), Z_STRLEN_P(req_uri));
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
    
    GET_HTVAL(EG(active_symbol_table), "_GET", get);
    
    if (GET_HTVAL(Z_ARRVAL_PP(get), param_name, tmp)) {
        normalize_path(Z_STRVAL_PP(tmp), &path);
        route(this_ptr, return_value, return_value_used, Z_STRVAL_P(path), Z_STRLEN_P(path));
    }
}

static void handle_exception(char *message, zval *route) 
{
    zend_class_entry *parent = (zend_class_entry *) zend_exception_get_default();
    zend_class_entry *base = rest_route_exception;
    zval             *exception;
    
    MAKE_STD_ZVAL(exception);
    object_init_ex(exception, base);
    
    zend_update_property(parent, exception, "route", sizeof("route") - 1, route TSRMLS_CC);
    zend_update_property_string(parent, exception, "message", sizeof("message") - 1, message TSRMLS_CC);
    
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
    smart_str   uri = {0};
    int         i;
    int         has_callback = 0;
    
    for (i = 0; i < 4; i++) {
        if ((has_callback = zend_hash_exists(Z_ARRVAL_P(route), user_callback_keys[i], strlen(user_callback_keys[i]) + 1))) {
            break;
        }
    }
    
    if (!has_callback) {
        handle_exception("Route doesn't contain callback!", route);
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
    
    if (GET_HTVAL(Z_ARRVAL_P(copy), "#path", tmp)) {
        normalize_path(Z_STRVAL_PP(tmp), &path);
        parse_path(Z_STRVAL_P(path), pathargs TSRMLS_CC);
    }
    
    smart_str_appends(&uri, "~^");
    rest_url_append_uri(Z_STRVAL_P(path), pathargs, &uri, 0 TSRMLS_CC);
    smart_str_appends(&uri, "$~");
    
    smart_str_0(&uri);
    add_assoc_stringl(copy, "#expr", uri.c, uri.len, 1);
    smart_str_free(&uri);
    
    GET_PROP(this_ptr, "routes", routes);
    zend_hash_next_index_insert(Z_ARRVAL_PP(routes), &copy, sizeof(zval *), NULL);
}

static void resolve_request_method(char **method TSRMLS_DC)
{
    zval **server;
    zval **req_method;
    smart_str resolved = {0};
    
    GET_HTVAL(EG(active_symbol_table), "_SERVER", server);
    GET_ARRVAL(server, "REQUEST_METHOD", req_method);
    
    smart_str_appends(&resolved, "#");
    
    if (IS_POST(Z_STRVAL_PP(req_method))) {
        
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
    
    if (Z_TYPE_P(callback) == IS_STRING) {
        convert_to_string(callback);
        fnargs[0] = &args;
        
        call_user_function_ex(EG(function_table), NULL, callback, ret_val, 1, fnargs, 0, NULL TSRMLS_CC);
        
        efree(args);
    }
}

static void route(zval *this_ptr, zval *return_value, int return_value_used, char *path, int path_len)
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
    
    GET_PROP(this_ptr, "routes", routes);
    
    for(zend_hash_internal_pointer_reset_ex(Z_ARRVAL_PP(routes), &pos);
        zend_hash_has_more_elements_ex(Z_ARRVAL_PP(routes), &pos) == SUCCESS && !found;
        zend_hash_move_forward_ex(Z_ARRVAL_PP(routes), &pos)) {
        
        if (zend_hash_get_current_data_ex(Z_ARRVAL_PP(routes), (void**)&route, &pos) == SUCCESS) {
            GET_ARRVAL(route, method, callback);
            GET_ARRVAL(route, "#expr", expr);
            
            if ((pce = pcre_get_compiled_regex_cache(Z_STRVAL_PP(expr), Z_STRLEN_PP(expr) TSRMLS_CC)) != NULL) {
                MAKE_STD_ZVAL(result);
                MAKE_STD_ZVAL(matches);
                array_init(matches);
                
                php_pcre_match_impl(pce, path, path_len, result, matches, 0, 1, 0, 0 TSRMLS_CC);
                
                if (zend_hash_num_elements(Z_ARRVAL_P(matches)) > 0) {
                    invoke_route_callback(*callback, matches, &ret_val TSRMLS_CC);
                    
                    if (return_value_used) {
                        COPY_PZVAL_TO_ZVAL(*return_value, ret_val);
                    }
                    
                    found = 1;
                }
            }
        }
    }
    
    efree(method);
}