dnl
dnl $Id: config.m4 299931 2010-05-29 04:55:04Z datibbaw $
dnl

PHP_ARG_WITH(rest, whether to enable rest support,
Make sure that the comment is aligned:
[  --with-rest[=CURLDIR]           Enable rest support])

if test "$PHP_REST" != "no"; then
  PHP_SUBST(REST_SHARED_LIBADD)

  PHP_NEW_EXTENSION(rest, rest.c rest_client.c rest_server.c, $ext_shared)
  CFLAGS="$CFLAGS -Wall -g"

  if test -r $PHP_REST/include/curl/easy.h; then
    CURL_DIR=$PHP_REST
  else
    AC_MSG_CHECKING(for cURL in default path)
    for i in /usr/local /usr; do
      if test -r $i/include/curl/easy.h; then
        CURL_DIR=$i
        AC_MSG_RESULT(found in $i)
        break
      fi
    done
  fi

  if test -z "$CURL_DIR"; then
    AC_MSG_RESULT(not found)
    AC_MSG_ERROR(Please reinstall the libcurl distribution -
    easy.h should be in <curl-dir>/include/curl/)
  fi
  
fi
