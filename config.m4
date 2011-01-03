dnl $Id$
dnl config.m4 for extension rest

dnl Comments in this file start with the string 'dnl'.
dnl Remove where necessary. This file will not work
dnl without editing.

dnl If your extension references something external, use with:

dnl PHP_ARG_WITH(rest, for rest support,
dnl Make sure that the comment is aligned:
dnl [  --with-rest             Include rest support])

dnl Otherwise use enable:

PHP_ARG_ENABLE(rest, whether to enable rest support,
Make sure that the comment is aligned:
[  --enable-rest           Enable rest support])

if test "$PHP_REST" != "no"; then
  dnl Write more examples of tests here...

  dnl # --with-rest -> check with-path
  dnl SEARCH_PATH="/usr/local /usr"     # you might want to change this
  dnl SEARCH_FOR="/include/rest.h"  # you most likely want to change this
  dnl if test -r $PHP_REST/$SEARCH_FOR; then # path given as parameter
  dnl   REST_DIR=$PHP_REST
  dnl else # search default path list
  dnl   AC_MSG_CHECKING([for rest files in default path])
  dnl   for i in $SEARCH_PATH ; do
  dnl     if test -r $i/$SEARCH_FOR; then
  dnl       REST_DIR=$i
  dnl       AC_MSG_RESULT(found in $i)
  dnl     fi
  dnl   done
  dnl fi
  dnl
  dnl if test -z "$REST_DIR"; then
  dnl   AC_MSG_RESULT([not found])
  dnl   AC_MSG_ERROR([Please reinstall the rest distribution])
  dnl fi

  dnl # --with-rest -> add include path
  dnl PHP_ADD_INCLUDE($REST_DIR/include)

  dnl # --with-rest -> check for lib and symbol presence
  dnl LIBNAME=rest # you may want to change this
  dnl LIBSYMBOL=rest # you most likely want to change this 

  dnl PHP_CHECK_LIBRARY($LIBNAME,$LIBSYMBOL,
  dnl [
  dnl   PHP_ADD_LIBRARY_WITH_PATH($LIBNAME, $REST_DIR/lib, REST_SHARED_LIBADD)
  dnl   AC_DEFINE(HAVE_RESTLIB,1,[ ])
  dnl ],[
  dnl   AC_MSG_ERROR([wrong rest lib version or lib not found])
  dnl ],[
  dnl   -L$REST_DIR/lib -lm
  dnl ])
  dnl
  PHP_SUBST(REST_SHARED_LIBADD)

  PHP_NEW_EXTENSION(rest, rest.c rest_client.c rest_server.c, $ext_shared)
fi
