#!/bin/sh
for i in modsecurity-apache_2.5.9/rules/modsecurity_crs_[2345]*
do 
   v=`basename $i`
   v=${v#modsecurity_crs_}
   echo $v
   ./tools/2vcl.pl $i > vcl/breach/${v%.conf}.vcl
done
