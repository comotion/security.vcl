sub vcl_recv {
   set req.http.X-Sec-Module = "2vcl";
   ## RESPONSE_BODY, 
   # skipped   RESPONSE_BODY rx  <h2>Site Error<\/h2>.{0,20}<p>An error was encountered while publishing this resource\.
   ## RESPONSE_BODY, 
   # skipped   RESPONSE_BODY rx  \bThe error occurred in\b.{0,100}: line\b.{0,1000}\bColdFusion\b.*?\bStack Trace \(click to expand\)
   ## RESPONSE_BODY, 
   # skipped   RESPONSE_BODY rx  <b>Warning<\/b>.{0,100}?:.{0,1000}?\bon line\b
   ## RESPONSE_BODY, 
   # skipped   RESPONSE_BODY rx  \b403 Forbidden\b.*?\bInternet Security and Acceleration Server\b
   ## RESPONSE_BODY, 
   # skipped   RESPONSE_BODY rx  <o:documentproperties>
   ## RESPONSE_BODY, 
   # skipped   RESPONSE_BODY rx  \<\%
   ## RESPONSE_BODY, 
   # skipped   RESPONSE_BODY rx  (?:\b(?:(?:i(?:nterplay|hdr|d3)|m(?:ovi|thd)|r(?:ar!|iff)|(?:ex|jf)if|f(?:lv|ws)|varg|cws)\b|gif)|B(?:%pdf|\.ra)\b)
   ## RESPONSE_BODY, 
   # skipped   RESPONSE_BODY rx  <cf
   ## RESPONSE_BODY, 
   # skipped   RESPONSE_BODY rx  [a-z]:\\\\inetpub\b
   ## &GLOBAL, :alerted_970018_iisDefLoc
   # AC alerted_970018_iisDefLoc 
   # skipped  & GLOBAL eq alerted_970018_iisDefLoc 0
   ## RESPONSE_STATUS, 
   # skipped   RESPONSE_STATUS rx  ^5\d{2}$
   ## RESPONSE_BODY, 
   # skipped   RESPONSE_BODY rx  (?:Microsoft OLE DB Provider for SQL Server(?:<\/font>.{1,20}?error '800(?:04005|40e31)'.{1,40}?Timeout expired| \(0x80040e31\)<br>Timeout expired<br>)|<h1>internal server error<\/h1>.*?<h2>part of the server has crashed or it has a configuration error\.<\/h2>|cannot connect to the server: timed out)
   ## RESPONSE_STATUS, 
   # skipped   RESPONSE_STATUS rx  ^500$
   ## RESPONSE_BODY, 
   # skipped   RESPONSE_BODY rx  <title>JSP compile error<\/title>
   ## RESPONSE_BODY, 
   # skipped   RESPONSE_BODY rx  href\s?=[\s\"\']*[A-Za-z]\:\x5c([^\"\']+)
   ## TX, :1
   # AC 1 
   ## Rule: TX rx :1
   ## RESPONSE_BODY, 
   # skipped   RESPONSE_BODY pm  iframe
   ## RESPONSE_BODY, 
   # skipped   RESPONSE_BODY rx  <\W*iframe[^>]+?\b(?:width|height)\b\W*?=\W*?[\"']?[^\"'1-9]*?(?:(?:20|1?\d(?:\.\d*)?)(?![\d%.])|[0-3](?:\.\d*)?%)
   ## RESPONSE_BODY, 
   # skipped   RESPONSE_BODY rx  <\W*iframe[^>]+?\bstyle\W*?=\W*?[\"']?\W*?\bdisplay\b\W*?:\W*?\bnone\b
   ## RESPONSE_BODY, 
   # skipped   RESPONSE_BODY rx  (?i:<\s*IFRAME\s*?[^>]*?src=\"javascript:)
   ## RESPONSE_BODY, 
   # skipped   RESPONSE_BODY rx  (?i)(String\.fromCharCode\(.*?){4,}
   ## RESPONSE_BODY, 
   # skipped   RESPONSE_BODY rx  (?i)(eval\(.{0,15}unescape\()
   ## RESPONSE_BODY, 
   # skipped   RESPONSE_BODY rx  (?i)(var[^=]+=\s*unescape\s*;)
   ## RESPONSE_BODY, 
   # skipped   RESPONSE_BODY rx  (?i:%u0c0c%u0c0c|%u9090%u9090|%u4141%u4141)
   ## RESPONSE_BODY, 
   # skipped   RESPONSE_BODY pmFromFile  modsecurity_50_outbound_malware.data
   ## RESPONSE_BODY, 
   # skipped   RESPONSE_BODY pmFromFile  modsecurity_50_outbound.data
   ## RESPONSE_BODY, 
   # skipped   RESPONSE_BODY rx  \bwscript\.shell\b
   ## RESPONSE_BODY, 
   # skipped   RESPONSE_BODY rx  <jsp:
   ## RESPONSE_BODY, 
   # skipped   RESPONSE_BODY rx  \.addheader\b
   ## RESPONSE_BODY, 
   # skipped   RESPONSE_BODY rx  \bserver\.execute\b
   ## RESPONSE_BODY, 
   # skipped   RESPONSE_BODY rx  \bserver\.mappath\b
   ## RESPONSE_BODY, 
   # skipped   RESPONSE_BODY rx  \bresponse\.binarywrite\b
   ## RESPONSE_BODY, 
   # skipped   RESPONSE_BODY rx  \bserver\.createobject\b
   ## RESPONSE_BODY, 
   # skipped   RESPONSE_BODY rx  \.createtextfile\b
   ## RESPONSE_BODY, 
   # skipped   RESPONSE_BODY rx  \bwscript\.network\b
   ## RESPONSE_BODY, 
   # skipped   RESPONSE_BODY rx  \bvbscript\.encode\b
   ## RESPONSE_BODY, 
   # skipped   RESPONSE_BODY rx  \bserver\.htmlencode\b
   ## RESPONSE_BODY, 
   # skipped   RESPONSE_BODY rx  \bjavax\.servlet
   ## RESPONSE_BODY, 
   # skipped   RESPONSE_BODY rx  \bscripting\.filesystemobject\b
   ## RESPONSE_BODY, 
   # skipped   RESPONSE_BODY rx  \bserver\.urlencode\b
   ## RESPONSE_BODY, 
   # skipped   RESPONSE_BODY rx  \.getfile\b
   ## RESPONSE_BODY, 
   # skipped   RESPONSE_BODY rx  \.loadfromfile\b
   ## RESPONSE_BODY, 
   # skipped   RESPONSE_BODY rx  \bresponse\.write\b
   ## RESPONSE_BODY, 
   # skipped   RESPONSE_BODY rx  \bproc_open\b
   ## RESPONSE_BODY, 
   # skipped   RESPONSE_BODY rx  \bgzread\b
   ## RESPONSE_BODY, 
   # skipped   RESPONSE_BODY rx  \bftp_nb_fget\b
   ## RESPONSE_BODY, 
   # skipped   RESPONSE_BODY rx  \bftp_nb_get\b
   ## RESPONSE_BODY, 
   # skipped   RESPONSE_BODY rx  \bfscanf\b
   ## RESPONSE_BODY, 
   # skipped   RESPONSE_BODY rx  \breadfile\b
   ## RESPONSE_BODY, 
   # skipped   RESPONSE_BODY rx  \bfgetss\b
   ## RESPONSE_BODY, 
   # skipped   RESPONSE_BODY rx  \$_post\b
   ## RESPONSE_BODY, 
   # skipped   RESPONSE_BODY rx  \bsession_start\b
   ## RESPONSE_BODY, 
   # skipped   RESPONSE_BODY rx  \breaddir\b
   ## RESPONSE_BODY, 
   # skipped   RESPONSE_BODY rx  \bgzwrite\b
   ## RESPONSE_BODY, 
   # skipped   RESPONSE_BODY rx  \bscandir\b
   ## RESPONSE_BODY, 
   # skipped   RESPONSE_BODY rx  \bftp_get\b
   ## RESPONSE_BODY, 
   # skipped   RESPONSE_BODY rx  \bfread\b
   ## RESPONSE_BODY, 
   # skipped   RESPONSE_BODY rx  \breadgzfile\b
   ## RESPONSE_BODY, 
   # skipped   RESPONSE_BODY rx  \bftp_put\b
   ## RESPONSE_BODY, 
   # skipped   RESPONSE_BODY rx  \bfwrite\b
   ## RESPONSE_BODY, 
   # skipped   RESPONSE_BODY rx  \bgzencode\b
   ## RESPONSE_BODY, 
   # skipped   RESPONSE_BODY rx  \bfopen\b
   ## RESPONSE_BODY, 
   # skipped   RESPONSE_BODY rx  \$_session\b
   ## RESPONSE_BODY, 
   # skipped   RESPONSE_BODY rx  \bftp_nb_fput\b
   ## RESPONSE_BODY, 
   # skipped   RESPONSE_BODY rx  \bftp_fput\b
   ## RESPONSE_BODY, 
   # skipped   RESPONSE_BODY rx  \bgzcompress\b
   ## RESPONSE_BODY, 
   # skipped   RESPONSE_BODY rx  \bbzopen\b
   ## RESPONSE_BODY, 
   # skipped   RESPONSE_BODY rx  \bgzopen\b
   ## RESPONSE_BODY, 
   # skipped   RESPONSE_BODY rx  \bfgetc\b
   ## RESPONSE_BODY, 
   # skipped   RESPONSE_BODY rx  \bmove_uploaded_file\b
   ## RESPONSE_BODY, 
   # skipped   RESPONSE_BODY rx  \bftp_nb_put\b
   ## RESPONSE_BODY, 
   # skipped   RESPONSE_BODY rx  \bcall_user_func\b
   ## RESPONSE_BODY, 
   # skipped   RESPONSE_BODY rx  \$_get\b
   ## RESPONSE_BODY, 
   # skipped   RESPONSE_BODY rx  \bfgets\b
   ## RESPONSE_BODY, 
   # skipped   RESPONSE_BODY rx  \bftp_fget\b
   ## RESPONSE_BODY, 
   # skipped   RESPONSE_BODY rx  <\?(?!xml)
   ## RESPONSE_BODY, 
   # skipped   RESPONSE_BODY rx  (?:\b(?:(?:i(?:nterplay|hdr|d3)|m(?:ovi|thd)|r(?:ar!|iff)|(?:ex|jf)if|f(?:lv|ws)|varg|cws)\b|gif)|B(?:%pdf|\.ra)\b)
   ## RESPONSE_BODY, 
   # skipped   RESPONSE_BODY rx  \bThis summary was generated by.{0,100}?webcruncher\b
   ## RESPONSE_BODY, 
   # skipped   RESPONSE_BODY rx  \bThese statistics were produced by PeLAB\b
   ## RESPONSE_BODY, 
   # skipped   RESPONSE_BODY rx  \bThis summary was generated by.{0,100}?analog\b
   ## RESPONSE_BODY, 
   # skipped   RESPONSE_BODY rx  \bThis summary was generated by.{0,100}?Jware\b
   ## RESPONSE_BODY, 
   # skipped   RESPONSE_BODY rx  \bThis summary was generated by.{0,100}?wwwstat\b
   ## RESPONSE_BODY, 
   # skipped   RESPONSE_BODY rx  \bThis analysis was produced by.{0,100}?calamaris\b
   ## RESPONSE_BODY, 
   # skipped   RESPONSE_BODY rx  \bThis report was generated by WebLog\b
   ## RESPONSE_BODY, 
   # skipped   RESPONSE_BODY rx  \b[gG]enerated by.{0,100}?[Ww]ebalizer\b
   ## RESPONSE_BODY, 
   # skipped   RESPONSE_BODY rx  \bThese statistics were produced by getstats\b
   ## RESPONSE_BODY, 
   # skipped   RESPONSE_BODY rx  \bThis analysis was produced by.{0,100}?EasyStat\b
   ## RESPONSE_BODY, 
   # skipped   RESPONSE_BODY rx  \bThis analysis was produced by.{0,100}?analog\b
   ## RESPONSE_BODY, 
   # skipped   RESPONSE_BODY rx  \bCould not find server \'\w+\' in sysservers\. execute sp_addlinkedserver\b
   ## RESPONSE_BODY, 
   # skipped   RESPONSE_BODY rx  \bSyntax error converting the \w+ value .*? to a column of data type\b
   ## RESPONSE_BODY, 
   # skipped   RESPONSE_BODY rx  \bORA-\d{5}\: |ORA-[0-9][0-9][0-9][0-9]|Oracle error|Oracle.*Driver|Warning.*Woci_.*|Warning.*Wora_.*
   ## RESPONSE_BODY, 
   # skipped   RESPONSE_BODY rx  \bUnclosed quotation mark before the character string\b
   ## RESPONSE_BODY, 
   # skipped   RESPONSE_BODY rx  \[Microsoft\]\[ODBC |Driver.* SQL[-_ ]*Server|OLE DB.* SQL Server|(W|A)SQL Server.*Driver|Warning.*mssql_.*|(W|A)SQL Server.*[0-9a-fA-F]{8}|Exception Details:.*WSystem.Data.SqlClient.|Exception Details:.*WRoadhouse.Cms.
   ## RESPONSE_BODY, 
   # skipped   RESPONSE_BODY rx  \berror \'800a01b8\'
   ## RESPONSE_BODY, 
   # skipped   RESPONSE_BODY rx  \bYou have an error in your SQL syntax near \'
   ## RESPONSE_BODY, 
   # skipped   RESPONSE_BODY rx  \bmicrosoft jet database engine error \'8|Microsoft Access Driver|JET Database Engine|Access Database Engine
   ## RESPONSE_BODY, 
   # skipped   RESPONSE_BODY rx  \bselect list because it is not contained in an aggregate function and there is no GROUP BY clause\b
   ## RESPONSE_BODY, 
   # skipped   RESPONSE_BODY rx  \bUnable to connect to PostgreSQL server\:
   ## RESPONSE_BODY, 
   # skipped   RESPONSE_BODY rx  \bPostgreSQL query failed\:|PostgreSQL.*ERROR|Warning.*Wpg_.*|valid PostgreSQL result|Npgsql.
   ## RESPONSE_BODY, 
   # skipped   RESPONSE_BODY rx  \bsupplied argument is not a valid MS SQL\b
   ## RESPONSE_BODY, 
   # skipped   RESPONSE_BODY rx  \bsupplied argument is not a valid Oracle\b
   ## RESPONSE_BODY, 
   # skipped   RESPONSE_BODY rx  \bWarning: mysql_connect\(\)\:
   ## RESPONSE_BODY, 
   # skipped   RESPONSE_BODY rx  \bsupplied argument is not a valid ODBC\b
   ## RESPONSE_BODY, 
   # skipped   RESPONSE_BODY rx  \bMicrosoft OLE DB Provider for .{0,30} [eE]rror '
   ## RESPONSE_BODY, 
   # skipped   RESPONSE_BODY rx  \bSQL Server does not exist or access denied\b
   ## RESPONSE_BODY, 
   # skipped   RESPONSE_BODY rx  \bEither BOF or EOF is True, or the current record has been deleted(. Requested|; the operation)\b
   ## RESPONSE_BODY, 
   # skipped   RESPONSE_BODY rx  \bcannot take a \w+ data type as an argument\.
   ## RESPONSE_BODY, 
   # skipped   RESPONSE_BODY rx  \bselect list because it is not contained in either an aggregate function or the GROUP BY clause\b
   ## RESPONSE_BODY, 
   # skipped   RESPONSE_BODY rx  \bThe column prefix .{0,50}? does not match with a table name or alias name used in the query\b
   ## RESPONSE_BODY, 
   # skipped   RESPONSE_BODY rx  \bsupplied argument is not a valid PostgreSQL result\b
   ## RESPONSE_BODY, 
   # skipped   RESPONSE_BODY rx  \bYou have an error in your SQL syntax
   ## RESPONSE_BODY, 
   # skipped   RESPONSE_BODY rx  \bsupplied argument is not a valid MySQL\b
   ## RESPONSE_BODY, 
   # skipped   RESPONSE_BODY rx  SQL syntax.*MySQL|Warning.*mysql_.*|valid MySQL result|MySqlClient.|SQLite/JDBCDriver|SQLite.Exception|System.Data.SQLite.SQLiteException|Warning.*sqlite_.*|Warning.*SQLite3::
   ## RESPONSE_BODY, 
   # skipped   RESPONSE_BODY rx  \bincorrect syntax near (?:\'|the\b|\@\@error\b)
   ## RESPONSE_BODY, 
   # skipped   RESPONSE_BODY rx  \<b\>Version Information\:\<\/b\>(?:&nbsp;|\s)Microsoft \.NET Framework Version\:
   ## RESPONSE_BODY, 
   # skipped   RESPONSE_BODY rx  >error \'ASP\b
   ## RESPONSE_BODY, 
   # skipped   RESPONSE_BODY rx  \berror \'800
   ## RESPONSE_BODY, 
   # skipped   RESPONSE_BODY rx  \<b\>Version Information\:\<\/b\>(?:&nbsp;|\s)ASP\.NET Version\:
   ## RESPONSE_BODY, 
   # skipped   RESPONSE_BODY rx  \bA trappable error occurred in an external object\. The script cannot continue running\b
   ## RESPONSE_BODY, 
   # skipped   RESPONSE_BODY rx  \bMicrosoft VBScript runtime Error\b
   ## RESPONSE_BODY, 
   # skipped   RESPONSE_BODY rx  \bMicrosoft VBScript compilation \(0x8\b
   ## RESPONSE_BODY, 
   # skipped   RESPONSE_BODY rx  /[Ee]rror[Mm]essage\.aspx\?[Ee]rror\b
   ## RESPONSE_BODY, 
   # skipped   RESPONSE_BODY rx  \bMicrosoft VBScript runtime \(0x8\b
   ## RESPONSE_BODY, 
   # skipped   RESPONSE_BODY rx  \bObject required\: \'
   ## RESPONSE_BODY, 
   # skipped   RESPONSE_BODY rx  \bADODB\.Command\b.{0,100}?\bApplication uses a value of the wrong type for the current operation\b
   ## RESPONSE_BODY, 
   # skipped   RESPONSE_BODY rx  /[Ee]rror[Mm]essage\.asp\?[Ee]rror\b
   ## RESPONSE_BODY, 
   # skipped   RESPONSE_BODY rx  \bADODB\.Command\b.{0,100}?\berror\'
   ## RESPONSE_BODY, 
   # skipped   RESPONSE_BODY rx  \bMicrosoft VBScript compilation error\b
   ## RESPONSE_BODY, 
   # skipped   RESPONSE_BODY rx  \bServer Error in.{0,50}?\bApplication\b
   ## RESPONSE_STATUS, 
   # skipped   RESPONSE_STATUS rx  ^404$
   ## RESPONSE_BODY, 
   # skipped   RESPONSE_BODY rx  >[To Parent Directory]</[Aa]><br>
   ## RESPONSE_BODY, 
   # skipped   RESPONSE_BODY rx  <TITLE>Index of.*?<H1>Index of
   ## RESPONSE_BODY, 
   # skipped   RESPONSE_BODY rx  <title>Index of.*?<h1>Index of
}

