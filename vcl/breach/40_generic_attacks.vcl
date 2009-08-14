sub vcl_recv {
   set req.http.X-Sec-Module = "2vcl";
   ## REQUEST_FILENAME, 
   # skipped   REQUEST_FILENAME pm  set-cookie .cookie
   ## ARGS, 
   # skipped   ARGS pm  set-cookie .cookie
   ## ARGS_NAMES, 
   # skipped   ARGS_NAMES pm  set-cookie .cookie
   ## REQUEST_HEADERS, 
   # skipped   REQUEST_HEADERS pm  set-cookie .cookie
   ## XML, :/*|
   # AC /*| 
   # skipped   XML pm /*| set-cookie .cookie
   ## !REQUEST_HEADERS, :Referer
   # AC Referer 
   # skipped !  REQUEST_HEADERS pm Referer set-cookie .cookie
   ## REQUEST_FILENAME, 
   ## Rule: REQUEST_FILENAME rx :
   if(req.url ~ "(\.cookie\b.*?;\W*?(expires|domain)\W*?=|\bhttp-equiv\W+set-cookie\b)"){
      set req.http.X-Sec-RuleInfo = "Session Fixation";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SESSION_FIXATION";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "950009";
      call sec_sev1;
   }
   ## ARGS, 
   ## Rule: ARGS rx :
   if(req.url ~ "(\.cookie\b.*?;\W*?(expires|domain)\W*?=|\bhttp-equiv\W+set-cookie\b)"){
      set req.http.X-Sec-RuleInfo = "Session Fixation";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SESSION_FIXATION";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "950009";
      call sec_sev1;
   }
   ## ARGS_NAMES, 
   ## Rule: ARGS_NAMES rx :
   if(req.url ~ "(\.cookie\b.*?;\W*?(expires|domain)\W*?=|\bhttp-equiv\W+set-cookie\b)"){
      set req.http.X-Sec-RuleInfo = "Session Fixation";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SESSION_FIXATION";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "950009";
      call sec_sev1;
   }
   ## REQUEST_HEADERS, 
   # skipped   REQUEST_HEADERS rx  (\.cookie\b.*?;\W*?(expires|domain)\W*?=|\bhttp-equiv\W+set-cookie\b)
   ## XML, :/*|
   # AC /*| 
   # skipped   XML rx /*| (\.cookie\b.*?;\W*?(expires|domain)\W*?=|\bhttp-equiv\W+set-cookie\b)
   ## !REQUEST_HEADERS, :Referer
   # AC Referer 
   ## Rule: REQUEST_HEADERS rx :Referer
   # AAA Referer
   if(req.http.Referer ~ "(\.cookie\b.*?;\W*?(expires|domain)\W*?=|\bhttp-equiv\W+set-cookie\b)"){
      set req.http.X-Sec-RuleInfo = "Session Fixation";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SESSION_FIXATION";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959009";
      call sec_sev1;
   }
   ## REQUEST_FILENAME, 
   # skipped   REQUEST_FILENAME pm  sys.user_triggers sys.user_objects @@spid msysaces instr sys.user_views sys.tab charindex sys.user_catalog constraint_type locate select msysobjects attnotnull sys.user_tables sys.user_tab_columns sys.user_constraints waitfor mysql.user sys.all_tables msysrelationships msyscolumns msysqueries
   ## ARGS, 
   # skipped   ARGS pm  sys.user_triggers sys.user_objects @@spid msysaces instr sys.user_views sys.tab charindex sys.user_catalog constraint_type locate select msysobjects attnotnull sys.user_tables sys.user_tab_columns sys.user_constraints waitfor mysql.user sys.all_tables msysrelationships msyscolumns msysqueries
   ## ARGS_NAMES, 
   # skipped   ARGS_NAMES pm  sys.user_triggers sys.user_objects @@spid msysaces instr sys.user_views sys.tab charindex sys.user_catalog constraint_type locate select msysobjects attnotnull sys.user_tables sys.user_tab_columns sys.user_constraints waitfor mysql.user sys.all_tables msysrelationships msyscolumns msysqueries
   ## REQUEST_HEADERS, 
   # skipped   REQUEST_HEADERS pm  sys.user_triggers sys.user_objects @@spid msysaces instr sys.user_views sys.tab charindex sys.user_catalog constraint_type locate select msysobjects attnotnull sys.user_tables sys.user_tab_columns sys.user_constraints waitfor mysql.user sys.all_tables msysrelationships msyscolumns msysqueries
   ## XML, :/*|
   # AC /*| 
   # skipped   XML pm /*| sys.user_triggers sys.user_objects @@spid msysaces instr sys.user_views sys.tab charindex sys.user_catalog constraint_type locate select msysobjects attnotnull sys.user_tables sys.user_tab_columns sys.user_constraints waitfor mysql.user sys.all_tables msysrelationships msyscolumns msysqueries
   ## !REQUEST_HEADERS, :Referer
   # AC Referer 
   # skipped !  REQUEST_HEADERS pm Referer sys.user_triggers sys.user_objects @@spid msysaces instr sys.user_views sys.tab charindex sys.user_catalog constraint_type locate select msysobjects attnotnull sys.user_tables sys.user_tab_columns sys.user_constraints waitfor mysql.user sys.all_tables msysrelationships msyscolumns msysqueries
   ## REQUEST_FILENAME, 
   ## Rule: REQUEST_FILENAME rx :
   if(req.url ~ "(\b((s(ys\.(user_((t(ab(_column|le)|rigger)|object|view)s|c(onstraints|atalog))|all_tables|tab)|elect\b.{0,40}\b(substring|ascii|user))|m(sys((queri|ac)e|relationship|column|object)s|ysql\.user)|c(onstraint_type|harindex)|waitfor\b\W*?\bdelay|attnotnull)\b|(locate|instr)\W+\()|\@\@spid\b)"){
      set req.http.X-Sec-RuleInfo = "Blind SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "950007";
      call sec_sev1;
   }
   ## ARGS, 
   ## Rule: ARGS rx :
   if(req.url ~ "(\b((s(ys\.(user_((t(ab(_column|le)|rigger)|object|view)s|c(onstraints|atalog))|all_tables|tab)|elect\b.{0,40}\b(substring|ascii|user))|m(sys((queri|ac)e|relationship|column|object)s|ysql\.user)|c(onstraint_type|harindex)|waitfor\b\W*?\bdelay|attnotnull)\b|(locate|instr)\W+\()|\@\@spid\b)"){
      set req.http.X-Sec-RuleInfo = "Blind SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "950007";
      call sec_sev1;
   }
   ## ARGS_NAMES, 
   ## Rule: ARGS_NAMES rx :
   if(req.url ~ "(\b((s(ys\.(user_((t(ab(_column|le)|rigger)|object|view)s|c(onstraints|atalog))|all_tables|tab)|elect\b.{0,40}\b(substring|ascii|user))|m(sys((queri|ac)e|relationship|column|object)s|ysql\.user)|c(onstraint_type|harindex)|waitfor\b\W*?\bdelay|attnotnull)\b|(locate|instr)\W+\()|\@\@spid\b)"){
      set req.http.X-Sec-RuleInfo = "Blind SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "950007";
      call sec_sev1;
   }
   ## REQUEST_HEADERS, 
   # skipped   REQUEST_HEADERS rx  (\b((s(ys\.(user_((t(ab(_column|le)|rigger)|object|view)s|c(onstraints|atalog))|all_tables|tab)|elect\b.{0,40}\b(substring|ascii|user))|m(sys((queri|ac)e|relationship|column|object)s|ysql\.user)|c(onstraint_type|harindex)|waitfor\b\W*?\bdelay|attnotnull)\b|(locate|instr)\W+\()|\@\@spid\b)
   ## XML, :/*|
   # AC /*| 
   # skipped   XML rx /*| (\b((s(ys\.(user_((t(ab(_column|le)|rigger)|object|view)s|c(onstraints|atalog))|all_tables|tab)|elect\b.{0,40}\b(substring|ascii|user))|m(sys((queri|ac)e|relationship|column|object)s|ysql\.user)|c(onstraint_type|harindex)|waitfor\b\W*?\bdelay|attnotnull)\b|(locate|instr)\W+\()|\@\@spid\b)
   ## !REQUEST_HEADERS, :Referer
   # AC Referer 
   ## Rule: REQUEST_HEADERS rx :Referer
   # AAA Referer
   if(req.http.Referer ~ "(\b((s(ys\.(user_((t(ab(_column|le)|rigger)|object|view)s|c(onstraints|atalog))|all_tables|tab)|elect\b.{0,40}\b(substring|ascii|user))|m(sys((queri|ac)e|relationship|column|object)s|ysql\.user)|c(onstraint_type|harindex)|waitfor\b\W*?\bdelay|attnotnull)\b|(locate|instr)\W+\()|\@\@spid\b)"){
      set req.http.X-Sec-RuleInfo = "Blind SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959007";
      call sec_sev1;
   }
   ## REQUEST_FILENAME, 
   # skipped   REQUEST_FILENAME pm  substr xtype textpos all_objects rownum sysfilegroups sysprocesses user_group sysobjects user_tables systables pg_attribute user_users user_password column_id attrelid user_tab_columns table_name pg_class user_constraints user_objects object_type dba_users sysconstraints mb_users column_name atttypid object_id substring syscat user_ind_columns sysibm syscolumns sysdba object_name
   ## ARGS, 
   # skipped   ARGS pm  substr xtype textpos all_objects rownum sysfilegroups sysprocesses user_group sysobjects user_tables systables pg_attribute user_users user_password column_id attrelid user_tab_columns table_name pg_class user_constraints user_objects object_type dba_users sysconstraints mb_users column_name atttypid object_id substring syscat user_ind_columns sysibm syscolumns sysdba object_name
   ## REQUEST_HEADERS, 
   # skipped   REQUEST_HEADERS pm  substr xtype textpos all_objects rownum sysfilegroups sysprocesses user_group sysobjects user_tables systables pg_attribute user_users user_password column_id attrelid user_tab_columns table_name pg_class user_constraints user_objects object_type dba_users sysconstraints mb_users column_name atttypid object_id substring syscat user_ind_columns sysibm syscolumns sysdba object_name
   ## XML, :/*|
   # AC /*| 
   # skipped   XML pm /*| substr xtype textpos all_objects rownum sysfilegroups sysprocesses user_group sysobjects user_tables systables pg_attribute user_users user_password column_id attrelid user_tab_columns table_name pg_class user_constraints user_objects object_type dba_users sysconstraints mb_users column_name atttypid object_id substring syscat user_ind_columns sysibm syscolumns sysdba object_name
   ## !REQUEST_HEADERS, :Referer
   # AC Referer 
   # skipped !  REQUEST_HEADERS pm Referer substr xtype textpos all_objects rownum sysfilegroups sysprocesses user_group sysobjects user_tables systables pg_attribute user_users user_password column_id attrelid user_tab_columns table_name pg_class user_constraints user_objects object_type dba_users sysconstraints mb_users column_name atttypid object_id substring syscat user_ind_columns sysibm syscolumns sysdba object_name
   ## REQUEST_FILENAME, 
   ## Rule: REQUEST_FILENAME rx :
   if(req.url ~ "\b((s(ys(((process|tabl)e|filegroup|object)s|c(o(nstraint|lumn)s|at)|dba|ibm)|ubstr(ing)?)|user_(((constrain|objec)t|tab(_column|le)|ind_column|user)s|password|group)|a(tt(rel|typ)id|ll_objects)|object_((nam|typ)e|id)|pg_(attribute|class)|column_(name|id)|(dba|mb)_users|xtype\W+\bchar|rownum)\b|t(able_name\b|extpos\W+\())"){
      set req.http.X-Sec-RuleInfo = "Blind SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "950904";
      call sec_sev1;
   }
   ## ARGS, 
   ## Rule: ARGS rx :
   if(req.url ~ "\b((s(ys(((process|tabl)e|filegroup|object)s|c(o(nstraint|lumn)s|at)|dba|ibm)|ubstr(ing)?)|user_(((constrain|objec)t|tab(_column|le)|ind_column|user)s|password|group)|a(tt(rel|typ)id|ll_objects)|object_((nam|typ)e|id)|pg_(attribute|class)|column_(name|id)|(dba|mb)_users|xtype\W+\bchar|rownum)\b|t(able_name\b|extpos\W+\())"){
      set req.http.X-Sec-RuleInfo = "Blind SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "950904";
      call sec_sev1;
   }
   ## REQUEST_HEADERS, 
   # skipped   REQUEST_HEADERS rx  \b((s(ys(((process|tabl)e|filegroup|object)s|c(o(nstraint|lumn)s|at)|dba|ibm)|ubstr(ing)?)|user_(((constrain|objec)t|tab(_column|le)|ind_column|user)s|password|group)|a(tt(rel|typ)id|ll_objects)|object_((nam|typ)e|id)|pg_(attribute|class)|column_(name|id)|(dba|mb)_users|xtype\W+\bchar|rownum)\b|t(able_name\b|extpos\W+\())
   ## XML, :/*|
   # AC /*| 
   # skipped   XML rx /*| \b((s(ys(((process|tabl)e|filegroup|object)s|c(o(nstraint|lumn)s|at)|dba|ibm)|ubstr(ing)?)|user_(((constrain|objec)t|tab(_column|le)|ind_column|user)s|password|group)|a(tt(rel|typ)id|ll_objects)|object_((nam|typ)e|id)|pg_(attribute|class)|column_(name|id)|(dba|mb)_users|xtype\W+\bchar|rownum)\b|t(able_name\b|extpos\W+\())
   ## !REQUEST_HEADERS, :Referer
   # AC Referer 
   ## Rule: REQUEST_HEADERS rx :Referer
   # AAA Referer
   if(req.http.Referer ~ "\b((s(ys(((process|tabl)e|filegroup|object)s|c(o(nstraint|lumn)s|at)|dba|ibm)|ubstr(ing)?)|user_(((constrain|objec)t|tab(_column|le)|ind_column|user)s|password|group)|a(tt(rel|typ)id|ll_objects)|object_((nam|typ)e|id)|pg_(attribute|class)|column_(name|id)|(dba|mb)_users|xtype\W+\bchar|rownum)\b|t(able_name\b|extpos\W+\())"){
      set req.http.X-Sec-RuleInfo = "Blind SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959904";
      call sec_sev1;
   }
   ## REQUEST_FILENAME, 
   # skipped   REQUEST_FILENAME pm  insert xp_enumdsn infile openrowset nvarchar autonomous_transaction print data_type or outfile inner shutdown tbcreator @@version xp_filelist sp_prepare sql_longvarchar xp_regenumkeys xp_loginconfig xp_dirtree ifnull sp_addextendedproc xp_regaddmultistring delete sp_sqlexec and sp_oacreate sp_execute cast xp_ntsec xp_regdeletekey drop varchar xp_execresultset having utl_file xp_regenumvalues xp_terminate xp_availablemedia xp_regdeletevalue dumpfile isnull sql_variant select 'sa' xp_regremovemultistring xp_makecab 'msdasql' xp_cmdshell openquery sp_executesql 'sqloledb' dbms_java 'dbo' utl_http sp_makewebtask benchmark xp_regread xp_regwrite
   ## ARGS, 
   # skipped   ARGS pm  insert xp_enumdsn infile openrowset nvarchar autonomous_transaction print data_type or outfile inner shutdown tbcreator @@version xp_filelist sp_prepare sql_longvarchar xp_regenumkeys xp_loginconfig xp_dirtree ifnull sp_addextendedproc xp_regaddmultistring delete sp_sqlexec and sp_oacreate sp_execute cast xp_ntsec xp_regdeletekey drop varchar xp_execresultset having utl_file xp_regenumvalues xp_terminate xp_availablemedia xp_regdeletevalue dumpfile isnull sql_variant select 'sa' xp_regremovemultistring xp_makecab 'msdasql' xp_cmdshell openquery sp_executesql 'sqloledb' dbms_java 'dbo' utl_http sp_makewebtask benchmark xp_regread xp_regwrite
   ## ARGS_NAMES, 
   # skipped   ARGS_NAMES pm  insert xp_enumdsn infile openrowset nvarchar autonomous_transaction print data_type or outfile inner shutdown tbcreator @@version xp_filelist sp_prepare sql_longvarchar xp_regenumkeys xp_loginconfig xp_dirtree ifnull sp_addextendedproc xp_regaddmultistring delete sp_sqlexec and sp_oacreate sp_execute cast xp_ntsec xp_regdeletekey drop varchar xp_execresultset having utl_file xp_regenumvalues xp_terminate xp_availablemedia xp_regdeletevalue dumpfile isnull sql_variant select 'sa' xp_regremovemultistring xp_makecab 'msdasql' xp_cmdshell openquery sp_executesql 'sqloledb' dbms_java 'dbo' utl_http sp_makewebtask benchmark xp_regread xp_regwrite
   ## REQUEST_HEADERS, 
   # skipped   REQUEST_HEADERS pm  insert xp_enumdsn infile openrowset nvarchar autonomous_transaction print data_type or outfile inner shutdown tbcreator @@version xp_filelist sp_prepare sql_longvarchar xp_regenumkeys xp_loginconfig xp_dirtree ifnull sp_addextendedproc xp_regaddmultistring delete sp_sqlexec and sp_oacreate sp_execute cast xp_ntsec xp_regdeletekey drop varchar xp_execresultset having utl_file xp_regenumvalues xp_terminate xp_availablemedia xp_regdeletevalue dumpfile isnull sql_variant select 'sa' xp_regremovemultistring xp_makecab 'msdasql' xp_cmdshell openquery sp_executesql 'sqloledb' dbms_java 'dbo' utl_http sp_makewebtask benchmark xp_regread xp_regwrite
   ## XML, :/*|
   # AC /*| 
   # skipped   XML pm /*| insert xp_enumdsn infile openrowset nvarchar autonomous_transaction print data_type or outfile inner shutdown tbcreator @@version xp_filelist sp_prepare sql_longvarchar xp_regenumkeys xp_loginconfig xp_dirtree ifnull sp_addextendedproc xp_regaddmultistring delete sp_sqlexec and sp_oacreate sp_execute cast xp_ntsec xp_regdeletekey drop varchar xp_execresultset having utl_file xp_regenumvalues xp_terminate xp_availablemedia xp_regdeletevalue dumpfile isnull sql_variant select 'sa' xp_regremovemultistring xp_makecab 'msdasql' xp_cmdshell openquery sp_executesql 'sqloledb' dbms_java 'dbo' utl_http sp_makewebtask benchmark xp_regread xp_regwrite
   ## !REQUEST_HEADERS, :Referer
   # AC Referer 
   # skipped !  REQUEST_HEADERS pm Referer insert xp_enumdsn infile openrowset nvarchar autonomous_transaction print data_type or outfile inner shutdown tbcreator @@version xp_filelist sp_prepare sql_longvarchar xp_regenumkeys xp_loginconfig xp_dirtree ifnull sp_addextendedproc xp_regaddmultistring delete sp_sqlexec and sp_oacreate sp_execute cast xp_ntsec xp_regdeletekey drop varchar xp_execresultset having utl_file xp_regenumvalues xp_terminate xp_availablemedia xp_regdeletevalue dumpfile isnull sql_variant select 'sa' xp_regremovemultistring xp_makecab 'msdasql' xp_cmdshell openquery sp_executesql 'sqloledb' dbms_java 'dbo' utl_http sp_makewebtask benchmark xp_regread xp_regwrite
   ## REQUEST_FILENAME, 
   ## Rule: REQUEST_FILENAME rx :
   if(req.url ~ "(\b((s(elect\b(.{1,100}?\b((length|count|top)\b.{1,100}?\bfrom|from\b.{1,100}?\bwhere)|.*?\b(d(ump\b.*\bfrom|ata_type)|(to_(numbe|cha)|inst)r))|p_((addextendedpro|sqlexe)c|(oacreat|prepar)e|execute(sql)?|makewebtask)|ql_(longvarchar|variant))|xp_(reg(re(movemultistring|ad)|delete(value|key)|enum(value|key)s|addmultistring|write)|e(xecresultset|numdsn)|(terminat|dirtre)e|availablemedia|loginconfig|cmdshell|filelist|makecab|ntsec)|u(nion\b.{1,100}?\bselect|tl_(file|http))|group\b.*\bby\b.{1,100}?\bhaving|d(elete\b\W*?\bfrom|bms_java)|load\b\W*?\bdata\b.*\binfile|(n?varcha|tbcreato)r)\b|i(n(to\b\W*?\b(dump|out)file|sert\b\W*?\binto|ner\b\W*?\bjoin)\b|(f(\b\W*?\(\W*?\bbenchmark|null\b)|snull\b)\W*?\()|a(nd\b ?(\d{1,10}|[\'%22][^=]{1,10}[\'%22]) ?[=<>]+|utonomous_transaction\b)|o(r\b ?(\d{1,10}|[\'%22][^=]{1,10}[\'%22]) ?[=<>]+|pen(rowset|query)\b)|having\b ?(\d{1,10}|[\'%22][^=]{1,10}[\'%22]) ?[=<>]+|print\b\W*?\@\@|cast\b\W*?\()|(;\W*?\b(shutdown|drop)|\@\@version)\b|'(s(qloledb|a)|msdasql|dbo)')"){
      set req.http.X-Sec-RuleInfo = "SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "950001";
      call sec_sev1;
   }
   ## ARGS, 
   ## Rule: ARGS rx :
   if(req.url ~ "(\b((s(elect\b(.{1,100}?\b((length|count|top)\b.{1,100}?\bfrom|from\b.{1,100}?\bwhere)|.*?\b(d(ump\b.*\bfrom|ata_type)|(to_(numbe|cha)|inst)r))|p_((addextendedpro|sqlexe)c|(oacreat|prepar)e|execute(sql)?|makewebtask)|ql_(longvarchar|variant))|xp_(reg(re(movemultistring|ad)|delete(value|key)|enum(value|key)s|addmultistring|write)|e(xecresultset|numdsn)|(terminat|dirtre)e|availablemedia|loginconfig|cmdshell|filelist|makecab|ntsec)|u(nion\b.{1,100}?\bselect|tl_(file|http))|group\b.*\bby\b.{1,100}?\bhaving|d(elete\b\W*?\bfrom|bms_java)|load\b\W*?\bdata\b.*\binfile|(n?varcha|tbcreato)r)\b|i(n(to\b\W*?\b(dump|out)file|sert\b\W*?\binto|ner\b\W*?\bjoin)\b|(f(\b\W*?\(\W*?\bbenchmark|null\b)|snull\b)\W*?\()|a(nd\b ?(\d{1,10}|[\'%22][^=]{1,10}[\'%22]) ?[=<>]+|utonomous_transaction\b)|o(r\b ?(\d{1,10}|[\'%22][^=]{1,10}[\'%22]) ?[=<>]+|pen(rowset|query)\b)|having\b ?(\d{1,10}|[\'%22][^=]{1,10}[\'%22]) ?[=<>]+|print\b\W*?\@\@|cast\b\W*?\()|(;\W*?\b(shutdown|drop)|\@\@version)\b|'(s(qloledb|a)|msdasql|dbo)')"){
      set req.http.X-Sec-RuleInfo = "SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "950001";
      call sec_sev1;
   }
   ## ARGS_NAMES, 
   ## Rule: ARGS_NAMES rx :
   if(req.url ~ "(\b((s(elect\b(.{1,100}?\b((length|count|top)\b.{1,100}?\bfrom|from\b.{1,100}?\bwhere)|.*?\b(d(ump\b.*\bfrom|ata_type)|(to_(numbe|cha)|inst)r))|p_((addextendedpro|sqlexe)c|(oacreat|prepar)e|execute(sql)?|makewebtask)|ql_(longvarchar|variant))|xp_(reg(re(movemultistring|ad)|delete(value|key)|enum(value|key)s|addmultistring|write)|e(xecresultset|numdsn)|(terminat|dirtre)e|availablemedia|loginconfig|cmdshell|filelist|makecab|ntsec)|u(nion\b.{1,100}?\bselect|tl_(file|http))|group\b.*\bby\b.{1,100}?\bhaving|d(elete\b\W*?\bfrom|bms_java)|load\b\W*?\bdata\b.*\binfile|(n?varcha|tbcreato)r)\b|i(n(to\b\W*?\b(dump|out)file|sert\b\W*?\binto|ner\b\W*?\bjoin)\b|(f(\b\W*?\(\W*?\bbenchmark|null\b)|snull\b)\W*?\()|a(nd\b ?(\d{1,10}|[\'%22][^=]{1,10}[\'%22]) ?[=<>]+|utonomous_transaction\b)|o(r\b ?(\d{1,10}|[\'%22][^=]{1,10}[\'%22]) ?[=<>]+|pen(rowset|query)\b)|having\b ?(\d{1,10}|[\'%22][^=]{1,10}[\'%22]) ?[=<>]+|print\b\W*?\@\@|cast\b\W*?\()|(;\W*?\b(shutdown|drop)|\@\@version)\b|'(s(qloledb|a)|msdasql|dbo)')"){
      set req.http.X-Sec-RuleInfo = "SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "950001";
      call sec_sev1;
   }
   ## REQUEST_HEADERS, 
   # skipped   REQUEST_HEADERS rx  (\b((s(elect\b(.{1,100}?\b((length|count|top)\b.{1,100}?\bfrom|from\b.{1,100}?\bwhere)|.*?\b(d(ump\b.*\bfrom|ata_type)|(to_(numbe|cha)|inst)r))|p_((addextendedpro|sqlexe)c|(oacreat|prepar)e|execute(sql)?|makewebtask)|ql_(longvarchar|variant))|xp_(reg(re(movemultistring|ad)|delete(value|key)|enum(value|key)s|addmultistring|write)|e(xecresultset|numdsn)|(terminat|dirtre)e|availablemedia|loginconfig|cmdshell|filelist|makecab|ntsec)|u(nion\b.{1,100}?\bselect|tl_(file|http))|group\b.*\bby\b.{1,100}?\bhaving|d(elete\b\W*?\bfrom|bms_java)|load\b\W*?\bdata\b.*\binfile|(n?varcha|tbcreato)r)\b|i(n(to\b\W*?\b(dump|out)file|sert\b\W*?\binto|ner\b\W*?\bjoin)\b|(f(\b\W*?\(\W*?\bbenchmark|null\b)|snull\b)\W*?\()|a(nd\b ?(\d{1,10}|[\'%22][^=]{1,10}[\'%22]) ?[=<>]+|utonomous_transaction\b)|o(r\b ?(\d{1,10}|[\'%22][^=]{1,10}[\'%22]) ?[=<>]+|pen(rowset|query)\b)|having\b ?(\d{1,10}|[\'%22][^=]{1,10}[\'%22]) ?[=<>]+|print\b\W*?\@\@|cast\b\W*?\()|(;\W*?\b(shutdown|drop)|\@\@version)\b|'(s(qloledb|a)|msdasql|dbo)')
   ## XML, :/*|
   # AC /*| 
   # skipped   XML rx /*| (\b((s(elect\b(.{1,100}?\b((length|count|top)\b.{1,100}?\bfrom|from\b.{1,100}?\bwhere)|.*?\b(d(ump\b.*\bfrom|ata_type)|(to_(numbe|cha)|inst)r))|p_((addextendedpro|sqlexe)c|(oacreat|prepar)e|execute(sql)?|makewebtask)|ql_(longvarchar|variant))|xp_(reg(re(movemultistring|ad)|delete(value|key)|enum(value|key)s|addmultistring|write)|e(xecresultset|numdsn)|(terminat|dirtre)e|availablemedia|loginconfig|cmdshell|filelist|makecab|ntsec)|u(nion\b.{1,100}?\bselect|tl_(file|http))|group\b.*\bby\b.{1,100}?\bhaving|d(elete\b\W*?\bfrom|bms_java)|load\b\W*?\bdata\b.*\binfile|(n?varcha|tbcreato)r)\b|i(n(to\b\W*?\b(dump|out)file|sert\b\W*?\binto|ner\b\W*?\bjoin)\b|(f(\b\W*?\(\W*?\bbenchmark|null\b)|snull\b)\W*?\()|a(nd\b ?(\d{1,10}|[\'%22][^=]{1,10}[\'%22]) ?[=<>]+|utonomous_transaction\b)|o(r\b ?(\d{1,10}|[\'%22][^=]{1,10}[\'%22]) ?[=<>]+|pen(rowset|query)\b)|having\b ?(\d{1,10}|[\'%22][^=]{1,10}[\'%22]) ?[=<>]+|print\b\W*?\@\@|cast\b\W*?\()|(;\W*?\b(shutdown|drop)|\@\@version)\b|'(s(qloledb|a)|msdasql|dbo)')
   ## !REQUEST_HEADERS, :Referer
   # AC Referer 
   ## Rule: REQUEST_HEADERS rx :Referer
   # AAA Referer
   if(req.http.Referer ~ "(\b((s(elect\b(.{1,100}?\b((length|count|top)\b.{1,100}?\bfrom|from\b.{1,100}?\bwhere)|.*?\b(d(ump\b.*\bfrom|ata_type)|(to_(numbe|cha)|inst)r))|p_((addextendedpro|sqlexe)c|(oacreat|prepar)e|execute(sql)?|makewebtask)|ql_(longvarchar|variant))|xp_(reg(re(movemultistring|ad)|delete(value|key)|enum(value|key)s|addmultistring|write)|e(xecresultset|numdsn)|(terminat|dirtre)e|availablemedia|loginconfig|cmdshell|filelist|makecab|ntsec)|u(nion\b.{1,100}?\bselect|tl_(file|http))|group\b.*\bby\b.{1,100}?\bhaving|d(elete\b\W*?\bfrom|bms_java)|load\b\W*?\bdata\b.*\binfile|(n?varcha|tbcreato)r)\b|i(n(to\b\W*?\b(dump|out)file|sert\b\W*?\binto|ner\b\W*?\bjoin)\b|(f(\b\W*?\(\W*?\bbenchmark|null\b)|snull\b)\W*?\()|a(nd\b ?(\d{1,10}|[\'%22][^=]{1,10}[\'%22]) ?[=<>]+|utonomous_transaction\b)|o(r\b ?(\d{1,10}|[\'%22][^=]{1,10}[\'%22]) ?[=<>]+|pen(rowset|query)\b)|having\b ?(\d{1,10}|[\'%22][^=]{1,10}[\'%22]) ?[=<>]+|print\b\W*?\@\@|cast\b\W*?\()|(;\W*?\b(shutdown|drop)|\@\@version)\b|'(s(qloledb|a)|msdasql|dbo)')"){
      set req.http.X-Sec-RuleInfo = "SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959001";
      call sec_sev1;
   }
   ## REQUEST_FILENAME, 
   ## Rule: REQUEST_FILENAME rx :
   if(req.url ~ "\b(\d+) ?= ?\1\b|[\'%22](\w+)[\'%22] ?= ?[\'%22]\2\b"){
      set req.http.X-Sec-RuleInfo = "SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "950901";
      call sec_sev1;
   }
   ## ARGS, 
   ## Rule: ARGS rx :
   if(req.url ~ "\b(\d+) ?= ?\1\b|[\'%22](\w+)[\'%22] ?= ?[\'%22]\2\b"){
      set req.http.X-Sec-RuleInfo = "SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "950901";
      call sec_sev1;
   }
   ## ARGS_NAMES, 
   ## Rule: ARGS_NAMES rx :
   if(req.url ~ "\b(\d+) ?= ?\1\b|[\'%22](\w+)[\'%22] ?= ?[\'%22]\2\b"){
      set req.http.X-Sec-RuleInfo = "SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "950901";
      call sec_sev1;
   }
   ## REQUEST_HEADERS, 
   # skipped   REQUEST_HEADERS rx  \b(\d+) ?= ?\1\b|[\'%22](\w+)[\'%22] ?= ?[\'%22]\2\b
   ## XML, :/*|
   # AC /*| 
   # skipped   XML rx /*| \b(\d+) ?= ?\1\b|[\'%22](\w+)[\'%22] ?= ?[\'%22]\2\b
   ## !REQUEST_HEADERS, :Referer
   # AC Referer 
   ## Rule: REQUEST_HEADERS rx :Referer
   # AAA Referer
   if(req.http.Referer ~ "\b(\d+) ?= ?\1\b|[\'%22](\w+)[\'%22] ?= ?[\'%22]\2\b"){
      set req.http.X-Sec-RuleInfo = "SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959901";
      call sec_sev1;
   }
   ## REQUEST_FILENAME, 
   # skipped   REQUEST_FILENAME pm  user_objects object_type substr all_objects mb_users column_name rownum atttypid substring object_id user_group user_tables pg_attribute user_users column_id user_password attrelid object_name table_name pg_class
   ## ARGS, 
   # skipped   ARGS pm  user_objects object_type substr all_objects mb_users column_name rownum atttypid substring object_id user_group user_tables pg_attribute user_users column_id user_password attrelid object_name table_name pg_class
   ## REQUEST_HEADERS, 
   # skipped   REQUEST_HEADERS pm  user_objects object_type substr all_objects mb_users column_name rownum atttypid substring object_id user_group user_tables pg_attribute user_users column_id user_password attrelid object_name table_name pg_class
   ## XML, :/*|
   # AC /*| 
   # skipped   XML pm /*| user_objects object_type substr all_objects mb_users column_name rownum atttypid substring object_id user_group user_tables pg_attribute user_users column_id user_password attrelid object_name table_name pg_class
   ## !REQUEST_HEADERS, :Referer
   # AC Referer 
   # skipped !  REQUEST_HEADERS pm Referer user_objects object_type substr all_objects mb_users column_name rownum atttypid substring object_id user_group user_tables pg_attribute user_users column_id user_password attrelid object_name table_name pg_class
   ## REQUEST_FILENAME, 
   ## Rule: REQUEST_FILENAME rx :
   if(req.url ~ "\b(user_((object|table|user)s|password|group)|a(tt(rel|typ)id|ll_objects)|object_((nam|typ)e|id)|pg_(attribute|class)|column_(name|id)|substr(ing)?|table_name|mb_users|rownum)\b"){
      set req.http.X-Sec-RuleInfo = "SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "950906";
      call sec_sev1;
   }
   ## ARGS, 
   ## Rule: ARGS rx :
   if(req.url ~ "\b(user_((object|table|user)s|password|group)|a(tt(rel|typ)id|ll_objects)|object_((nam|typ)e|id)|pg_(attribute|class)|column_(name|id)|substr(ing)?|table_name|mb_users|rownum)\b"){
      set req.http.X-Sec-RuleInfo = "SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "950906";
      call sec_sev1;
   }
   ## REQUEST_HEADERS, 
   # skipped   REQUEST_HEADERS rx  \b(user_((object|table|user)s|password|group)|a(tt(rel|typ)id|ll_objects)|object_((nam|typ)e|id)|pg_(attribute|class)|column_(name|id)|substr(ing)?|table_name|mb_users|rownum)\b
   ## XML, :/*|
   # AC /*| 
   # skipped   XML rx /*| \b(user_((object|table|user)s|password|group)|a(tt(rel|typ)id|ll_objects)|object_((nam|typ)e|id)|pg_(attribute|class)|column_(name|id)|substr(ing)?|table_name|mb_users|rownum)\b
   ## !REQUEST_HEADERS, :Referer
   # AC Referer 
   ## Rule: REQUEST_HEADERS rx :Referer
   # AAA Referer
   if(req.http.Referer ~ "\b(user_((object|table|user)s|password|group)|a(tt(rel|typ)id|ll_objects)|object_((nam|typ)e|id)|pg_(attribute|class)|column_(name|id)|substr(ing)?|table_name|mb_users|rownum)\b"){
      set req.http.X-Sec-RuleInfo = "SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959906";
      call sec_sev1;
   }
   ## REQUEST_FILENAME, 
   ## Rule: REQUEST_FILENAME rx :
   if(req.url ~ "\b(coalesce\b|root\@)"){
      set req.http.X-Sec-RuleInfo = "SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "950908";
      call sec_sev1;
   }
   ## ARGS, 
   ## Rule: ARGS rx :
   if(req.url ~ "\b(coalesce\b|root\@)"){
      set req.http.X-Sec-RuleInfo = "SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "950908";
      call sec_sev1;
   }
   ## ARGS_NAMES, 
   ## Rule: ARGS_NAMES rx :
   if(req.url ~ "\b(coalesce\b|root\@)"){
      set req.http.X-Sec-RuleInfo = "SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "950908";
      call sec_sev1;
   }
   ## !REQUEST_HEADERS, :via
   # AC via 
   ## Rule: REQUEST_HEADERS rx :via
   # AAA via
   if(req.http.via ~ "\b(coalesce\b|root\@)"){
      set req.http.X-Sec-RuleInfo = "SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "950908";
      call sec_sev1;
   }
   ## REQUEST_HEADERS, 
   # skipped   REQUEST_HEADERS rx  \b(coalesce\b|root\@)
   ## XML, :/*|
   # AC /*| 
   # skipped   XML rx /*| \b(coalesce\b|root\@)
   ## !REQUEST_HEADERS, :Referer|
   # AC Referer| 
   ## Rule: REQUEST_HEADERS rx :Referer|
   # AAA Referer|
   if(req.http.Referer ~ "\b(coalesce\b|root\@)"){
      set req.http.X-Sec-RuleInfo = "SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959908";
      call sec_sev1;
   }
   ## !REQUEST_HEADERS, :via
   # AC via 
   ## Rule: REQUEST_HEADERS rx :via
   # AAA via
   if(req.http.via ~ "\b(coalesce\b|root\@)"){
      set req.http.X-Sec-RuleInfo = "SQL Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SQL_INJECTION";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959908";
      call sec_sev1;
   }
   ## REQUEST_FILENAME, 
   # skipped   REQUEST_FILENAME pm  jscript onsubmit copyparentfolder javascript meta onmove onkeydown onchange onkeyup activexobject expression onmouseup ecmascript onmouseover vbscript: <![cdata[ http: settimeout onabort shell: .innerhtml onmousedown onkeypress asfunction: onclick .fromcharcode background-image: .cookie ondragdrop onblur x-javascript mocha: onfocus javascript: getparentfolder lowsrc onresize @import alert onselect script onmouseout onmousemove background application .execscript livescript: getspecialfolder vbscript iframe .addimport onunload createtextrange onload <input
   ## ARGS, 
   # skipped   ARGS pm  jscript onsubmit copyparentfolder javascript meta onmove onkeydown onchange onkeyup activexobject expression onmouseup ecmascript onmouseover vbscript: <![cdata[ http: settimeout onabort shell: .innerhtml onmousedown onkeypress asfunction: onclick .fromcharcode background-image: .cookie ondragdrop onblur x-javascript mocha: onfocus javascript: getparentfolder lowsrc onresize @import alert onselect script onmouseout onmousemove background application .execscript livescript: getspecialfolder vbscript iframe .addimport onunload createtextrange onload <input
   ## ARGS_NAMES, 
   # skipped   ARGS_NAMES pm  jscript onsubmit copyparentfolder javascript meta onmove onkeydown onchange onkeyup activexobject expression onmouseup ecmascript onmouseover vbscript: <![cdata[ http: settimeout onabort shell: .innerhtml onmousedown onkeypress asfunction: onclick .fromcharcode background-image: .cookie ondragdrop onblur x-javascript mocha: onfocus javascript: getparentfolder lowsrc onresize @import alert onselect script onmouseout onmousemove background application .execscript livescript: getspecialfolder vbscript iframe .addimport onunload createtextrange onload <input
   ## REQUEST_HEADERS, 
   # skipped   REQUEST_HEADERS pm  jscript onsubmit copyparentfolder javascript meta onmove onkeydown onchange onkeyup activexobject expression onmouseup ecmascript onmouseover vbscript: <![cdata[ http: settimeout onabort shell: .innerhtml onmousedown onkeypress asfunction: onclick .fromcharcode background-image: .cookie ondragdrop onblur x-javascript mocha: onfocus javascript: getparentfolder lowsrc onresize @import alert onselect script onmouseout onmousemove background application .execscript livescript: getspecialfolder vbscript iframe .addimport onunload createtextrange onload <input
   ## XML, :/*|
   # AC /*| 
   # skipped   XML pm /*| jscript onsubmit copyparentfolder javascript meta onmove onkeydown onchange onkeyup activexobject expression onmouseup ecmascript onmouseover vbscript: <![cdata[ http: settimeout onabort shell: .innerhtml onmousedown onkeypress asfunction: onclick .fromcharcode background-image: .cookie ondragdrop onblur x-javascript mocha: onfocus javascript: getparentfolder lowsrc onresize @import alert onselect script onmouseout onmousemove background application .execscript livescript: getspecialfolder vbscript iframe .addimport onunload createtextrange onload <input
   ## !REQUEST_HEADERS, :Referer
   # AC Referer 
   # skipped !  REQUEST_HEADERS pm Referer jscript onsubmit copyparentfolder javascript meta onmove onkeydown onchange onkeyup activexobject expression onmouseup ecmascript onmouseover vbscript: <![cdata[ http: settimeout onabort shell: .innerhtml onmousedown onkeypress asfunction: onclick .fromcharcode background-image: .cookie ondragdrop onblur x-javascript mocha: onfocus javascript: getparentfolder lowsrc onresize @import alert onselect script onmouseout onmousemove background application .execscript livescript: getspecialfolder vbscript iframe .addimport onunload createtextrange onload <input
   ## REQUEST_FILENAME, 
   ## Rule: REQUEST_FILENAME rx :
   if(req.url ~ "(\b((type\b\W*?\b(text\b\W*?\b(j(ava)?|ecma|vb)|application\b\W*?\bx-(java|vb))script|c(opyparentfolder|reatetextrange)|get(special|parent)folder|iframe\b.{0,100}?\bsrc)\b|on((mo(use(o(ver|ut)|down|move|up)|ve)|key(press|down|up)|c(hange|lick)|s(elec|ubmi)t|(un)?load|dragdrop|resize|focus|blur)\b\W*?=|abort\b)|(l(owsrc\b\W*?\b((java|vb)script|shell|http)|ivescript)|(href|url)\b\W*?\b((java|vb)script|shell)|background-image|mocha):|s((tyle\b\W*=.*\bexpression\b\W*|ettimeout\b\W*?)\(|rc\b\W*?\b((java|vb)script|shell|http):)|a(ctivexobject\b|lert\b\W*?\(|sfunction:))|<((body\b.*?\b(backgroun|onloa)d|input\b.*?\btype\b\W*?\bimage)\b| ?((script|meta)\b|iframe)|!\[cdata\[)|(\.((execscrip|addimpor)t|(fromcharcod|cooki)e|innerhtml)|\@import)\b)"){
      set req.http.X-Sec-RuleInfo = "Cross-site Scripting (XSS) Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/XSS";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "950004";
      call sec_sev1;
   }
   ## ARGS, 
   ## Rule: ARGS rx :
   if(req.url ~ "(\b((type\b\W*?\b(text\b\W*?\b(j(ava)?|ecma|vb)|application\b\W*?\bx-(java|vb))script|c(opyparentfolder|reatetextrange)|get(special|parent)folder|iframe\b.{0,100}?\bsrc)\b|on((mo(use(o(ver|ut)|down|move|up)|ve)|key(press|down|up)|c(hange|lick)|s(elec|ubmi)t|(un)?load|dragdrop|resize|focus|blur)\b\W*?=|abort\b)|(l(owsrc\b\W*?\b((java|vb)script|shell|http)|ivescript)|(href|url)\b\W*?\b((java|vb)script|shell)|background-image|mocha):|s((tyle\b\W*=.*\bexpression\b\W*|ettimeout\b\W*?)\(|rc\b\W*?\b((java|vb)script|shell|http):)|a(ctivexobject\b|lert\b\W*?\(|sfunction:))|<((body\b.*?\b(backgroun|onloa)d|input\b.*?\btype\b\W*?\bimage)\b| ?((script|meta)\b|iframe)|!\[cdata\[)|(\.((execscrip|addimpor)t|(fromcharcod|cooki)e|innerhtml)|\@import)\b)"){
      set req.http.X-Sec-RuleInfo = "Cross-site Scripting (XSS) Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/XSS";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "950004";
      call sec_sev1;
   }
   ## ARGS_NAMES, 
   ## Rule: ARGS_NAMES rx :
   if(req.url ~ "(\b((type\b\W*?\b(text\b\W*?\b(j(ava)?|ecma|vb)|application\b\W*?\bx-(java|vb))script|c(opyparentfolder|reatetextrange)|get(special|parent)folder|iframe\b.{0,100}?\bsrc)\b|on((mo(use(o(ver|ut)|down|move|up)|ve)|key(press|down|up)|c(hange|lick)|s(elec|ubmi)t|(un)?load|dragdrop|resize|focus|blur)\b\W*?=|abort\b)|(l(owsrc\b\W*?\b((java|vb)script|shell|http)|ivescript)|(href|url)\b\W*?\b((java|vb)script|shell)|background-image|mocha):|s((tyle\b\W*=.*\bexpression\b\W*|ettimeout\b\W*?)\(|rc\b\W*?\b((java|vb)script|shell|http):)|a(ctivexobject\b|lert\b\W*?\(|sfunction:))|<((body\b.*?\b(backgroun|onloa)d|input\b.*?\btype\b\W*?\bimage)\b| ?((script|meta)\b|iframe)|!\[cdata\[)|(\.((execscrip|addimpor)t|(fromcharcod|cooki)e|innerhtml)|\@import)\b)"){
      set req.http.X-Sec-RuleInfo = "Cross-site Scripting (XSS) Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/XSS";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "950004";
      call sec_sev1;
   }
   ## REQUEST_HEADERS, 
   # skipped   REQUEST_HEADERS rx  (\b((type\b\W*?\b(text\b\W*?\b(j(ava)?|ecma|vb)|application\b\W*?\bx-(java|vb))script|c(opyparentfolder|reatetextrange)|get(special|parent)folder|iframe\b.{0,100}?\bsrc)\b|on((mo(use(o(ver|ut)|down|move|up)|ve)|key(press|down|up)|c(hange|lick)|s(elec|ubmi)t|(un)?load|dragdrop|resize|focus|blur)\b\W*?=|abort\b)|(l(owsrc\b\W*?\b((java|vb)script|shell|http)|ivescript)|(href|url)\b\W*?\b((java|vb)script|shell)|background-image|mocha):|s((tyle\b\W*=.*\bexpression\b\W*|ettimeout\b\W*?)\(|rc\b\W*?\b((java|vb)script|shell|http):)|a(ctivexobject\b|lert\b\W*?\(|sfunction:))|<((body\b.*?\b(backgroun|onloa)d|input\b.*?\btype\b\W*?\bimage)\b| ?((script|meta)\b|iframe)|!\[cdata\[)|(\.((execscrip|addimpor)t|(fromcharcod|cooki)e|innerhtml)|\@import)\b)
   ## XML, :/*|
   # AC /*| 
   # skipped   XML rx /*| (\b((type\b\W*?\b(text\b\W*?\b(j(ava)?|ecma|vb)|application\b\W*?\bx-(java|vb))script|c(opyparentfolder|reatetextrange)|get(special|parent)folder|iframe\b.{0,100}?\bsrc)\b|on((mo(use(o(ver|ut)|down|move|up)|ve)|key(press|down|up)|c(hange|lick)|s(elec|ubmi)t|(un)?load|dragdrop|resize|focus|blur)\b\W*?=|abort\b)|(l(owsrc\b\W*?\b((java|vb)script|shell|http)|ivescript)|(href|url)\b\W*?\b((java|vb)script|shell)|background-image|mocha):|s((tyle\b\W*=.*\bexpression\b\W*|ettimeout\b\W*?)\(|rc\b\W*?\b((java|vb)script|shell|http):)|a(ctivexobject\b|lert\b\W*?\(|sfunction:))|<((body\b.*?\b(backgroun|onloa)d|input\b.*?\btype\b\W*?\bimage)\b| ?((script|meta)\b|iframe)|!\[cdata\[)|(\.((execscrip|addimpor)t|(fromcharcod|cooki)e|innerhtml)|\@import)\b)
   ## !REQUEST_HEADERS, :Referer
   # AC Referer 
   ## Rule: REQUEST_HEADERS rx :Referer
   # AAA Referer
   if(req.http.Referer ~ "(\b((type\b\W*?\b(text\b\W*?\b(j(ava)?|ecma|vb)|application\b\W*?\bx-(java|vb))script|c(opyparentfolder|reatetextrange)|get(special|parent)folder|iframe\b.{0,100}?\bsrc)\b|on((mo(use(o(ver|ut)|down|move|up)|ve)|key(press|down|up)|c(hange|lick)|s(elec|ubmi)t|(un)?load|dragdrop|resize|focus|blur)\b\W*?=|abort\b)|(l(owsrc\b\W*?\b((java|vb)script|shell|http)|ivescript)|(href|url)\b\W*?\b((java|vb)script|shell)|background-image|mocha):|s((tyle\b\W*=.*\bexpression\b\W*|ettimeout\b\W*?)\(|rc\b\W*?\b((java|vb)script|shell|http):)|a(ctivexobject\b|lert\b\W*?\(|sfunction:))|<((body\b.*?\b(backgroun|onloa)d|input\b.*?\btype\b\W*?\bimage)\b| ?((script|meta)\b|iframe)|!\[cdata\[)|(\.((execscrip|addimpor)t|(fromcharcod|cooki)e|innerhtml)|\@import)\b)"){
      set req.http.X-Sec-RuleInfo = "Cross-site Scripting (XSS) Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/XSS";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959004";
      call sec_sev1;
   }
   ## REQUEST_FILENAME, 
   # skipped   REQUEST_FILENAME pm  .www_acl .htpasswd .htaccess boot.ini httpd.conf /etc/ .htgroup global.asa .wwwacl
   ## ARGS, 
   # skipped   ARGS pm  .www_acl .htpasswd .htaccess boot.ini httpd.conf /etc/ .htgroup global.asa .wwwacl
   ## ARGS_NAMES, 
   # skipped   ARGS_NAMES pm  .www_acl .htpasswd .htaccess boot.ini httpd.conf /etc/ .htgroup global.asa .wwwacl
   ## REQUEST_HEADERS, 
   # skipped   REQUEST_HEADERS pm  .www_acl .htpasswd .htaccess boot.ini httpd.conf /etc/ .htgroup global.asa .wwwacl
   ## XML, :/*
   # AC /* 
   # skipped   XML pm /* .www_acl .htpasswd .htaccess boot.ini httpd.conf /etc/ .htgroup global.asa .wwwacl
   ## REQUEST_FILENAME, 
   ## Rule: REQUEST_FILENAME rx :
   if(req.url ~ "(\b(\.(ht(access|passwd|group)|www_?acl)|global\.asa|httpd\.conf|boot\.ini)\b|\/etc\/)"){
      set req.http.X-Sec-Return = "501";
      set req.http.X-Sec-RuleInfo = "Remote File Access Attempt";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/FILE_INJECTION";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "950005";
      call sec_sev1;
   }
   ## ARGS, 
   ## Rule: ARGS rx :
   if(req.url ~ "(\b(\.(ht(access|passwd|group)|www_?acl)|global\.asa|httpd\.conf|boot\.ini)\b|\/etc\/)"){
      set req.http.X-Sec-Return = "501";
      set req.http.X-Sec-RuleInfo = "Remote File Access Attempt";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/FILE_INJECTION";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "950005";
      call sec_sev1;
   }
   ## ARGS_NAMES, 
   ## Rule: ARGS_NAMES rx :
   if(req.url ~ "(\b(\.(ht(access|passwd|group)|www_?acl)|global\.asa|httpd\.conf|boot\.ini)\b|\/etc\/)"){
      set req.http.X-Sec-Return = "501";
      set req.http.X-Sec-RuleInfo = "Remote File Access Attempt";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/FILE_INJECTION";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "950005";
      call sec_sev1;
   }
   ## REQUEST_HEADERS, 
   # skipped   REQUEST_HEADERS rx  (\b(\.(ht(access|passwd|group)|www_?acl)|global\.asa|httpd\.conf|boot\.ini)\b|\/etc\/)
   ## XML, :/*
   # AC /* 
   # skipped   XML rx /* (\b(\.(ht(access|passwd|group)|www_?acl)|global\.asa|httpd\.conf|boot\.ini)\b|\/etc\/)
   ## REQUEST_FILENAME, 
   ## Rule: REQUEST_FILENAME rx :
   if(req.url ~ "\b(n(map|et|c)|w(guest|sh)|cmd(32)?|telnet|rcmd|ftp)\.exe\b"){
      set req.http.X-Sec-Return = "501";
      set req.http.X-Sec-RuleInfo = "System Command Access";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/FILE_INJECTION";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "950002";
      call sec_sev1;
   }
   ## ARGS, 
   # skipped   ARGS pm  uname wguest.exe /perl /nasm rcmd.exe nc tclsh /xterm finger tftp chown /echo nmap.exe ping /passwd /chsh ps /uname telnet.exe /ftp ls tclsh8 lsof /ping echo cmd.exe /kill python traceroute /ps perl passwd wsh.exe /rm /cpp chgrp /telnet localgroup kill /chgrp /finger nasm /ls nc.exe id /chmod /nc /g++ /id /chown cmd /nmap chsh /gcc net.exe /python /lsof ftp.exe ftp xterm mail /mail tracert nmap rm cd chmod cpp telnet cmd32.exe gcc g++
   ## ARGS, 
   ## Rule: ARGS rx :
   if(req.url ~ "(\b((n(et(\b\W+?\blocalgroup|\.exe)|(map|c)\.exe)|t(racer(oute|t)|elnet\.exe|clsh8?|ftp)|(w(guest|sh)|rcmd|ftp)\.exe|echo\b\W*?\by+)\b|c(md((32)?\.exe\b|\b\W*?\/c)|d(\b\W*?[\\\/]|\W*?\.\.)|hmod.{0,40}?\+.{0,3}x))|[\;\|\`]\W*?\b((c(h(grp|mod|own|sh)|md|pp)|p(asswd|ython|erl|ing|s)|n(asm|map|c)|f(inger|tp)|(kil|mai)l|(xte)?rm|ls(of)?|telnet|uname|echo|id)\b|g(\+\+|cc\b))|\/(c(h(grp|mod|own|sh)|pp)|p(asswd|ython|erl|ing|s)|n(asm|map|c)|f(inger|tp)|(kil|mai)l|g(\+\+|cc)|(xte)?rm|ls(of)?|telnet|uname|echo|id)([\'%22\|\;\`\-\s]|$))"){
      set req.http.X-Sec-Return = "501";
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "950006";
      call sec_sev1;
   }
   ## REQUEST_HEADERS, 
   # skipped   REQUEST_HEADERS pm  uname wguest.exe /perl /nasm rcmd.exe nc tclsh /xterm finger tftp chown /echo nmap.exe ping /passwd /chsh ps /uname telnet.exe /ftp ls tclsh8 lsof /ping echo cmd.exe /kill python traceroute /ps perl passwd wsh.exe /rm /cpp chgrp /telnet localgroup kill /chgrp /finger nasm /ls nc.exe id /chmod /nc /g++ /id /chown cmd /nmap chsh /gcc net.exe /python /lsof ftp.exe ftp xterm mail /mail tracert nmap rm cd chmod cpp telnet cmd32.exe gcc g++
   ## XML, :/*|
   # AC /*| 
   # skipped   XML pm /*| uname wguest.exe /perl /nasm rcmd.exe nc tclsh /xterm finger tftp chown /echo nmap.exe ping /passwd /chsh ps /uname telnet.exe /ftp ls tclsh8 lsof /ping echo cmd.exe /kill python traceroute /ps perl passwd wsh.exe /rm /cpp chgrp /telnet localgroup kill /chgrp /finger nasm /ls nc.exe id /chmod /nc /g++ /id /chown cmd /nmap chsh /gcc net.exe /python /lsof ftp.exe ftp xterm mail /mail tracert nmap rm cd chmod cpp telnet cmd32.exe gcc g++
   ## !REQUEST_HEADERS, :'/^(Cookie|Referer|X-OS-Prefs)$/'
   # skipped !  REQUEST_HEADERS pm :'/^(Cookie|Referer|X-OS-Prefs)$/' uname wguest.exe /perl /nasm rcmd.exe nc tclsh /xterm finger tftp chown /echo nmap.exe ping /passwd /chsh ps /uname telnet.exe /ftp ls tclsh8 lsof /ping echo cmd.exe /kill python traceroute /ps perl passwd wsh.exe /rm /cpp chgrp /telnet localgroup kill /chgrp /finger nasm /ls nc.exe id /chmod /nc /g++ /id /chown cmd /nmap chsh /gcc net.exe /python /lsof ftp.exe ftp xterm mail /mail tracert nmap rm cd chmod cpp telnet cmd32.exe gcc g++
   ## REQUEST_COOKIES, 
   # skipped   REQUEST_COOKIES pm  uname wguest.exe /perl /nasm rcmd.exe nc tclsh /xterm finger tftp chown /echo nmap.exe ping /passwd /chsh ps /uname telnet.exe /ftp ls tclsh8 lsof /ping echo cmd.exe /kill python traceroute /ps perl passwd wsh.exe /rm /cpp chgrp /telnet localgroup kill /chgrp /finger nasm /ls nc.exe id /chmod /nc /g++ /id /chown cmd /nmap chsh /gcc net.exe /python /lsof ftp.exe ftp xterm mail /mail tracert nmap rm cd chmod cpp telnet cmd32.exe gcc g++
   ## REQUEST_COOKIES_NAMES, 
   # skipped   REQUEST_COOKIES_NAMES pm  uname wguest.exe /perl /nasm rcmd.exe nc tclsh /xterm finger tftp chown /echo nmap.exe ping /passwd /chsh ps /uname telnet.exe /ftp ls tclsh8 lsof /ping echo cmd.exe /kill python traceroute /ps perl passwd wsh.exe /rm /cpp chgrp /telnet localgroup kill /chgrp /finger nasm /ls nc.exe id /chmod /nc /g++ /id /chown cmd /nmap chsh /gcc net.exe /python /lsof ftp.exe ftp xterm mail /mail tracert nmap rm cd chmod cpp telnet cmd32.exe gcc g++
   ## REQUEST_HEADERS, 
   # skipped   REQUEST_HEADERS rx  (\b((n(et(\b\W+?\blocalgroup|\.exe)|(map|c)\.exe)|t(racer(oute|t)|elnet\.exe|clsh8?|ftp)|(w(guest|sh)|rcmd|ftp)\.exe|echo\b\W*?\by+)\b|c(md((32)?\.exe\b|\b\W*?\/c)|d(\b\W*?[\\\/]|\W*?\.\.)|hmod.{0,40}?\+.{0,3}x))|[\;\|\`]\W*?\b((c(h(grp|mod|own|sh)|md|pp)|p(asswd|ython|erl|ing|s)|n(asm|map|c)|f(inger|tp)|(kil|mai)l|(xte)?rm|ls(of)?|telnet|uname|echo|id)\b|g(\+\+|cc\b))|\/(c(h(grp|mod|own|sh)|pp)|p(asswd|ython|erl|ing|s)|n(asm|map|c)|f(inger|tp)|(kil|mai)l|g(\+\+|cc)|(xte)?rm|ls(of)?|telnet|uname|echo|id)([\'%22\|\;\`\-\s]|$))
   ## XML, :/*|
   # AC /*| 
   # skipped   XML rx /*| (\b((n(et(\b\W+?\blocalgroup|\.exe)|(map|c)\.exe)|t(racer(oute|t)|elnet\.exe|clsh8?|ftp)|(w(guest|sh)|rcmd|ftp)\.exe|echo\b\W*?\by+)\b|c(md((32)?\.exe\b|\b\W*?\/c)|d(\b\W*?[\\\/]|\W*?\.\.)|hmod.{0,40}?\+.{0,3}x))|[\;\|\`]\W*?\b((c(h(grp|mod|own|sh)|md|pp)|p(asswd|ython|erl|ing|s)|n(asm|map|c)|f(inger|tp)|(kil|mai)l|(xte)?rm|ls(of)?|telnet|uname|echo|id)\b|g(\+\+|cc\b))|\/(c(h(grp|mod|own|sh)|pp)|p(asswd|ython|erl|ing|s)|n(asm|map|c)|f(inger|tp)|(kil|mai)l|g(\+\+|cc)|(xte)?rm|ls(of)?|telnet|uname|echo|id)([\'%22\|\;\`\-\s]|$))
   ## !REQUEST_HEADERS, :'/^(Cookie|Referer|X-OS-Prefs)$/'
   ## Rule: REQUEST_HEADERS rx ::'/^(Cookie|Referer|X-OS-Prefs)$/'
   # AAA Cookie|Referer|X-OS-Prefs
   if(req.http.Cookie ~ "(\b((n(et(\b\W+?\blocalgroup|\.exe)|(map|c)\.exe)|t(racer(oute|t)|elnet\.exe|clsh8?|ftp)|(w(guest|sh)|rcmd|ftp)\.exe|echo\b\W*?\by+)\b|c(md((32)?\.exe\b|\b\W*?\/c)|d(\b\W*?[\\\/]|\W*?\.\.)|hmod.{0,40}?\+.{0,3}x))|[\;\|\`]\W*?\b((c(h(grp|mod|own|sh)|md|pp)|p(asswd|ython|erl|ing|s)|n(asm|map|c)|f(inger|tp)|(kil|mai)l|(xte)?rm|ls(of)?|telnet|uname|echo|id)\b|g(\+\+|cc\b))|\/(c(h(grp|mod|own|sh)|pp)|p(asswd|ython|erl|ing|s)|n(asm|map|c)|f(inger|tp)|(kil|mai)l|g(\+\+|cc)|(xte)?rm|ls(of)?|telnet|uname|echo|id)([\'%22\|\;\`\-\s]|$))"){
      set req.http.X-Sec-Return = "501";
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959006";
      call sec_sev1;
   }
   if(req.http.Referer ~ "(\b((n(et(\b\W+?\blocalgroup|\.exe)|(map|c)\.exe)|t(racer(oute|t)|elnet\.exe|clsh8?|ftp)|(w(guest|sh)|rcmd|ftp)\.exe|echo\b\W*?\by+)\b|c(md((32)?\.exe\b|\b\W*?\/c)|d(\b\W*?[\\\/]|\W*?\.\.)|hmod.{0,40}?\+.{0,3}x))|[\;\|\`]\W*?\b((c(h(grp|mod|own|sh)|md|pp)|p(asswd|ython|erl|ing|s)|n(asm|map|c)|f(inger|tp)|(kil|mai)l|(xte)?rm|ls(of)?|telnet|uname|echo|id)\b|g(\+\+|cc\b))|\/(c(h(grp|mod|own|sh)|pp)|p(asswd|ython|erl|ing|s)|n(asm|map|c)|f(inger|tp)|(kil|mai)l|g(\+\+|cc)|(xte)?rm|ls(of)?|telnet|uname|echo|id)([\'%22\|\;\`\-\s]|$))"){
      set req.http.X-Sec-Return = "501";
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959006";
      call sec_sev1;
   }
   if(req.http.X-OS-Prefs ~ "(\b((n(et(\b\W+?\blocalgroup|\.exe)|(map|c)\.exe)|t(racer(oute|t)|elnet\.exe|clsh8?|ftp)|(w(guest|sh)|rcmd|ftp)\.exe|echo\b\W*?\by+)\b|c(md((32)?\.exe\b|\b\W*?\/c)|d(\b\W*?[\\\/]|\W*?\.\.)|hmod.{0,40}?\+.{0,3}x))|[\;\|\`]\W*?\b((c(h(grp|mod|own|sh)|md|pp)|p(asswd|ython|erl|ing|s)|n(asm|map|c)|f(inger|tp)|(kil|mai)l|(xte)?rm|ls(of)?|telnet|uname|echo|id)\b|g(\+\+|cc\b))|\/(c(h(grp|mod|own|sh)|pp)|p(asswd|ython|erl|ing|s)|n(asm|map|c)|f(inger|tp)|(kil|mai)l|g(\+\+|cc)|(xte)?rm|ls(of)?|telnet|uname|echo|id)([\'%22\|\;\`\-\s]|$))"){
      set req.http.X-Sec-Return = "501";
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959006";
      call sec_sev1;
   }
   ## REQUEST_COOKIES, 
   ## Rule: REQUEST_COOKIES rx :
   if(req.http.Cookie ~ "(\b((n(et(\b\W+?\blocalgroup|\.exe)|(map|c)\.exe)|t(racer(oute|t)|elnet\.exe|clsh8?|ftp)|(w(guest|sh)|rcmd|ftp)\.exe|echo\b\W*?\by+)\b|c(md((32)?\.exe\b|\b\W*?\/c)|d(\b\W*?[\\\/]|\W*?\.\.)|hmod.{0,40}?\+.{0,3}x))|[\;\|\`]\W*?\b((c(h(grp|mod|own|sh)|md|pp)|p(asswd|ython|erl|ing|s)|n(asm|map|c)|f(inger|tp)|(kil|mai)l|(xte)?rm|ls(of)?|telnet|uname|echo|id)\b|g(\+\+|cc\b))|\/(c(h(grp|mod|own|sh)|pp)|p(asswd|ython|erl|ing|s)|n(asm|map|c)|f(inger|tp)|(kil|mai)l|g(\+\+|cc)|(xte)?rm|ls(of)?|telnet|uname|echo|id)([\'%22\|\;\`\-\s]|$))"){
      set req.http.X-Sec-Return = "501";
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959006";
      call sec_sev1;
   }
   ## REQUEST_COOKIES_NAMES, 
   ## Rule: REQUEST_COOKIES_NAMES rx :
   if(req.http.Cookie ~ "(\b((n(et(\b\W+?\blocalgroup|\.exe)|(map|c)\.exe)|t(racer(oute|t)|elnet\.exe|clsh8?|ftp)|(w(guest|sh)|rcmd|ftp)\.exe|echo\b\W*?\by+)\b|c(md((32)?\.exe\b|\b\W*?\/c)|d(\b\W*?[\\\/]|\W*?\.\.)|hmod.{0,40}?\+.{0,3}x))|[\;\|\`]\W*?\b((c(h(grp|mod|own|sh)|md|pp)|p(asswd|ython|erl|ing|s)|n(asm|map|c)|f(inger|tp)|(kil|mai)l|(xte)?rm|ls(of)?|telnet|uname|echo|id)\b|g(\+\+|cc\b))|\/(c(h(grp|mod|own|sh)|pp)|p(asswd|ython|erl|ing|s)|n(asm|map|c)|f(inger|tp)|(kil|mai)l|g(\+\+|cc)|(xte)?rm|ls(of)?|telnet|uname|echo|id)([\'%22\|\;\`\-\s]|$))"){
      set req.http.X-Sec-Return = "501";
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959006";
      call sec_sev1;
   }
   ## ARGS, 
   ## Rule: ARGS rx :
   if(req.url ~ "(([\;\|\`]\W*?\bcc|\bwget)\b|\/cc([\'%22\|\;\`\-\s]|$))"){
      set req.http.X-Sec-Return = "501";
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "950907";
      call sec_sev1;
   }
   ## REQUEST_HEADERS, 
   # skipped   REQUEST_HEADERS rx  (([\;\|\`]\W*?\bcc|\bwget)\b|\/cc([\'%22\|\;\`\-\s]|$))
   ## XML, :/*|
   # AC /*| 
   # skipped   XML rx /*| (([\;\|\`]\W*?\bcc|\bwget)\b|\/cc([\'%22\|\;\`\-\s]|$))
   ## !REQUEST_HEADERS, :'/^(Cookie|Referer|X-OS-Prefs|User-Agent)$/'
   ## Rule: REQUEST_HEADERS rx ::'/^(Cookie|Referer|X-OS-Prefs|User-Agent)$/'
   # AAA Cookie|Referer|X-OS-Prefs|User-Agent
   if(req.http.Cookie ~ "(([\;\|\`]\W*?\bcc|\bwget)\b|\/cc([\'%22\|\;\`\-\s]|$))"){
      set req.http.X-Sec-Return = "501";
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959907";
      call sec_sev1;
   }
   if(req.http.Referer ~ "(([\;\|\`]\W*?\bcc|\bwget)\b|\/cc([\'%22\|\;\`\-\s]|$))"){
      set req.http.X-Sec-Return = "501";
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959907";
      call sec_sev1;
   }
   if(req.http.X-OS-Prefs ~ "(([\;\|\`]\W*?\bcc|\bwget)\b|\/cc([\'%22\|\;\`\-\s]|$))"){
      set req.http.X-Sec-Return = "501";
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959907";
      call sec_sev1;
   }
   if(req.http.User-Agent ~ "(([\;\|\`]\W*?\bcc|\bwget)\b|\/cc([\'%22\|\;\`\-\s]|$))"){
      set req.http.X-Sec-Return = "501";
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959907";
      call sec_sev1;
   }
   ## REQUEST_COOKIES, 
   ## Rule: REQUEST_COOKIES rx :
   if(req.http.Cookie ~ "(([\;\|\`]\W*?\bcc|\bwget)\b|\/cc([\'%22\|\;\`\-\s]|$))"){
      set req.http.X-Sec-Return = "501";
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959907";
      call sec_sev1;
   }
   ## REQUEST_COOKIES_NAMES, 
   ## Rule: REQUEST_COOKIES_NAMES rx :
   if(req.http.Cookie ~ "(([\;\|\`]\W*?\bcc|\bwget)\b|\/cc([\'%22\|\;\`\-\s]|$))"){
      set req.http.X-Sec-Return = "501";
      set req.http.X-Sec-RuleInfo = "System Command Injection";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/COMMAND_INJECTION";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959907";
      call sec_sev1;
   }
   ## REQUEST_FILENAME, 
   ## Rule: REQUEST_FILENAME rx :
   if(req.url ~ "\bcf(usion_(d(bconnections_flush|ecrypt)|set(tings_refresh|odbcini)|getodbc(dsn|ini)|verifymail|encrypt)|_((iscoldfusiondatasourc|getdatasourceusernam)e|setdatasource(password|username))|newinternal(adminsecurit|registr)y|admin_registry_(delete|set)|internaldebug)\b"){
      set req.http.X-Sec-Return = "501";
      set req.http.X-Sec-RuleInfo = "Injection of Undocumented ColdFusion Tags";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/CF_INJECTION";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "950008";
      call sec_sev1;
   }
   ## ARGS, 
   ## Rule: ARGS rx :
   if(req.url ~ "\bcf(usion_(d(bconnections_flush|ecrypt)|set(tings_refresh|odbcini)|getodbc(dsn|ini)|verifymail|encrypt)|_((iscoldfusiondatasourc|getdatasourceusernam)e|setdatasource(password|username))|newinternal(adminsecurit|registr)y|admin_registry_(delete|set)|internaldebug)\b"){
      set req.http.X-Sec-Return = "501";
      set req.http.X-Sec-RuleInfo = "Injection of Undocumented ColdFusion Tags";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/CF_INJECTION";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "950008";
      call sec_sev1;
   }
   ## ARGS_NAMES, 
   ## Rule: ARGS_NAMES rx :
   if(req.url ~ "\bcf(usion_(d(bconnections_flush|ecrypt)|set(tings_refresh|odbcini)|getodbc(dsn|ini)|verifymail|encrypt)|_((iscoldfusiondatasourc|getdatasourceusernam)e|setdatasource(password|username))|newinternal(adminsecurit|registr)y|admin_registry_(delete|set)|internaldebug)\b"){
      set req.http.X-Sec-Return = "501";
      set req.http.X-Sec-RuleInfo = "Injection of Undocumented ColdFusion Tags";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/CF_INJECTION";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "950008";
      call sec_sev1;
   }
   ## REQUEST_HEADERS, 
   # skipped   REQUEST_HEADERS rx  \bcf(usion_(d(bconnections_flush|ecrypt)|set(tings_refresh|odbcini)|getodbc(dsn|ini)|verifymail|encrypt)|_((iscoldfusiondatasourc|getdatasourceusernam)e|setdatasource(password|username))|newinternal(adminsecurit|registr)y|admin_registry_(delete|set)|internaldebug)\b
   ## XML, :/*
   # AC /* 
   # skipped   XML rx /* \bcf(usion_(d(bconnections_flush|ecrypt)|set(tings_refresh|odbcini)|getodbc(dsn|ini)|verifymail|encrypt)|_((iscoldfusiondatasourc|getdatasourceusernam)e|setdatasource(password|username))|newinternal(adminsecurit|registr)y|admin_registry_(delete|set)|internaldebug)\b
   ## REQUEST_FILENAME, 
   ## Rule: REQUEST_FILENAME rx :
   if(req.url ~ "(\((\W*?(objectc(ategory|lass)|homedirectory|[gu]idnumber|cn)\b\W*?=|[^\w\x80-\xFF]*?[\!\&\|][^\w\x80-\xFF]*?\()|\)[^\w\x80-\xFF]*?\([^\w\x80-\xFF]*?[\!\&\|])"){
      set req.http.X-Sec-Return = "501";
      set req.http.X-Sec-RuleInfo = "LDAP Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/LDAP_INJECTION";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "950010";
      call sec_sev1;
   }
   ## ARGS, 
   ## Rule: ARGS rx :
   if(req.url ~ "(\((\W*?(objectc(ategory|lass)|homedirectory|[gu]idnumber|cn)\b\W*?=|[^\w\x80-\xFF]*?[\!\&\|][^\w\x80-\xFF]*?\()|\)[^\w\x80-\xFF]*?\([^\w\x80-\xFF]*?[\!\&\|])"){
      set req.http.X-Sec-Return = "501";
      set req.http.X-Sec-RuleInfo = "LDAP Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/LDAP_INJECTION";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "950010";
      call sec_sev1;
   }
   ## ARGS_NAMES, 
   ## Rule: ARGS_NAMES rx :
   if(req.url ~ "(\((\W*?(objectc(ategory|lass)|homedirectory|[gu]idnumber|cn)\b\W*?=|[^\w\x80-\xFF]*?[\!\&\|][^\w\x80-\xFF]*?\()|\)[^\w\x80-\xFF]*?\([^\w\x80-\xFF]*?[\!\&\|])"){
      set req.http.X-Sec-Return = "501";
      set req.http.X-Sec-RuleInfo = "LDAP Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/LDAP_INJECTION";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "950010";
      call sec_sev1;
   }
   ## REQUEST_HEADERS, 
   # skipped   REQUEST_HEADERS rx  (\((\W*?(objectc(ategory|lass)|homedirectory|[gu]idnumber|cn)\b\W*?=|[^\w\x80-\xFF]*?[\!\&\|][^\w\x80-\xFF]*?\()|\)[^\w\x80-\xFF]*?\([^\w\x80-\xFF]*?[\!\&\|])
   ## XML, :/*|
   # AC /*| 
   # skipped   XML rx /*| (\((\W*?(objectc(ategory|lass)|homedirectory|[gu]idnumber|cn)\b\W*?=|[^\w\x80-\xFF]*?[\!\&\|][^\w\x80-\xFF]*?\()|\)[^\w\x80-\xFF]*?\([^\w\x80-\xFF]*?[\!\&\|])
   ## !REQUEST_HEADERS, :Referer
   # AC Referer 
   ## Rule: REQUEST_HEADERS rx :Referer
   # AAA Referer
   if(req.http.Referer ~ "(\((\W*?(objectc(ategory|lass)|homedirectory|[gu]idnumber|cn)\b\W*?=|[^\w\x80-\xFF]*?[\!\&\|][^\w\x80-\xFF]*?\()|\)[^\w\x80-\xFF]*?\([^\w\x80-\xFF]*?[\!\&\|])"){
      set req.http.X-Sec-Return = "501";
      set req.http.X-Sec-RuleInfo = "LDAP Injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/LDAP_INJECTION";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "959010";
      call sec_sev1;
   }
   ## REQUEST_FILENAME, 
   ## Rule: REQUEST_FILENAME rx :
   if(req.url ~ "<!--\W*?#\W*?(e(cho|xec)|printenv|include|cmd)"){
      set req.http.X-Sec-Return = "501";
      set req.http.X-Sec-RuleInfo = "SSI injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SSI_INJECTION";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "950011";
      call sec_sev1;
   }
   ## ARGS, 
   ## Rule: ARGS rx :
   if(req.url ~ "<!--\W*?#\W*?(e(cho|xec)|printenv|include|cmd)"){
      set req.http.X-Sec-Return = "501";
      set req.http.X-Sec-RuleInfo = "SSI injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SSI_INJECTION";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "950011";
      call sec_sev1;
   }
   ## ARGS_NAMES, 
   ## Rule: ARGS_NAMES rx :
   if(req.url ~ "<!--\W*?#\W*?(e(cho|xec)|printenv|include|cmd)"){
      set req.http.X-Sec-Return = "501";
      set req.http.X-Sec-RuleInfo = "SSI injection Attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/SSI_INJECTION";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "950011";
      call sec_sev1;
   }
   ## REQUEST_HEADERS, 
   # skipped   REQUEST_HEADERS rx  <!--\W*?#\W*?(e(cho|xec)|printenv|include|cmd)
   ## XML, :/*
   # AC /* 
   # skipped   XML rx /* <!--\W*?#\W*?(e(cho|xec)|printenv|include|cmd)
   ## REQUEST_FILENAME, 
   # skipped   REQUEST_FILENAME pm  <?fgets move_uploaded_file $_session readfile ftp_put ftp_fget gzencode ftp_nb_put bzopen readdir $_post fopen gzread ftp_nb_fput ftp_nb_fget ftp_get $_get scandir fscanf readgzfile fread proc_open fgetc fgetss ftp_fput ftp_nb_get session_start fwrite gzwrite gzopen gzcompress
   ## ARGS, 
   # skipped   ARGS pm  <?fgets move_uploaded_file $_session readfile ftp_put ftp_fget gzencode ftp_nb_put bzopen readdir $_post fopen gzread ftp_nb_fput ftp_nb_fget ftp_get $_get scandir fscanf readgzfile fread proc_open fgetc fgetss ftp_fput ftp_nb_get session_start fwrite gzwrite gzopen gzcompress
   ## ARGS_NAMES, 
   # skipped   ARGS_NAMES pm  <?fgets move_uploaded_file $_session readfile ftp_put ftp_fget gzencode ftp_nb_put bzopen readdir $_post fopen gzread ftp_nb_fput ftp_nb_fget ftp_get $_get scandir fscanf readgzfile fread proc_open fgetc fgetss ftp_fput ftp_nb_get session_start fwrite gzwrite gzopen gzcompress
   ## REQUEST_HEADERS, 
   # skipped   REQUEST_HEADERS pm  <?fgets move_uploaded_file $_session readfile ftp_put ftp_fget gzencode ftp_nb_put bzopen readdir $_post fopen gzread ftp_nb_fput ftp_nb_fget ftp_get $_get scandir fscanf readgzfile fread proc_open fgetc fgetss ftp_fput ftp_nb_get session_start fwrite gzwrite gzopen gzcompress
   ## XML, :/*
   # AC /* 
   # skipped   XML pm /* <?fgets move_uploaded_file $_session readfile ftp_put ftp_fget gzencode ftp_nb_put bzopen readdir $_post fopen gzread ftp_nb_fput ftp_nb_fget ftp_get $_get scandir fscanf readgzfile fread proc_open fgetc fgetss ftp_fput ftp_nb_get session_start fwrite gzwrite gzopen gzcompress
   ## REQUEST_HEADERS, 
   # skipped   REQUEST_HEADERS rx  ((\b(f(tp_(nb_)?f?(ge|pu)t|get(s?s|c)|scanf|write|open|read)|gz((encod|writ)e|compress|open|read)|s(ession_start|candir)|read((gz)?file|dir)|move_uploaded_file|(proc_|bz)open)|\$_((pos|ge)t|session))\b|<\?(?!xml))
   ## XML, :/*
   # AC /* 
   # skipped   XML rx /* ((\b(f(tp_(nb_)?f?(ge|pu)t|get(s?s|c)|scanf|write|open|read)|gz((encod|writ)e|compress|open|read)|s(ession_start|candir)|read((gz)?file|dir)|move_uploaded_file|(proc_|bz)open)|\$_((pos|ge)t|session))\b|<\?(?!xml))
   ## REQUEST_FILENAME, 
   ## Rule: REQUEST_FILENAME rx :
   if(req.url ~ "http:\/\/[\w\.]+?\/.*?\.pdf\b[^\x0d\x0a]*#"){
      set req.http.X-Sec-Return = "501";
      set req.http.X-Sec-RuleInfo = "Persistent Universal PDF XSS attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/UPDF_XSS";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "950018";
      call sec_sev1;
   }
   ## ARGS, 
   ## Rule: ARGS rx :
   if(req.url ~ "http:\/\/[\w\.]+?\/.*?\.pdf\b[^\x0d\x0a]*#"){
      set req.http.X-Sec-Return = "501";
      set req.http.X-Sec-RuleInfo = "Persistent Universal PDF XSS attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/UPDF_XSS";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "950018";
      call sec_sev1;
   }
   ## ARGS_NAMES, 
   ## Rule: ARGS_NAMES rx :
   if(req.url ~ "http:\/\/[\w\.]+?\/.*?\.pdf\b[^\x0d\x0a]*#"){
      set req.http.X-Sec-Return = "501";
      set req.http.X-Sec-RuleInfo = "Persistent Universal PDF XSS attack";
      set req.http.X-Sec-RuleName = "WEB_ATTACK/UPDF_XSS";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "950018";
      call sec_sev1;
   }
   ## REQUEST_HEADERS, 
   # skipped   REQUEST_HEADERS rx  http:\/\/[\w\.]+?\/.*?\.pdf\b[^\x0d\x0a]*#
   ## XML, :/*
   # AC /* 
   # skipped   XML rx /* http:\/\/[\w\.]+?\/.*?\.pdf\b[^\x0d\x0a]*#
   ## REQUEST_FILENAME, 
   ## Rule: REQUEST_FILENAME rx :
   if(req.url ~ "[\n\r]\s*\b(to|b?cc)\b\s*:.*?\@"){
      set req.http.X-Sec-RuleInfo = "Email Injection Attack";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "950019";
      call sec_sev1;
   }
   ## ARGS, 
   ## Rule: ARGS rx :
   if(req.url ~ "[\n\r]\s*\b(to|b?cc)\b\s*:.*?\@"){
      set req.http.X-Sec-RuleInfo = "Email Injection Attack";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "950019";
      call sec_sev1;
   }
   ## ARGS_NAMES, 
   ## Rule: ARGS_NAMES rx :
   if(req.url ~ "[\n\r]\s*\b(to|b?cc)\b\s*:.*?\@"){
      set req.http.X-Sec-RuleInfo = "Email Injection Attack";
      set req.http.X-Sec-Severity = "2";
      set req.http.X-Sec-RuleId = "950019";
      call sec_sev1;
   }
   ## REQUEST_HEADERS, 
   # skipped   REQUEST_HEADERS rx  [\n\r]\s*\b(to|b?cc)\b\s*:.*?\@
   ## XML, :/*
   # AC /* 
   # skipped   XML rx /* [\n\r]\s*\b(to|b?cc)\b\s*:.*?\@
   ## REQUEST_URI, 
   ## Rule: REQUEST_URI rx :
   if(req.url ~ "%250[ad]"){
      set req.http.X-Sec-Return = "400";
      set req.http.X-Sec-RuleInfo = "HTTP Response Splitting Attack";
      set req.http.X-Sec-Severity = "1";
      set req.http.X-Sec-RuleId = "950910";
      call sec_sev1;
   }
   ## REQUEST_HEADERS, 
   # skipped   REQUEST_HEADERS rx  %250[ad]
   ## REQUEST_HEADERS_NAMES, 
   ## Rule: REQUEST_HEADERS_NAMES rx :
   ## REQUEST_FILENAME, 
   ## Rule: REQUEST_FILENAME rx :
   if(req.url ~ "(\bhttp\/(0\.9|1\.[01])|<(html|meta)\b)"){
      set req.http.X-Sec-Return = "400";
      set req.http.X-Sec-RuleInfo = "HTTP Response Splitting Attack";
      set req.http.X-Sec-Severity = "1";
      set req.http.X-Sec-RuleId = "950911";
      call sec_sev1;
   }
   ## ARGS, 
   ## Rule: ARGS rx :
   if(req.url ~ "(\bhttp\/(0\.9|1\.[01])|<(html|meta)\b)"){
      set req.http.X-Sec-Return = "400";
      set req.http.X-Sec-RuleInfo = "HTTP Response Splitting Attack";
      set req.http.X-Sec-Severity = "1";
      set req.http.X-Sec-RuleId = "950911";
      call sec_sev1;
   }
   ## ARGS_NAMES, 
   ## Rule: ARGS_NAMES rx :
   if(req.url ~ "(\bhttp\/(0\.9|1\.[01])|<(html|meta)\b)"){
      set req.http.X-Sec-Return = "400";
      set req.http.X-Sec-RuleInfo = "HTTP Response Splitting Attack";
      set req.http.X-Sec-Severity = "1";
      set req.http.X-Sec-RuleId = "950911";
      call sec_sev1;
   }
   ## XML, :/*
   # AC /* 
   # skipped   XML rx /* (\bhttp\/(0\.9|1\.[01])|<(html|meta)\b)
}

