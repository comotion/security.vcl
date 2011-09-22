sub vcl_recv {
   set req.http.X-Sec-Module = "2vcl";
   ## &TX, :ARG_NAME_LENGTH
   # AC ARG_NAME_LENGTH 
   # skipped  & TX eq ARG_NAME_LENGTH 1
   ## ARGS_NAMES, 
   # skipped   ARGS_NAMES gt  %{tx.arg_name_length}
   ## &TX, :ARG_LENGTH
   # AC ARG_LENGTH 
   # skipped  & TX eq ARG_LENGTH 1
   ## ARGS, 
   # skipped   ARGS gt  %{tx.arg_length}
   ## &TX, :MAX_NUM_ARGS
   # AC MAX_NUM_ARGS 
   # skipped  & TX eq MAX_NUM_ARGS 1
   ## &ARGS, 
   # skipped  & ARGS gt  %{tx.max_num_args}
   ## &TX, :TOTAL_ARG_LENGTH
   # AC TOTAL_ARG_LENGTH 
   # skipped  & TX eq TOTAL_ARG_LENGTH 1
   ## ARGS_COMBINED_SIZE, 
   # skipped   ARGS_COMBINED_SIZE gt  %{tx.total_arg_length}
   ## &TX, :MAX_FILE_SIZE
   # AC MAX_FILE_SIZE 
   # skipped  & TX eq MAX_FILE_SIZE 1
   ## FILES_SIZES, 
   # skipped   FILES_SIZES gt  %{tx.max_file_size}
   ## &TX, :COMBINED_FILE_SIZES
   # AC COMBINED_FILE_SIZES 
   # skipped  & TX eq COMBINED_FILE_SIZES 1
   ## FILES_COMBINED_SIZE, 
   # skipped   FILES_COMBINED_SIZE gt  %{tx.combined_file_sizes}
}

