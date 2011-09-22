sub vcl_recv {
   set req.http.X-Sec-Module = "2vcl";
   ## Script, 
   ## Rule: Script rx :
   ## &RESOURCE, :'/(niframes|nscripts|nlinks|nimages)/'
   # AA 
   # skipped  & RESOURCE eq niframes|nscripts|nlinks|nimages 0
   ## TX, :NIFRAMES
   # AC NIFRAMES 
   # skipped   TX eq NIFRAMES %{resource.niframes}
   ## TX, :NSCRIPTS
   # AC NSCRIPTS 
   # skipped   TX eq NSCRIPTS %{resource.nscripts}
   ## TX, :NLINKS
   # AC NLINKS 
   # skipped   TX eq NLINKS %{resource.nlinks}
   ## TX, :NIMAGES
   # AC NIMAGES 
   # skipped   TX eq NIMAGES %{resource.nimages}
   ## RESOURCE, :PROFILE_CONFIDENCE_COUNTER
   # AC PROFILE_CONFIDENCE_COUNTER 
   # skipped   RESOURCE lt PROFILE_CONFIDENCE_COUNTER 40
   ## TX, :NIFRAMES
   # AC NIFRAMES 
   # skipped   TX eq NIFRAMES %{resource.niframes}
   ## TX, :NSCRIPTS
   # AC NSCRIPTS 
   # skipped   TX eq NSCRIPTS %{resource.nscripts}
   ## TX, :NLINKS
   # AC NLINKS 
   # skipped   TX eq NLINKS %{resource.nlinks}
   ## TX, :NIMAGES
   # AC NIMAGES 
   # skipped   TX eq NIMAGES %{resource.nimages}
}

