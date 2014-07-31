
let includes = "
#include \"sha2.h\"
#include \"md5.h\"
#include \"rijndael.h\"
#include \"d3des.h\"
"

let c_stubs  = "src/native/nc_generated_stubs.c" 
let ml_stubs = "src/nc_generated.ml" 

let with_formatter ~path f =
  let chan = open_out path in
  f Format.(formatter_of_out_channel chan); close_out chan

let _ =

  with_formatter ~path:c_stubs (fun fmt ->
    Format.fprintf fmt "%s" includes ;
    Cstubs.write_c fmt ~prefix:"nocrypto" (module Native.Bindings));

  with_formatter ~path:ml_stubs (fun fmt ->
    Cstubs.write_ml fmt ~prefix:"nocrypto" (module Native.Bindings))
