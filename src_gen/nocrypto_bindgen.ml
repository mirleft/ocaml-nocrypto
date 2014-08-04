
let c_stubs  = "src/native/nocrypto_stubs.c"
let ml_stubs = "src/nocrypto_generated.ml"

let includes = "
#include \"sha2.h\"
#include \"md5.h\"
#include \"rijndael.h\"
#include \"d3des.h\"
"

let with_formatter ~path f =
  let chan = open_out path in
  f Format.(formatter_of_out_channel chan); close_out chan

let _ =

  with_formatter ~path:c_stubs (fun fmt ->
    Format.fprintf fmt "%s" includes ;
    Cstubs.write_c fmt ~prefix:"nocrypto" (module Bindings.Make));

  with_formatter ~path:ml_stubs (fun fmt ->
    Cstubs.write_ml fmt ~prefix:"nocrypto" (module Bindings.Make))
