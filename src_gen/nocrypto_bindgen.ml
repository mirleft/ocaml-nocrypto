
let with_formatter ~path f =
  let chan = open_out path in
  f Format.(formatter_of_out_channel chan);
  close_out chan

let _ =

  with_formatter
    ~path:"src/native/nocrypto_generated_stubs.c"
    (fun fmt ->
      Format.fprintf fmt "#include \"nocrypto_stubs.h\"\n\n";
      Cstubs.write_c fmt ~prefix:"nocrypto" (module Bindings.Make));

  with_formatter
    ~path:"src/nocrypto_generated.ml"
    (fun fmt ->
      Cstubs.write_ml fmt ~prefix:"nocrypto" (module Bindings.Make))
