open Ocamlbuild_plugin

let () = dispatch Ocb_stubblr.(
  init & ccopt_flags ~tags:["accelerate"] "-DACCELERATE -msse2 -maes";
)
