open Ocamlbuild_plugin

let () = dispatch Ocb_stubblr.(
  init & ccopt ~tags:["accelerate"] "-DACCELERATE -msse2 -maes"
)
