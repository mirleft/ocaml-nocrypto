open Ocamlbuild_plugin

let () = dispatch Ocb_stubblr.(
  init & ccopt_flags ~tags:["accelerate"] "-DACCELERATE -msse2 -maes"
  (* <= 4.02.X *) & Ocb_stubblr.ccopt_flags "--std=c99 -Wall -Wextra -O3"
)
