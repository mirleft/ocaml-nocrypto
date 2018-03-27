open Ocamlbuild_plugin

let ocamlfind_and_pack = function
  | After_rules ->
     if !Options.use_ocamlfind then
       pflag ["ocaml"; "pack"] "package"
         (fun pkg -> S [A "-package"; A pkg]);
  | _ -> ()

let () = dispatch Ocb_stubblr.(
  init & ccopt ~tags:["accelerate"] "-DACCELERATE -mssse3 -maes -mpclmul"
  & ocamlfind_and_pack
)
