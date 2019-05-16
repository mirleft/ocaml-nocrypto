let evar  = "NOCRYPTO_ACCELERATE"
let needs = [`SSSE3; `AES; `PCLMULQDQ]
let flags = ["-DACCELERATE"; "-mssse3"; "-maes"; "-mpclmul"]

let _ =
  let auto = match Cpuid.supports needs with Ok true -> flags | _ -> [] in
  let fs = match Sys.getenv evar with
    "true" -> flags
  | "false" -> []
  | _ -> auto
  | exception Not_found -> auto in
  let cflags = match Sys.getenv_opt "CFLAGS" with
  | Some cflags -> [ cflags ]
  | None -> []
  in
  let fs = fs @ cflags in
  Format.(printf "(@[%a@])%!" (fun ppf -> List.iter (fprintf ppf "%s@ ")) fs)
  