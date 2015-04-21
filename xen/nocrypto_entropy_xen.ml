
open Lwt

let attach e g =
  let open Nocrypto.Fortuna.Accumulator in
  let acc = create ~g in
  Entropy_xen.add_handler e (add_rr ~acc)

let initialize () =
  Entropy_xen.connect () >>= fun (`Ok t) ->
    attach t !Nocrypto.Rng.generator
