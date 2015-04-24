
open Lwt

let attach e g =
  let open Nocrypto.Fortuna.Accumulator in
  let acc = create ~g in
  Entropy_xen.add_handler e (add_rr ~acc)

let stash = ref None

let initialize () =
  lwt e = match !stash with
    | Some (e, tok) -> Entropy_xen.remove_handler e tok ; return e
    | None          -> Entropy_xen.connect () in
  lwt tok = attach e !Nocrypto.Rng.generator in
  return (stash := Some (e, tok))
