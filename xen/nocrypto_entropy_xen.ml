open Lwt

open Nocrypto
open Uncommon

let attach e g =
  let open Fortuna.Accumulator in
  let acc = create ~g in
  Entropy_xen.add_handler e (add_rr ~acc)

let stash = ref None

let initialize () =
  lwt e = match !stash with
    | Some (e, tok) -> Entropy_xen.remove_handler e tok ; return e
    | None          -> Entropy_xen.connect () in
  lwt tok = attach e !Rng.generator in
  return (stash := Some (e, tok))

let sources () =
  Option.map ~f:(Entropy_xen.sources &. fst) !stash
