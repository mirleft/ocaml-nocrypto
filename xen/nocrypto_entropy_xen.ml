open Lwt

open Nocrypto
open Uncommon

module E = Entropy_xen

type t = { e : E.t ; token : E.token ; g : Rng.g }

let attach e g =
  let One acc = Rng.accumulate (Some g) in
  E.add_handler e acc

let active = ref None

let initialize () =
  let g = !Rng.generator in
  let register e =
    lwt token = attach e g in return (active := Some { e ; token ; g }) in
  match !active with
  | Some t when t.g == g -> return_unit
  | Some t               -> E.remove_handler t.e t.token ; register t.e
  | None                 -> E.connect () >>= register

let sources () =
  Option.map ~f:(fun { e; _ } -> Entropy_xen.sources e) !active
