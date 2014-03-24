
open Cstruct

let sym     = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
let padding = '='

let (emap, dmap) =
  let make_ht f =
    let ht = Hashtbl.create 64 in
    for i = 0 to String.length sym - 1 do f ht i sym.[i] done ;
    ht in
  (lazy (make_ht Hashtbl.add)),
  (lazy (make_ht (fun ht i c -> Hashtbl.add ht c i)))


let padding_size cs =
  let is_pad i = if get_char cs i = padding then 1 else 0 in
  match len cs with
  | 0 -> 0
  | 1 -> is_pad 0
  | n -> is_pad (n - 1) + is_pad (n - 2)

(* let decode cs =
  let n  = len cs in
  let n' = n / 4 - padding_size cs in
  let rec loop = function
    |  *)

