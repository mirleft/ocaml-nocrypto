
open Cstruct

let sym     = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
let padding = '='

let (emap, dmap) =
  let make_ht f =
    let ht = Hashtbl.create 64 in
    for i = 0 to String.length sym - 1 do f ht i sym.[i] done ;
    ht in
  (make_ht Hashtbl.add),
  (make_ht (fun ht i c -> Hashtbl.add ht c i))


let padding_size cs =
  let is_pad i = if get_char cs i = padding then 1 else 0 in
  match len cs with
  | 0 -> 0
  | 1 -> is_pad 0
  | n -> is_pad (n - 1) + is_pad (n - 2)

let decode cs =
  let n  = len cs in
  let n' = 3 * n / 4 - padding_size cs in
  let r = create n' in
  let rec go leftover bits rbyte wbyte =
    if rbyte >= n then
      ()
    else
      if bits >= 8 then
        ( let nbits = bits - 8 in
          let tval = (leftover asr nbits) land 0xFF in
          let lo = leftover land (pred (1 lsl nbits)) in
          set_uint8 r wbyte tval;
          go lo
             nbits
             rbyte
             (succ wbyte) )
      else
        let ch = char_of_int (get_uint8 cs rbyte) in
        if ch = padding then
          ()
        else
          let dec = Hashtbl.find dmap ch in
          (* we better ensure dec is sane (and byte was in dmap) *)
          (* dec is 6 bit, thus shift leftover by 6 *)
          go ((leftover lsl 6) + dec)
             (bits + 6)
             (succ rbyte)
             wbyte
  in
  go 0 0 0 0;
  r
