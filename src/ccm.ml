open Common

let (<+>) = Cs.append

let valid_t = [ 4 ; 6 ; 8 ; 10 ; 12 ; 14 ; 16 ] (* octet length of mac *)
let valid_small_q = [ 2 ; 3 ; 4 ; 5 ; 6 ; 7 ; 8 ] (* octet length of octet length of plain *)
let valid_n = [ 7 ; 8 ; 9 ; 10 ; 11 ; 12 ; 13 ] (* octet length of nonce *)

let bits n =
  let rec go acc = function
    | 0 -> acc
    | n -> go (acc + 1) (n lsr 1)
  in
  go 0 n

let flags bit6 len1 len2 =
  assert (len1 < 8 && len2 < 8);
  let byte = Cstruct.create 1
  and data = bit6 lsl 6 + len1 lsl 3 + len2 in
  Cstruct.set_uint8 byte 0 data ;
  byte

let encode_len size value =
  let b = Cstruct.create size in
  let rec ass num = function
    | 0 -> Cstruct.set_uint8 b 0 num ; b
    | m -> Cstruct.set_uint8 b m (num land 0xff) ; ass (num lsr 8) (pred m)
  in
  ass value (pred size)

let format nonce adata plain t (* mac len *) =
  let q = Cstruct.len plain in
  (* n + q = 15 *)
  (* a < 2 ^ 64 *)
  let n = Cstruct.len nonce in
  let small_q = 15 - n in
  assert (List.mem small_q valid_small_q) ;
  assert (List.mem t valid_t) ;
  assert (List.mem n valid_n) ;
  (* first byte (flags): *)
  (* reserved | adata | (t - 2) / 2 | q - 1 *)
  let b6 = match adata with
    | Some _ -> 1
    | None   -> 0
  in
  let flag = flags b6 ((t - 2) / 2) (small_q - 1) in
  (* first octet block:
     0          : flags
     1..15 - q  : N
     16 - q..15 : Q *)
  let qblock = encode_len small_q q in
  flag <+> nonce <+> qblock

let pad16 b =
  let size = Cstruct.len b in
  if size mod 16 = 0 then
    b
  else
    Cs.rpad b (size + (16 - size mod 16)) 0

let gen_adata a =
  let lbuf =
    match Cstruct.len a with
    | x when x < (1 lsl 16 - 1 lsl 8) ->
       let buf = Cstruct.create 2 in
       Cstruct.BE.set_uint16 buf 0 x ;
       buf
    | x when x < (1 lsl 32)           ->
       let buf = Cstruct.create 4 in
       Cstruct.BE.set_uint32 buf 0 (Int32.of_int x) ;
       Cs.of_bytes [0xff ; 0xfe] <+> buf
    | x                               ->
       let buf = Cstruct.create 8 in
       Cstruct.BE.set_uint64 buf 0 (Int64.of_int x) ;
       Cs.of_bytes [0xff ; 0xff] <+> buf
  in
  pad16 (lbuf <+> a)

let gen_ctr_stub nonce =
  let n = Cstruct.len nonce in
  let small_q = 15 - n in
  let flag = flags 0 0 (small_q - 1) in
  (flag <+> nonce, small_q)

let gen_ctr_post i small_q =
  let count = encode_len small_q i in
  count

let gen_ctr nonce i =
  let pre, q = gen_ctr_stub nonce in
  pre <+> gen_ctr_post i q

let gen_block cipher idx nonce key =
  let ctr = gen_ctr nonce idx in
  cipher ~key ctr ctr ;
  ctr

let blocks cipher dlen nonce key =
  let ctrblocks = cdiv dlen 16 + 1 in
  let rec ctrloop idx = function
    | 1 -> Cs.empty
    | n ->
       let ctr = gen_block cipher idx nonce key in
       ctr <+> ctrloop (idx + 1) (n - 1)
  in
  ctrloop 1 ctrblocks

let mac cipher nonce adata p tlen key =
  let ada = match adata with
    | Some x -> gen_adata x
    | None   -> Cs.empty
  in
  let blocks = (format nonce adata p tlen) <+> ada <+> pad16 p in

  let rec loop last block =
    match Cstruct.len block with
    | 0 -> last
    | _ ->
       Cs.xor_into last block 16 ;
       cipher ~key block block ;
       loop (Cstruct.sub block 0 16)
            (Cstruct.shift block 16)
  in
  let last = loop (Cs.create_with 16 0) blocks in
  Cstruct.sub last 0 tlen

let generation_encryption ~cipher ~key ~nonce ~maclen ?adata data =
  let t = mac cipher nonce adata data maclen key in

  let firstblock = gen_block cipher 0 nonce key
  and blocks = blocks cipher (Cstruct.len data) nonce key
  in
  Cs.xor_into blocks data (Cstruct.len data) ;
  Cs.xor_into firstblock t (Cstruct.len t) ;
  data <+> t

let decryption_verification ~cipher ~key ~nonce ~maclen ?adata data =
  let pclen = Cstruct.len data - maclen in
  assert (pclen > 0);
  let firstblock = gen_block cipher 0 nonce key
  and blocks = blocks cipher pclen nonce key
  in
  Cs.xor_into blocks data pclen ;
  let p = Cstruct.sub data 0 pclen in
  Cs.xor_into firstblock (Cstruct.sub data pclen maclen) maclen ;
  let t = Cstruct.sub data pclen maclen in
  let t' = mac cipher nonce adata p maclen key in
  (* assert t' = t *)
  match Cs.equal t' t with
  | true  -> Some p
  | false -> None
