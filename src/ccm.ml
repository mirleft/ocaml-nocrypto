
let (<+>) = Common.Cs.append


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
  assert (small_q > 0 && small_q > bits q) ;
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
  Common.Cs.rpad b (size + (16 - size mod 16)) 0

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
       Common.Cs.of_bytes [0xff ; 0xfe] <+> buf
    | x                               ->
       let buf = Cstruct.create 8 in
       Cstruct.BE.set_uint64 buf 0 (Int64.of_int x) ;
       Common.Cs.of_bytes [0xff ; 0xff] <+> buf
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

let a = Common.Cs.of_bytes [ 0x00 ; 0x01 ; 0x02 ; 0x03 ; 0x04 ; 0x05 ; 0x06 ; 0x07 ]
let n = Common.Cs.of_bytes [ 0x10 ; 0x11 ; 0x12 ; 0x13 ; 0x14 ; 0x15 ; 0x16 ]
let p = Common.Cs.of_bytes [ 0x20 ; 0x21 ; 0x22 ; 0x23 ]
let k = Block_cipher.AES.Raw.e_of_secret (Common.Cs.of_bytes [ 0x40 ; 0x41 ; 0x42 ; 0x43 ; 0x44 ; 0x45 ; 0x46 ; 0x47 ; 0x48 ; 0x49 ; 0x4A ; 0x4B ; 0x4C ; 0x4D ; 0x4E ; 0x4F ])

let gen_block idx nonce key =
  let ctr = gen_ctr nonce idx in
  Block_cipher.AES.Raw.encrypt_block ~key ctr ctr ;
  ctr

let blocks dlen nonce key =
  let ctrblocks = Common.cdiv dlen 16 + 1 in
  let rec ctrloop idx = function
    | 1 -> Common.Cs.empty
    | n ->
       let ctr = gen_block idx nonce key in
       ctr <+> ctrloop (idx + 1) (n - 1)
  in
  ctrloop 1 ctrblocks

let mac nonce adata p tlen key =
  let ada = match adata with
    | Some x -> gen_adata x
    | None   -> Common.Cs.empty
  in
  let blocks = (format nonce adata p tlen) <+> ada <+> pad16 p in

  let rec loop last block =
    match Cstruct.len block with
    | 0 -> last
    | _ ->
       Common.Cs.xor_into last block 16 ;
       Block_cipher.AES.Raw.encrypt_block ~key block block ;
       loop (Cstruct.sub block 0 16)
            (Cstruct.shift block 16)
  in
  let last = loop (Common.Cs.create_with 16 0) blocks in
  Cstruct.sub last 0 tlen

let ccm key nonce ?adata data tlen =
  let t = mac nonce adata data tlen key in
  let firstblock = gen_block 0 nonce key
  and blocks = blocks (Cstruct.len data) nonce key
  in
  Common.Cs.xor_into blocks data (Cstruct.len data) ;
  Common.Cs.xor_into firstblock t (Cstruct.len t) ;
  data <+> t

let decrypt key nonce ?adata cipher tlen =
  let pclen = Cstruct.len cipher - tlen in
  assert (pclen > 0);
  let firstblock = gen_block 0 nonce key
  and blocks = blocks pclen nonce key
  in
  Common.Cs.xor_into blocks cipher pclen ;
  let p = Cstruct.sub cipher 0 pclen in
  Common.Cs.xor_into firstblock (Cstruct.sub cipher pclen tlen) tlen ;
  let t = Cstruct.sub cipher pclen tlen in
  let t' = mac nonce adata p tlen key in
  (* assert t' = t *)
  Cstruct.hexdump t' ; Cstruct.hexdump t ;
  p
