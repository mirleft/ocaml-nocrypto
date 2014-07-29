
open Cstruct

  let append cs1 cs2 =
    let l1 = len cs1 and l2 = len cs2 in
    let cs = create (l1 + l2) in
    blit cs1 0 cs 0 l1 ;
    blit cs2 0 cs l1 l2 ;
    cs

let (<+>) = append


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
  let q = len plain in
  (* n + q = 15 *)
  (* a < 2 ^ 64 *)
  let n = len nonce in
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

let cs_of_list l =
  let b = create (List.length l) in
  let rec go idx = function
    | []    -> ()
    | x::xs -> set_uint8 b idx x ; go (idx + 1) xs
  in
  go 0 l ;
  b

let pad16 b =
  let size = Cstruct.len b in
  Common.Cs.rpad b (size + (16 - size mod 16)) 0

let gen_adata a =
  let lbuf =
    match len a with
    | x when x < (1 lsl 16 - 1 lsl 8) ->
       let buf = create 2 in
       BE.set_uint16 buf 0 x ;
       buf
    | x when x < (1 lsl 32)           ->
       let buf = create 4 in
       BE.set_uint32 buf 0 (Int32.of_int x) ;
       cs_of_list [0xff ; 0xfe] <+> buf
    | x                               ->
       let buf = create 8 in
       BE.set_uint64 buf 0 (Int64.of_int x) ;
       cs_of_list [0xff ; 0xff] <+> buf
  in
  pad16 (lbuf <+> a)

let gen_ctr_stub nonce =
  let n = len nonce in
  let small_q = 15 - n in
  let flag = flags 0 0 (small_q - 1) in
  (flag <+> nonce, small_q)

let gen_ctr_post i small_q =
  let count = encode_len small_q i in
  count

let gen_ctr nonce i =
  let pre, q = gen_ctr_stub nonce in
  pre <+> gen_ctr_post i q

let a = cs_of_list [ 0x00 ; 0x01 ; 0x02 ; 0x03 ; 0x04 ; 0x05 ; 0x06 ; 0x07 ]
let n = cs_of_list [ 0x10 ; 0x11 ; 0x12 ; 0x13 ; 0x14 ; 0x15 ; 0x16 ]
let p = cs_of_list [ 0x20 ; 0x21 ; 0x22 ; 0x23 ]
let k = Block_cipher.AES.Raw.e_of_secret (cs_of_list [ 0x40 ; 0x41 ; 0x42 ; 0x43 ; 0x44 ; 0x45 ; 0x46 ; 0x47 ; 0x48 ; 0x49 ; 0x4A ; 0x4B ; 0x4C ; 0x4D ; 0x4E ; 0x4F ])

let ccm key nonce ?adata data tlen =
  let ada = match adata with
    | Some x -> gen_adata x
    | None   -> Common.Cs.empty
  in
  let bs = (format nonce adata data tlen) <+> ada <+> pad16 data in

  let mac blocks tlen =
    let rec loop last block =
      match len block with
      | 0 -> last
      | _ ->
         Common.Cs.xor_into last block 16 ;
         Block_cipher.AES.Raw.encrypt_block ~key block block ;
         loop (sub block 0 16)
              (shift block 16)
    in
    let last = loop (Common.Cs.create_with 16 0) blocks in
    sub last 0 tlen
  in

  let t = mac bs tlen in
  Cstruct.hexdump t ;

  let gen_block idx =
    let ctr = gen_ctr nonce idx in
    Block_cipher.AES.Raw.encrypt_block ~key ctr ctr ;
    ctr
  in

  let blocks data =
    let ctrblocks = Common.cdiv (len data) 16 + 1 in
    let rec ctrloop idx = function
      | 1 -> Common.Cs.empty
      | n ->
         let ctr = gen_block idx in
         ctr <+> ctrloop (idx + 1) (n - 1)
    in
    ctrloop 1 ctrblocks
  in

  let firstblock = gen_block 0 in

  Common.Cs.xor_into (blocks data) p (len p) ;
  Common.Cs.xor_into firstblock t (len t) ;
  let c = p <+> t in
  Printf.printf "c" ;
  hexdump c

let decrypt key nonce ?adata cipher tlen =
  let pclen = len cipher - tlen in
  assert (pclen > 0);
  let ctrblocks = Common.cdiv pclen 16 + 1 in
  let rec ctrloop idx = function
    | 0 -> []
    | n ->
       let ctr = gen_ctr nonce idx in
       Block_cipher.AES.Raw.encrypt_block ~key ctr ctr ;
       ctr :: ctrloop (idx + 1) (n - 1)
  in
  let blocks = ctrloop 0 ctrblocks in
  let block1 = List.hd (List.tl blocks) in
  Common.Cs.xor_into block1 cipher pclen ;
  let p = sub cipher 0 pclen in
  let block0 = List.hd blocks in
  Common.Cs.xor_into block0 (sub cipher pclen tlen) tlen ;
  let t = sub cipher pclen tlen in
  Printf.printf "t" ; hexdump t ;

  let ada = match adata with
    | Some x -> gen_adata x
    | None   -> Common.Cs.empty
  in
  let bs = (format nonce adata p tlen) <+> ada <+> pad16 p in
  let rec loop last block =
    match len block with
    | 0 -> last
    | _ ->
       Common.Cs.xor_into last block 16 ;
       Block_cipher.AES.Raw.encrypt_block ~key block block ;
       loop (sub block 0 16)
            (shift block 16)
  in
  let last = loop (Common.Cs.create_with 16 0) bs in
  let t' = sub last 0 tlen in
  (* assert t' = t *)
  Printf.printf "t'" ; hexdump t'
