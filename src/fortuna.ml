open Common

module AES = Block_cipher.AES_raw

exception Unseeded_generator

type g = {
          ctr    : Cstruct.t ;
  mutable key    : (Cstruct.t * AES.key) ;
  mutable seeded : bool
}

let incr cs =
  let rec loop = function
    | 16 -> ()
    | i  ->
        let b = (1 + Cstruct.get_uint8 cs i) land 0xff in
        Cstruct.set_uint8 cs i b;
        if b = 0x00 then loop (succ i) in
  loop 0

let create () =
  let (ctr, k) = Cstruct_.(create_with 16 0, create_with 32 0) in
  { ctr ; key = (k, AES.create_e k) ; seeded = false }

let clone ~state: { ctr ; seeded ; key = (k, _) } =
  { ctr = Cstruct_.copy ctr ; key = (Cstruct_.copy k, AES.create_e k) ; seeded }

let exchange_key ~state key =
  let (k1, k2) = state.key in
  Cstruct_.cs_erase k1 ;
  AES.erase k2 ;
  state.key <- (key, AES.create_e key )

let reseed ~state cs =
  exchange_key ~state @@ SHA_d.digestv [ fst state.key ; cs ] ;
  incr state.ctr ;
  state.seeded <- true

let aes_ctr_blocks ~state: { ctr ; key = (_, k) } blocks =
  let result = Cstruct.create (blocks * 16) in
  let rec loop res = function
    | 0 -> result
    | n ->
        ( AES.encrypt_blk k ctr res ; incr ctr ) ;
        loop (Cstruct.shift res 16) (pred n) in
  loop result blocks

let generate_rekey ~state bytes =
  let r1 = aes_ctr_blocks ~state (div_ceil bytes 16)
  and r2 = aes_ctr_blocks ~state 2 in
  exchange_key ~state r2 ;
  Cstruct.sub r1 0 bytes

let generate ~state bytes =
  let rec stream = function
    | 0 -> []
    | n ->
        let n' = min n 0x10000 in
        generate_rekey ~state n' :: stream (n - n') in
  match state.seeded with
  | true  -> Cstruct_.concat (stream bytes)
  | false -> raise Unseeded_generator


let add_random ~r ~source ~pool data =
  match Cstruct.len data with
  | 0 -> ()
  | n ->
      let packet = Cstruct.create 2 in
      Cstruct.set_uint8 packet 0 source ;
      Cstruct.set_uint8 packet 1 pool ;
      (* feed the pool-hash *)
