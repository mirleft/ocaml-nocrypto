open Common
open Hash
open Cstruct

module AES = Block_cipher.AES.Raw

let block_size = AES.block_size

exception Unseeded_generator

type g =
  { ctr            : Cstruct.t
  ; mutable key    : Cstruct.t * AES.ekey
  ; mutable trap   : (unit -> unit) option
  ; mutable seeded : bool
  }

let incr cs =
  let rec loop = function
    | 16 -> ()
    | i  ->
        let b = Int64.(succ @@ LE.get_uint64 cs i) in
        LE.set_uint64 cs i b ;
        if b = 0x00L then loop (i + 8) in
  loop 0

let create () =
  let k = Cs.create_with 32 0 in
  { ctr    = Cs.create_with 16 0
  ; key    = (k, AES.e_of_secret k)
  ; trap   = None
  ; seeded = false
  }

let clone ~g: { ctr ; seeded ; key } =
  { ctr = Cs.clone ctr ; key ; seeded ; trap = None }

(* XXX
 * We _might_ want to erase the old key, but the entire topic is a can of
 * worms in a memory-managed setting. What with compactifying GC and all. *)
let exchange_key ~g key = g.key <- (key, AES.e_of_secret key )

let reseedv ~g css =
  exchange_key ~g @@ SHAd256.digestv (fst g.key :: css) ;
  incr g.ctr ;
  g.seeded <- true

let reseed ~g cs = reseedv ~g [cs]

let aes_ctr_blocks ~g: { ctr ; key = (_, k) } blocks =
  let result = Cstruct.create @@ blocks lsl 4 in
  let rec loop res = function
    | 0 -> result
    | n ->
        ( AES.encrypt_block k ctr res ; incr ctr ) ;
        loop (shift res 16) (pred n) in
  loop result blocks

let generate_rekey ~g bytes =
  let r1 = aes_ctr_blocks ~g (cdiv bytes 16)
  and r2 = aes_ctr_blocks ~g 2 in
  exchange_key ~g r2 ;
  sub r1 0 bytes

let generate ~g bytes =
  if not g.seeded then raise Unseeded_generator ;
  let rec chunk = function
    | 0 -> []
    | n ->
        let n' = min n 0x10000 in
        generate_rekey ~g n' :: chunk (n - n')
  in
  ( match g.trap with None -> () | Some f -> g.trap <- None ; f () );
  Cs.concat @@ chunk bytes


module Accumulator = struct

  type t = {
    mutable count : int ;
    pools         : SHAd256.t array ;
    gen           : g ;
  }

  let create ~g = {
    pools = Array.init 32 (fun _ -> SHAd256.init ()) ;
    count = 0 ;
    gen   = g
  }

  let fire acc =
    let r   = acc.count + 1 in
    let ent =
      let rec collect = function
        | 32 -> []
        | i  ->
            match r land (1 lsl i - 1) with
            | 0 ->
                let h = acc.pools.(i) in
                acc.pools.(i) <- SHAd256.init () ;
                SHAd256.get h :: collect (succ i)
            | _ -> collect (succ i)
      in
      collect 0
    in
    acc.count <- r ;
    reseedv ~g: acc.gen ent

  let add ~acc ~src ~pool data =
    let pool = pool land 0x1f
    and src  = src  land 0xff in
    let h = acc.pools.(pool) in
    SHAd256.feed h (Cs.of_bytes [ src ; len data ]) ;
    SHAd256.feed h data ;
    (* XXX This is clobbered on multi-pool. *)
    acc.gen.trap <- Some (fun () -> fire acc)

  (* XXX
   * Schneier recommends against using generator-imposed pool-seeding schedule
   * but it just makes for a horrid api.
   *)
  let add_rr ~acc =
    let pool = ref 0 in
    fun ~src data ->
      add ~acc ~src ~pool: !pool data ;
      Pervasives.incr pool

end

