
open Common
open Hash

module Counter = Block_cipher.Counters.Inc_LE
module AES_CTR = Block_cipher.AES.CTR (Counter)

let block_size = AES_CTR.block_size

exception Unseeded_generator

(* XXX Locking!! *)
type g =
  { ctr            : Cstruct.t
  ; mutable secret : Cstruct.t
  ; mutable key    : AES_CTR.key
  ; mutable trap   : (unit -> unit) option
  ; mutable seeded : bool
  }

let create () =
  let k = Cs.create_with 32 0 in
  { ctr    = Cs.create_with 16 0
  ; secret = k
  ; key    = AES_CTR.of_secret k
  ; trap   = None
  ; seeded = false
  }

let clone ~g: { ctr ; seeded ; secret ; key } =
  { ctr = Cs.clone ctr ; secret ; key ; seeded ; trap = None }

let seeded ~g = g.seeded

(* XXX We might want to erase the old key. *)
let exchange_key ~g sec =
  g.secret <- sec ;
  g.key    <- AES_CTR.of_secret sec

let reseedv ~g css =
  exchange_key ~g @@ SHAd256.digestv (g.secret :: css) ;
  Counter.increment g.ctr ;
  g.seeded <- true

let reseed ~g cs = reseedv ~g [cs]

let stream ~g:{ ctr ; key ; _ } bytes =
  AES_CTR.stream ~ctr ~key bytes

let generate_rekey ~g bytes =
  let r1 = stream ~g bytes
  and r2 = stream ~g 32 in
  exchange_key ~g r2 ;
  r1

let generate ~g bytes =
  ( match g.trap with None -> () | Some f -> g.trap <- None ; f () );
  if not g.seeded then raise Unseeded_generator ;
  let rec chunk = function
    | i when i <= 0 -> []
    | n ->
        let n' = min n 0x10000 in
        generate_rekey ~g n' :: chunk (n - n')
  in
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

  let add ~acc ~source ~pool data =
    let pool   = pool land 0x1f
    and source = source land 0xff in
    let h = acc.pools.(pool) in
    SHAd256.feed h (Cs.of_bytes [ source ; Cstruct.len data ]) ;
    SHAd256.feed h data ;
    (* XXX This is clobbered on multi-pool. *)
    acc.gen.trap <- Some (fun () -> fire acc)

  (* XXX
   * Schneier recommends against using generator-imposed pool-seeding schedule
   * but it just makes for a horrid api.
   *)
  let add_rr ~acc =
    let pool = ref 0 in
    fun ~source data ->
      add ~acc ~source ~pool:!pool data ;
      incr pool

end

