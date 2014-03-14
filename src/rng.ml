open Common

module type Rng = sig
  type g
  val generate : ?g:g -> int -> Cstruct.t
  val block : int
end

module Rng_api (Rng : Rng) = struct

  module N_gen (N : Numeric.T) = struct

    (* If there was only, like, an instruction doing `ceil (log2 n)`... *)

    let bits i =
      let rec scan acc bound = function
        | i when i = N.zero -> acc
        | i when i = N.one  -> acc + 1
        | i ->
            let mid   = bound / 2 in
            let upper = N.(i lsr mid) in
            if upper = N.zero then
              scan acc (bound - mid) i
            else scan (acc + mid) (bound - mid) upper in
      scan 0 N.(bound i) i

    let of_bits_be cs b =
      let open Cstruct in
      let open BE in
      (* XXX read larger chunks *)

      let rec loop acc i = function
        | 0 -> acc
        | b when b <= 8 ->
            let x  = get_uint8 cs i
            and b' = 8 - b in
            N.((of_int x lsr b') + (acc lsl b))
        | b ->
            let x = get_uint8 cs i in
            loop N.(of_int x + (acc lsl 8)) (succ i) (b - 8) in
      loop N.zero 0 b

    let gen ?g n =

      let size   = bits (N.pred n) in
      let octets = cdiv size 8 in
      let batch  = cdiv (octets * 4) Rng.block * Rng.block in

      let rec attempt cs =
        try
          let x = of_bits_be cs size in
          if x < n then x else attempt (Cstruct.shift cs octets)
        with | Invalid_argument _ -> attempt Rng.(generate ?g batch) in

      if n < N.zero then invalid_arg "gen: negative bound"
      else attempt Rng.(generate ?g batch)

    let gen_r ?g a b = N.(a + gen ?g (b - a))

  end

  module Int   = N_gen (Numeric.Int)
  module Int32 = N_gen (Numeric.Int32)
  module Int64 = N_gen (Numeric.Int64)
  module Z     = N_gen (Numeric.Z)

end

let g       = Fortuna.create ()
let reseedv = Fortuna.reseedv ~g
and reseed  = Fortuna.reseed  ~g

module Accumulator = struct
  let acc    = Fortuna.Accumulator.create ~g
  let add    = Fortuna.Accumulator.add    ~acc
  let add_rr = Fortuna.Accumulator.add_rr ~acc
end

module Rng = Rng_api ( struct
  type g = Fortuna.g
  let generate ?(g = g) n = Fortuna.generate ~g n
  let block = 0x10
end )

(* include Rng *)



(* crap *)



(* XXX Should obsolete this, hate measuring nat's bytes sizes. *)
let gen_z_bytes bytes =
  let rec loop acc = function
    | 0 -> acc
    | n ->
        let i = Random.int 0x100 in
        loop Z.((shift_left acc 8) lor of_int i) (pred n) in
  loop Z.zero bytes

(* XXX unsolved *)
(* [a, b) *)
let gen_z a b =
(*   let rec loop acc = function
    | n when n <= Z.zero -> acc
    | n ->
        let (n_part, n_rest) =
          Z.(n land (of_int 0xff), shift_right n 8) in
        let i    = Random.int Z.(to_int n_part) in
        let acc' = Z.((shift_left acc 8) lor of_int i) in
        loop acc' n_rest in
  loop Z.zero limit *)
  (* fake *)
  let range = Z.(b - a) in
  let rnd   = Random.int64 Int64.max_int in
  Z.((of_int64 rnd) mod range + a)
