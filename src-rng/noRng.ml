open Nocrypto_uncommon

type bits = int

exception Unseeded_generator = Boot.Unseeded_generator

module S = struct

  module type Generator = sig
    type g
    val block      : int
    val create     : unit -> g
    val generate   : g:g -> int -> Cstruct.t
    val reseed     : g:g -> Cstruct.t -> unit
    val accumulate : g:g -> [`Acc of source:int -> Cstruct.t -> unit]
    val seeded     : g:g -> bool
  end

  type 'a generator = (module Generator with type g = 'a)
  type g = Generator : ('a * bool * 'a generator) -> g

end

type g = S.g

let create (type a) ?g ?seed ?(strict=false) (m : a S.generator) =
  let module M = (val m) in
  let g = Option.get_or M.create () g in
  seed |> Option.cond ~f:(M.reseed ~g) ;
  S.Generator (g, strict, m)

let generator = ref (create (module Fortuna))

let get = function Some g -> g | None -> !generator

let generate ?(g = !generator) n =
  let S.Generator (g, _, m) = g in let module M = (val m) in M.generate ~g n

let reseed ?(g = !generator) cs =
  let S.Generator (g, _, m) = g in let module M = (val m) in M.reseed ~g cs

let accumulate g =
  let S.Generator (g, _, m) = get g in let module M = (val m) in M.accumulate ~g

let seeded g =
  let S.Generator (g, _, m) = get g in let module M = (val m) in M.seeded ~g

let block g =
  let S.Generator (_, _, m) = get g in let module M = (val m) in M.block

let strict g =
  let S.Generator (_, s, _) = get g in s


module type Number = Numbers.S

module type Arith = sig
  type t
  val gen      : ?g:g -> t -> t
  val gen_r    : ?g:g -> t -> t -> t
  val gen_bits : ?g:g -> ?msb:int -> int -> t
end

module Arith (N: Number) = struct

  type t = N.t

  let gen ?g n =
    if n < N.one then invalid_arg "Rng.gen: non-positive: %a" N.pp n;

    let bs     = block g in
    let bits   = N.(bit_size (n - one)) in
    let octets = bits // 8 in
    let batch  = if strict g then octets else 2 * octets // bs * bs in

    let rec attempt cs =
      if cs.Cstruct.len >= octets then
        let x = N.of_cstruct_be ~bits cs in
        if x < n then x else attempt (Cstruct.shift cs octets)
      else attempt (generate ?g batch) in
    attempt (generate ?g batch)

  let rec gen_r ?g a b =
    if strict g then
      let x = gen ?g b in if x < a then gen_r ?g a b else x
    else N.(a + gen ?g (b - a))

  let gen_bits ?g ?(msb = 0) bits =
    let res = generate ?g (bits // 8) in
    Cs.set_msb msb res ;
    N.of_cstruct_be ~bits res
end

module Int   = Arith (Numbers.Int)
module Int32 = Arith (Numbers.Int32)
module Int64 = Arith (Numbers.Int64)

module Generators = struct

  module Fortuna = Fortuna

  module Hmac_drgb = Hmac_drgb

  module Null = struct

    type g = Cstruct.t ref

    let block = 1

    let create () = ref Cstruct.empty

    let generate ~g n =
      try
        let (a, b) = Cstruct.split !g n in ( g := b ; a )
      with Invalid_argument _ -> raise Unseeded_generator

    let reseed ~g cs = g := Cs.(!g <+> cs)

    let seeded ~g = Cstruct.len !g > 0

    let accumulate ~g = `Acc (fun ~source:_ -> reseed ~g)
  end

end

module Private = struct
  let of_cstruct_be   = Numbers.Int.of_cstruct_be
  let of_cstruct_be32 = Numbers.Int32.of_cstruct_be
  let of_cstruct_be64 = Numbers.Int64.of_cstruct_be
  let bit_size   = Numbers.Int.bit_size
  let bit_size32 = Numbers.Int32.bit_size
  let bit_size64 = Numbers.Int64.bit_size
end

