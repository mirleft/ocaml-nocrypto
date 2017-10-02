(** [Uncommon] is a [Common], now with less name clashes. *)

type 'a one = One of 'a

let cdiv (x : int) (y : int) =
  if x > 0 && y > 0 then (x + y - 1) / y
  else if x < 0 && y < 0 then (x + y + 1) / y
  else x / y

let align ~block n = cdiv n block * block

let imin (a : int) (b : int) = if a < b then a else b

let (&.) f g = fun h -> f (g h)

let id x = x

let rec until p f =
  let r = f () in if p r then r else until p f

module Raise = struct

  open Printf

  let tag = (^) "Nocrypto: "

  let invalid fmt = Format.ksprintf invalid_arg ("Nocrypto: " ^^ fmt)
end

module Option = struct

  let getf a b = function None -> a b | Some x -> x

  let (>>=) a fb = match a with Some x -> fb x | _ -> None
  let (>>|) a f = match a with Some x -> Some (f x) | _ -> None

  let v_map ~def ~f = function
    | Some x -> f x
    | None   -> def

  let get ~def = function
    | Some x -> x
    | None   -> def

  let map ~f = function
    | Some x -> Some (f x)
    | None   -> None

  let cond ~f = function
    | Some x -> ignore (f x)
    | None   -> ()
end

type 'a iter = ('a -> unit) -> unit

let iter1 a     f = f a
let iter2 a b   f = f a; f b
let iter3 a b c f = f a; f b; f c

let string_fold ~f ~z str =
  let st = ref z in
  ( String.iter (fun c -> st := f !st c) str  ; !st )

let bytes bits = cdiv bits 8

(* The Sexplib hack... *)
module Z = struct
  include Z

  let two   = ~$2
  let three = ~$3

  open Sexplib.Conv
  let sexp_of_t z = sexp_of_string (Z.to_string z)
  let t_of_sexp s = Z.of_string (string_of_sexp s)
end

module Cs = struct

  open Cstruct

  let empty = create 0

  let null cs = len cs = 0

  let append cs1 cs2 =
    let l1 = len cs1 and l2 = len cs2 in
    let cs = create (l1 + l2) in
    blit cs1 0 cs 0 l1 ;
    blit cs2 0 cs l1 l2 ;
    cs

  let (<+>) = append

  let ct_eq cs1 cs2 =
    let rec go ok i = function
      | n when n >= 8 ->
          go (LE.(get_uint64 cs1 i = get_uint64 cs2 i) && ok) (i + 8) (n - 8)
      | n when n >= 4 ->
          go (LE.(get_uint32 cs1 i = get_uint32 cs2 i) && ok) (i + 4) (n - 4)
      | n when n >= 2 ->
          go (LE.(get_uint16 cs1 i = get_uint16 cs2 i) && ok) (i + 2) (n - 2)
      | 1             -> (get_uint8 cs1 i = get_uint8 cs2 i) && ok
      | _             -> ok
    in
    let n1 = len cs1 and n2 = len cs2 in
    go true 0 (imin n1 n2) && n1 = n2

  let ct_find_uint8 ?(off=0) ~f cs =
    let rec go acc i = function
      | 0 -> acc
      | n ->
          let acc = match (acc, f (get_uint8 cs i)) with
            | (None, true) -> Some i
            | _            -> acc in
          go acc (succ i) (pred n) in
    go None off (len cs - off)

  let clone ?(off = 0) ?len cs =
    let len = match len with None -> cs.len - off | Some x -> x in
    let cs' = create len in
    ( blit cs off cs' 0 len ; cs' )

  let xor_into src dst n =
    if n > imin (len src) (len dst) then
      Raise.invalid "Uncommon.Cs.xor_into: buffers to small (need %d)" n
    else Native.xor_into src.buffer src.off dst.buffer dst.off n

  let xor cs1 cs2 =
    let len = imin (len cs1) (len cs2) in
    let cs  = clone ~len cs2 in
    ( xor_into cs1 cs len ; cs )

  let create ?(init=0x00) n = let cs = create n in ( memset cs init ; cs )

  let is_prefix cs0 cs = cs0.len <= cs.len && equal cs0 (sub cs 0 cs0.len)

  let set_msb bits cs =
    if bits > 0 then
      let n = len cs in
      let rec go width = function
        | i when i = n     -> ()
        | i when width < 8 ->
            set_uint8 cs i (get_uint8 cs i lor (0xff lsl (8 - width)))
        | i ->
            set_uint8 cs i 0xff ; go (width - 8) (succ i) in
      go bits 0

  let split2 cs l =
    (sub cs 0 l, sub cs l (len cs - l))

  let split3 cs l1 l2 =
    let l12 = l1 + l2 in
    (sub cs 0 l1, sub cs l1 l2, sub cs l12 (len cs - l12))

  let rpad cs size x =
    let l = len cs and cs' = Cstruct.create size in
    if size < l then Raise.invalid "Uncommon.Cs.rpad: size < len";
    blit cs 0 cs' 0 l ;
    memset (sub cs' l (size - l)) x ;
    cs'

  let lpad cs size x =
    let l = len cs and cs' = Cstruct.create size in
    if size < l then Raise.invalid "Uncommon.Cs.lpad: size < len";
    blit cs 0 cs' (size - l) l ;
    memset (sub cs' 0 (size - l)) x ;
    cs'

  let of_bytes, of_int32s, of_int64s =
    let aux k set xs =
      let cs = Cstruct.create @@ List.length xs * k in
      List.iteri (fun i x -> set cs (i * k) x) xs;
      cs
    in
    (aux 1 set_uint8, aux 4 BE.set_uint32, aux 8 BE.set_uint64)

  let b x =
    let cs = Cstruct.create 1 in ( set_uint8 cs 0 x ; cs )

  let rec shift_left_inplace cs = function
    | 0 -> ()
    | bits when bits mod 8 = 0 ->
        let off = bits / 8 in
        blit cs off cs 0 (cs.len - off) ;
        memset (shift cs (cs.len - off)) 0x00
    | bits when bits < 8 ->
        let foo = 8 - bits in
        for i = 0 to cs.len - 2 do
          let b1 = get_uint8 cs i
          and b2 = get_uint8 cs (i + 1) in
          set_uint8 cs i ((b1 lsl bits) lor (b2 lsr foo))
        done ;
        set_uint8 cs (cs.len - 1) @@ get_uint8 cs (cs.len - 1) lsl bits
    | bits ->
        shift_left_inplace cs (8 * (bits / 8)) ;
        shift_left_inplace cs (bits mod 8)

  let rec shift_right_inplace cs = function
    | 0 -> ()
    | bits when bits mod 8 = 0 ->
        let off = bits / 8 in
        blit cs 0 cs off (cs.len - off) ;
        memset (sub cs 0 off) 0x00
    | bits when bits < 8 ->
        let foo = 8 - bits in
        for i = cs.len - 1 downto 1 do
          let b1 = get_uint8 cs i
          and b2 = get_uint8 cs (i - 1) in
          set_uint8 cs i ((b2 lsl foo) lor (b1 lsr bits))
        done ;
        set_uint8 cs 0 @@ get_uint8 cs 0 lsr bits
    | bits ->
        shift_right_inplace cs (8 * (bits / 8));
        shift_right_inplace cs (bits mod 8)

  let of_hex str =
    let hexdigit = function
      | 'a' .. 'f' as x -> int_of_char x - 87
      | 'A' .. 'F' as x -> int_of_char x - 55
      | '0' .. '9' as x -> int_of_char x - 48
      | x               -> Raise.invalid "of_hex: `%c'" x
    in
    let whitespace = function
      | ' ' | '\t' | '\r' | '\n' -> true
      | _                        -> false
    in
    match
      string_fold
      ~f:(fun (cs, i, acc) -> function
          | char when whitespace char -> (cs, i, acc)
          | char ->
              match (acc, hexdigit char) with
              | (None  , x) -> (cs, i, Some (x lsl 4))
              | (Some y, x) -> set_uint8 cs i (x lor y) ; (cs, succ i, None))
      ~z:(create (String.length str), 0, None)
      str
    with
    | (_ , _, Some _) -> Raise.invalid "of_hex: dangling nibble"
    | (cs, i, _     ) -> sub cs 0 i


  let (lsl) cs bits =
    let cs' = clone cs in
    shift_left_inplace cs' bits ; cs'

  and (lsr) cs bits =
    let cs' = clone cs in
    shift_right_inplace cs' bits ; cs'

  and (lxor) cs1 cs2 = xor cs1 cs2

end

module Arr = struct

  let mem x arr =
    let rec scan = function
      | -1 -> false
      | n  -> arr.(n) = x || scan (pred n) in
    scan (Array.length arr - 1)
end

(* Random stuff needed for other modules because deps. *)
module Boot = struct

  (* Should be thrown be generators and live in Rng, but Rng needs to
   * instantiate Fortuna for the latter can't depend on the former. *)
  exception Unseeded_generator

end

let bracket ~init ~fini f =
  let a = init () in
  match f a with
  | exception exn -> fini a; raise exn
  | res           -> fini a; res
