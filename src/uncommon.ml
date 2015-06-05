(** [Uncommon] is a [Common], now with less name clashes. *)

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

  let invalid  fmt     = invalid_arg @@ tag fmt
  let invalid1 fmt a   = invalid_arg @@ tag (sprintf fmt a)
  let invalid2 fmt a b = invalid_arg @@ tag (sprintf fmt a b)
end

module Option = struct

  let v_map ~def ~f = function
    | Some x -> f x
    | None   -> def

  let value ~def = function
    | Some x -> x
    | None   -> def

  let map ~f = function
    | Some x -> Some (f x)
    | None   -> None
end

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

  let concat = function
    | []   -> create 0
    | [cs] -> cs
    | css  ->
        let result = create (lenv css) in
        let _ = List.fold_left
          (fun off cs ->
            let n = len cs in
            blit cs 0 result off n ;
            off + n
          ) 0 css in
        result

  let equal ?(mask = false) cs1 cs2 =

    let eq_with_mask cs1 cs2 =
      let rec loop ok i = function
        | n when n >= 8 ->
            loop (LE.(get_uint64 cs1 i = get_uint64 cs2 i) && ok) (i + 8) (n - 8)
        | n when n >= 4 ->
            loop (LE.(get_uint32 cs1 i = get_uint32 cs2 i) && ok) (i + 4) (n - 4)
        | n when n >= 2 ->
            loop (LE.(get_uint16 cs1 i = get_uint16 cs2 i) && ok) (i + 2) (n - 2)
        | 1             -> (get_uint8 cs1 i = get_uint8 cs2 i) && ok
        | _             -> ok
      in
      let n1 = len cs1 and n2 = len cs2 in
      loop true 0 (imin n1 n2) && n1 = n2 in

    if mask then
      eq_with_mask cs1 cs2
    else
      (len cs1 = len cs2) && (to_bigarray cs1 = to_bigarray cs2)

  let rec find_uint8 ?(mask=false) ?(off=0) ~f cs =
    let f' x = ignore (f x) ; false in
    let rec go i = function
      | 0 -> None
      | n ->
          match f (get_uint8 cs i) with
          | false -> go (succ i) (pred n)
          | true  ->
              if mask then ignore (find_uint8 ~off:(succ i) ~f:f' cs) ;
              Some i in
    go off (len cs - off)

  let clone ?(off = 0) ?len cs =
    let len = match len with None -> cs.len - off | Some x -> x in
    let cs' = create len in
    ( blit cs off cs' 0 len ; cs' )

  let xor_into src dst n =
    if n > imin (len src) (len dst) then
      Raise.invalid1 "Uncommon.Cs.xor_into: buffers to small (need %d)" n
    else Native.xor_into src.buffer src.off dst.buffer dst.off n

  let xor cs1 cs2 =
    let len = imin (len cs1) (len cs2) in
    let cs  = clone ~len cs2 in
    ( xor_into cs1 cs len ; cs )

  let create_with n x =
    let cs = create n in ( memset cs x ; cs )

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

  let zeros n = create_with n 0x00

  let split2 cs l =
    (sub cs 0 l, sub cs l (len cs - l))

  let split3 cs l1 l2 =
    let l12 = l1 + l2 in
    (sub cs 0 l1, sub cs l1 l2, sub cs l12 (len cs - l12))

  let rpad cs size x =
    let l = len cs and cs' = create size in
    if size < l then invalid_arg "Nocrypto.Uncommon.Cs.rpad: size < len";
    blit cs 0 cs' 0 l ;
    memset (sub cs' l (size - l)) x ;
    cs'

  let lpad cs size x =
    let l = len cs and cs' = create size in
    if size < l then invalid_arg "Nocrypto.Uncommon.Cs.lpad: size < len";
    blit cs 0 cs' (size - l) l ;
    memset (sub cs' 0 (size - l)) x ;
    cs'

  let of_bytes, of_int32s, of_int64s =
    let aux k set xs =
      let cs = create @@ List.length xs * k in
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
      | x               -> invalid_arg Printf.(sprintf "of_hex: `%c'" x)
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
    | (_ , _, Some _) -> invalid_arg "of_hex: dangling nibble"
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
