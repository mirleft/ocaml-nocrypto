open Uncommon

module type Counter_S = sig
  type t
  val zero : t
  val add  : t -> int64 -> t
  val of_cstruct : Cstruct.t -> t
  val to_cstruct : t -> Cstruct.t
  type words
  val of_words : words -> t
  val to_words : t -> words
end

module S = struct

  (* XXX old block-level sig, remove *)
  module type Raw = sig

    type ekey
    type dkey

    val e_of_secret : Cstruct.t -> ekey
    val d_of_secret : Cstruct.t -> dkey

    val key_sizes  : int array
    val block_size : int
    val encrypt_block : key:ekey -> Cstruct.t -> Cstruct.t -> unit
    val decrypt_block : key:dkey -> Cstruct.t -> Cstruct.t -> unit
  end

  module type Core = sig

    type ekey
    type dkey

    val of_secret   : Cstruct.t -> ekey * dkey
    val e_of_secret : Cstruct.t -> ekey
    val d_of_secret : Cstruct.t -> dkey

    val key   : int array
    val block : int

    (* XXX currently unsafe point *)
    val encrypt : key:ekey -> blocks:int -> Native.buffer -> int -> Native.buffer -> int -> unit
    val decrypt : key:dkey -> blocks:int -> Native.buffer -> int -> Native.buffer -> int -> unit
  end

  module type ECB = sig

    type key
    val of_secret : Cstruct.t -> key

    val key_sizes  : int array
    val block_size : int
    val encrypt : key:key -> Cstruct.t -> Cstruct.t
    val decrypt : key:key -> Cstruct.t -> Cstruct.t
  end

  module type CBC = sig

    type key
    val of_secret : Cstruct.t -> key

    val key_sizes  : int array
    val block_size : int

    val encrypt : key:key -> iv:Cstruct.t -> Cstruct.t -> Cstruct.t
    val decrypt : key:key -> iv:Cstruct.t -> Cstruct.t -> Cstruct.t
    val next_iv : iv:Cstruct.t -> Cstruct.t -> Cstruct.t
  end

  module type CTR = sig

    type key
    val of_secret : Cstruct.t -> key

    val key_sizes  : int array
    val block_size : int

    module C : Counter_S

    val stream  : key:key -> ctr:C.t -> int -> Cstruct.t
    val encrypt : key:key -> ctr:C.t -> Cstruct.t -> Cstruct.t
    val decrypt : key:key -> ctr:C.t -> Cstruct.t -> Cstruct.t
    val next_ctr : ctr:C.t -> Cstruct.t -> C.t
  end

  module type GCM = sig
    type key
    type result = { message : Cstruct.t ; tag : Cstruct.t }
    val of_secret : Cstruct.t -> key

    val key_sizes  : int array
    val block_size : int
    val encrypt : key:key -> iv:Cstruct.t -> ?adata:Cstruct.t -> Cstruct.t -> result
    val decrypt : key:key -> iv:Cstruct.t -> ?adata:Cstruct.t -> Cstruct.t -> result
  end

  module type CCM = sig
    type key
    val of_secret : maclen:int -> Cstruct.t -> key

    val key_sizes  : int array
    val block_size : int
    val mac_sizes  : int array
    val encrypt : key:key -> nonce:Cstruct.t -> ?adata:Cstruct.t -> Cstruct.t -> Cstruct.t
    val decrypt : key:key -> nonce:Cstruct.t -> ?adata:Cstruct.t -> Cstruct.t -> Cstruct.t option
  end
end

module Counters = struct

  module type S = Counter_S

  module type Priv_S = sig
    include S
    val size : int
    val unsafe_count_into : t -> Native.buffer -> int -> blocks:int -> unit
  end

  let of_cstruct size cs =
    if cs.Cstruct.len = size then
      let t = Bytes.create size in
      ( Cstruct.blit_to_bytes cs 0 t 0 size; t )
    else invalid_arg "Counters.S.of_cstruct: expected %d, got %d bytes"
          size (Cstruct.len cs)

  let cmp_64u a b =
    let cmp = compare a b in if Int64.logxor a b < 0L then -cmp else cmp
  [@@inline]

  open EndianBytes.BigEndian_unsafe

  module C64be = struct
    type t = bytes
    type words = int64
    let size = 8
    let of_words x = let t = Bytes.create size in set_int64 t 0 x; t
    let to_words t = get_int64 t 0 [@@inline]
    let zero = of_words 0L
    let add t n = of_words (to_words t |> Int64.add n)
    let of_cstruct cs = of_cstruct size cs
    let to_cstruct t = Cstruct.of_bytes t
    let unsafe_count_into = Native.count8be
  end

  module C128be = struct
    type t = bytes
    let size = 16
    type words = int64 * int64
    let of_words (a, b) =
      let t = Bytes.create size in set_int64 t 0 a; set_int64 t 8 b; t
    let to_words t = (get_int64 t 0, get_int64 t 8) [@@inline]
    let zero = of_words (0L, 0L)
    let add t n =
      let (w1, w0) = to_words t in
      let w0' = Int64.add w0 n in
      of_words ((if cmp_64u w0 w0' > 0 then Int64.succ w1 else w1), w0')
    let of_cstruct cs = of_cstruct size cs
    let to_cstruct t = Cstruct.of_bytes t
    let unsafe_count_into = Native.count16be
  end

  module C128be32 = struct
    include C128be
    let add t n =
      let (w1, w0) = to_words t in
      let hi = 0xffffffff00000000L and lo = 0x00000000ffffffffL in
      of_words (w1, Int64.(logor (logand hi w0) (add n w0 |> logand lo)))
    let unsafe_count_into = Native.count16be4
  end
end


module Modes = struct

  module CCM_of (C : S.Raw) : S.CCM = struct

    assert (C.block_size = 16)

    type key = C.ekey * int

    let mac_sizes = [| 4; 6; 8; 10; 12; 14; 16 |]

    let of_secret ~maclen sec =
      if Array.mem maclen mac_sizes then
        (C.e_of_secret sec, maclen)
      else invalid_arg "CCM: MAC length %d" maclen

    let (key_sizes, block_size) = C.(key_sizes, block_size)

    let encrypt ~key:(key, maclen) ~nonce ?adata cs =
      Ccm.generation_encryption ~cipher:C.encrypt_block ~key ~nonce ~maclen ?adata cs

    let decrypt ~key:(key, maclen) ~nonce ?adata cs =
      Ccm.decryption_verification ~cipher:C.encrypt_block ~key ~nonce ~maclen ?adata cs

  end

end

module Modes2 = struct

  open Cstruct

  module Raw_of (Core : S.Core) : S.Raw = struct

    type ekey = Core.ekey
    type dkey = Core.dkey

    let e_of_secret = Core.e_of_secret
    let d_of_secret = Core.d_of_secret

    let key_sizes  = Core.key
    let block_size = Core.block

    let encrypt_block ~key:key src dst =
      if src.len < block_size || dst.len < block_size then
        invalid_arg "src len %d, dst len %d" src.len dst.len;
      Core.encrypt ~key ~blocks:1 src.buffer src.off dst.buffer dst.off

    let decrypt_block ~key:key src dst =
      if src.len < block_size || dst.len < block_size then
        invalid_arg "src len %d, dst len %d" src.len dst.len;
      Core.decrypt ~key ~blocks:1 src.buffer src.off dst.buffer dst.off
  end

  module ECB_of (Core : S.Core) : S.ECB = struct

    type key = Core.ekey * Core.dkey

    let (key_sizes, block_size) = Core.(key, block)

    let of_secret = Core.of_secret

    let (encrypt, decrypt) =
      let ecb xform key src =
        let n = src.len in
        if n mod block_size <> 0 then invalid_arg "ECB: length %d" n;
        let dst = create n in
        xform ~key ~blocks:(n / block_size) src.buffer src.off dst.buffer dst.off ;
        dst
      in
      (fun ~key:(key, _) src -> ecb Core.encrypt key src),
      (fun ~key:(_, key) src -> ecb Core.decrypt key src)

  end

  module CBC_of (Core : S.Core) : S.CBC = struct

    type key = Core.ekey * Core.dkey

    let (key_sizes, block_size) = Core.(key, block)
    let block = block_size

    let of_secret = Core.of_secret

    let bounds_check ~iv cs =
      if iv.len <> block then invalid_arg "CBC: IV length %d" iv.len;
      if cs.len mod block <> 0 then
        invalid_arg "CBC: argument length %d" cs.len

    let next_iv ~iv cs =
      bounds_check ~iv cs ;
      if cs.len > 0 then
        sub cs (cs.len - block_size) block_size
      else iv

    let encrypt ~key:(key, _) ~iv src =
      bounds_check ~iv src ;
      let msg = Cs.clone src in
      let dst = msg.buffer in
      let rec loop iv iv_i dst_i = function
        0 -> ()
      | b -> Native.xor_into iv iv_i dst dst_i block ;
             Core.encrypt ~key ~blocks:1 dst dst_i dst dst_i ;
             loop dst dst_i (dst_i + block) (b - 1)
      in
      loop iv.buffer iv.off msg.off (msg.len / block) ; msg

    let decrypt ~key:(_, key) ~iv src =
      bounds_check ~iv src ;
      let msg = create src.len
      and b   = src.len / block in
      if b > 0 then begin
        Core.decrypt ~key ~blocks:b src.buffer src.off msg.buffer msg.off ;
        Native.xor_into iv.buffer iv.off msg.buffer msg.off block ;
        Native.xor_into src.buffer src.off msg.buffer (msg.off + block) ((b - 1) * block) ;
      end ;
      msg

  end

  module CTR_of (Core : S.Core) (Ctr : Counters.Priv_S) :
    S.CTR with type key = Core.ekey and module C = Ctr =
  struct
    (* FIXME: CTR has more room for speedups. Like stitching. *)

    assert (Core.block = Ctr.size)
    type key = Core.ekey

    let (key_sizes, block_size) = Core.(key, block)
    let of_secret = Core.e_of_secret

    module C = Ctr

    let next_ctr ~ctr msg = C.add ctr (Int64.of_int @@ msg.len // block_size)

    let stream ~key ~ctr n =
      let blocks = imax 0 n // block_size in
      let buf    = Native.buffer (blocks * block_size) in
      Ctr.unsafe_count_into ctr ~blocks buf 0 ;
      Core.encrypt ~key ~blocks buf 0 buf 0 ;
      of_bigarray ~len:n buf

    let encrypt ~key ~ctr src =
      let res = stream ~key ~ctr src.len in
      Native.xor_into src.buffer src.off res.buffer res.off src.len ;
      res

    let decrypt = encrypt
  end

  module GHASH : sig
    type key
    val derive  : Cstruct.t -> key
    val digesti : key:key -> (Cstruct.t Uncommon.iter) -> Cstruct.t
  end = struct
    type key = bytes
    let keysize = Native.GHASH.keysize ()
    let derive cs =
      assert (cs.len >= 16);
      let k = Bytes.create keysize in
      Native.GHASH.keyinit cs.buffer cs.off k; k
    let _cs = create_unsafe 16
    let hash0 = Bytes.make 16 '\x00'
    let digesti ~key i = (* Clobbers `_cs`! *)
      let res = Bytes.copy hash0 in
      i (fun cs -> Native.GHASH.ghash key res cs.buffer cs.off cs.len);
      blit_from_bytes res 0 _cs 0 16; _cs
  end

  module GCM_of (C : S.Core) : S.GCM = struct

    let _ = assert (C.block = 16)
    module CTR = CTR_of (C) (Counters.C128be32)

    type key = { key : C.ekey ; hkey : GHASH.key }
    type result = { message : Cstruct.t ; tag : Cstruct.t }

    let key_sizes, block_size = C.(key, block)
    let z128, h = create block_size, create block_size

    let of_secret cs =
      let key = C.e_of_secret cs in
      C.encrypt ~key ~blocks:1 z128.buffer z128.off h.buffer h.off;
      { key ; hkey = GHASH.derive h }

    let bits64 cs = Int64.of_int (len cs * 8)
    let pack64s = let _cs = create_unsafe 16 in fun a b ->
                    BE.set_uint64 _cs 0 a; BE.set_uint64 _cs 8 b; _cs

    let counter ~hkey iv = match len iv with
      | 12 -> let (w1, w2) = BE.(get_uint64 iv 0, BE.get_uint32 iv 8) in
              CTR.C.of_words (w1, Int64.(shift_left (of_int32 w2) 32 |> add 1L))
      | _  -> CTR.C.of_cstruct @@
                GHASH.digesti ~key:hkey @@ iter2 iv (pack64s 0L (bits64 iv))

    let tag ~key ~hkey ~ctr ?(adata=Cs.empty) cdata =
      CTR.encrypt ~key ~ctr @@
        GHASH.digesti ~key:hkey @@
          iter3 adata cdata (pack64s (bits64 adata) (bits64 cdata))

    let encrypt ~key:{ key; hkey } ~iv ?adata data =
      let ctr   = counter ~hkey iv in
      let cdata = CTR.(encrypt ~key ~ctr:(C.add ctr 1L) data) in
      { message = cdata ; tag = tag ~key ~hkey ~ctr ?adata cdata }

    let decrypt ~key:{ key; hkey } ~iv ?adata cdata =
      let ctr  = counter ~hkey iv in
      let data = CTR.(encrypt ~key ~ctr:(C.add ctr 1L) cdata) in
      { message = data ; tag = tag ~key ~hkey ~ctr ?adata cdata }
  end

end

open Bigarray

module AES = struct

  let mode =
    match Native.AES.mode () with
    | 0 -> `Generic | 1 -> `AES_NI | _ -> assert false

  module Core : S.Core = struct

    let key   = [| 16; 24; 32 |]
    let block = 16

    type ekey = Native.buffer * int
    type dkey = Native.buffer * int

    let of_secret_with init { Cstruct.buffer ; off ; len } =
      let rounds =
        match len with
        | 16|24|32 -> len / 4 + 6
        | _        -> invalid_arg "AES.of_secret: key length %d" len in
      let rk = Native.(buffer @@ AES.rk_s rounds) in
      init buffer off rk rounds ;
      (rk, rounds)

    let derive_d ?e buf off rk rs = Native.AES.derive_d buf off rk rs e

    let e_of_secret = of_secret_with Native.AES.derive_e
    let d_of_secret = of_secret_with (derive_d ?e:None)

    let of_secret secret =
      let (e, _) as ekey = e_of_secret secret in
      (ekey, of_secret_with (derive_d ~e) secret)

    (* XXX arg order ocaml<->c slows down *)
    (* XXX bounds checks *)

    let encrypt ~key:(e, rounds) ~blocks src off1 dst off2 =
      Native.AES.enc src off1 dst off2 e rounds blocks

    let decrypt ~key:(d, rounds) ~blocks src off1 dst off2 =
      Native.AES.dec src off1 dst off2 d rounds blocks

  end

  module ECB = Modes2.ECB_of (Core)
  module CBC = Modes2.CBC_of (Core)
  module CTR = Modes2.CTR_of (Core) (Counters.C128be)
  module GCM = Modes2.GCM_of (Core)

  module CCM = Modes.CCM_of (Modes2.Raw_of(Core))

end

module DES = struct

  module Core : S.Core = struct

    let key   = [| 24 |]
    let block = 8

    type ekey = Native.buffer
    type dkey = Native.buffer

    let k_s = Native.DES.k_s ()

    let gen_of_secret ~direction { Cstruct.buffer ; off ; len } =
      if len <> 24 then
        invalid_arg "DES.of_secret: key length %d" len ;
      let key = Native.buffer k_s in
      Native.DES.des3key buffer off direction ;
      Native.DES.cp3key key ;
      key

    let e_of_secret = gen_of_secret ~direction:0
    let d_of_secret = gen_of_secret ~direction:1

    let of_secret secret = (e_of_secret secret, d_of_secret secret)

    let encrypt ~key ~blocks src off1 dst off2 =
      Native.DES.use3key key ;
      Native.DES.ddes src off1 dst off2 blocks

    let decrypt = encrypt
  end

  module ECB = Modes2.ECB_of (Core)
  module CBC = Modes2.CBC_of (Core)
  module CTR = Modes2.CTR_of (Core) (Counters.C64be)

end
