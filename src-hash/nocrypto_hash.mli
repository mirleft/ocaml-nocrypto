(** {1 Hashing} *)

(** Hashes.

    Each algorithm is contained in its own {{!hashing_modules}module}, with
    high-level operations accessible through {{!hashing_funs}functions} that
    dispatch on {{!hash}code} value. *)

type digest = Cstruct.t

type 'a iter = ('a -> unit) -> unit
(** A general (inner) iterator. It applies the provided function to a
    collection of elements.

    For instance:

    {ul
    {- [let iter_k    : 'a      -> 'a iter = fun x f -> f x]}
    {- [let iter_pair : 'a * 'a -> 'a iter = fun (x, y) f = f x; f y]}
    {- [let iter_list : 'a list -> 'a iter = fun xs f -> List.iter f xs]}} *)

(** {1:hashing_modules Hashing algorithms} *)

(** A single hash algorithm. *)
module type S = sig

  val digest_size : int
  (** Size of digests (in bytes). *)

  (** {1 Core operations} *)

  type t
  (** Represents a running hash computation in a way suitable for appending
      inputs. *)

  val empty : t
  (** [empty] is the hash of the empty string. *)

  val feed : t -> Cstruct.t -> t
  (** [feed t msg] adds the information in [msg] to [t].

      [feed] is analogous to appending:
      [feed (feed t msg1) msg2 = feed t (append msg1 msg2)]. *)

  val get : t -> digest
  (** [get t] is the digest corresponding to [t]. *)

  (** {1 All-in-one}

      Functions that operate on data stored in a single chunk. *)

  val digest : Cstruct.t -> digest
  (** [digest msg] is the digest of [msg].

      [digest msg = get (feed empty msg)] *)

  val hmac : key:Cstruct.t -> Cstruct.t -> digest
  (** [hmac ~key bytes] is the authentication code for [bytes] under the
      secret [key], generated using the standard HMAC construction over this
      hash algorithm. *)

  (** {1:hashing_funs Functions over iterators}

      Functions that operate on arbitrary {{!iter}iterators}. They can serve
      as a basis for other, more specialized aggregate hashing operations.

      These functions are a little faster than using {{!feed}[feed]} directly. *)

  val feedi : t -> Cstruct.t iter -> t
  (** [feedi t iter =
(let r = ref t in iter (fun msg -> r := feed !r msg); !r)] *)

  val digesti : Cstruct.t iter -> digest
  (** [digesti iter = feedi empty iter |> get] *)

  val hmaci : key:Cstruct.t -> Cstruct.t iter -> digest
  (** See {{!hmac}[hmac]}. *)
end

module MD5     : S
module SHA1    : S
module SHA224  : S
module SHA256  : S
module SHA384  : S
module SHA512  : S

(** {1 Codes-based interface} *)

type hash = [ `MD5 | `SHA1 | `SHA224 | `SHA256 | `SHA384 | `SHA512 ]
(** Algorithm codes. *)

val module_of   : [< hash ] -> (module S)
(** [module_of hash] is the (first-class) module corresponding to the code
    [hash].

    This is the most convenient way to go from a code to a module. *)

val digest      : [< hash ] -> Cstruct.t -> digest
val digesti     : [< hash ] -> Cstruct.t iter -> digest
val mac         : [< hash ] -> key:Cstruct.t -> Cstruct.t -> digest
val maci        : [< hash ] -> key:Cstruct.t -> Cstruct.t iter -> digest
val digest_size : [< hash ] -> int

(** {1 Misc} *)

type 'a or_digest = [ `Message of 'a | `Digest of digest ]
(** Either an ['a] or its digest, according to some hash algorithm. *)

(**/**)

module Digest_or (H: S) : sig
  val digest_or : Cstruct.t or_digest -> digest
end
val digest_or : hash:hash -> Cstruct.t or_digest -> digest

(**/**)
