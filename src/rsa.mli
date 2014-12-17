(** RSA public-key cryptography.

 Keys are taken to be trusted material, and their properties are not checked.

 Messages are checked not to exceed the key size, and this is signalled via
 exceptions.

 Private-key operations are optionally protected through RSA blinding.
*)

(** A public key *)
type pub  = {
  e : Z.t ; (** Public exponent *)
  n : Z.t ; (** Modulus *)
} with sexp

(** A private key (two-prime version) *)
type priv = {
  e  : Z.t ; (** Public exponent *)
  d  : Z.t ; (** Private exponent *)
  n  : Z.t ; (** Modulus *)
  p  : Z.t ; (** [p], one of two primes *)
  q  : Z.t ; (** [q], one of two primes *)
  dp : Z.t ; (** [d mod (p-1)] *)
  dq : Z.t ; (** [d mod (q-1)] *)
  q' : Z.t ; (** [q^(-1) mod p] *)
} with sexp

(** Masking (blinding) request. *)
type mask = [
  | `No                (** Don't perform blinding. *)
  | `Yes               (** Use default {!Rng.g} for blinding. *)
  | `Yes_with of Rng.g (** Use the provided {!Rng.g} for blinding. *)
]

(** Bit-size of a public key. *)
val pub_bits : pub -> int

(** Bit-size of a private key. *)
val priv_bits : priv -> int

(** Construct a {!pub}. {!Cstruct.t} are taken to be big-endian. *)
val pub : e:Cstruct.t -> n:Cstruct.t -> pub

(** Construct a {!priv}. {!Cstruct.t} are taken to be big-endian. *)
val priv : e:Cstruct.t -> d:Cstruct.t -> n:Cstruct.t ->
           p:Cstruct.t -> q:Cstruct.t ->
           dp:Cstruct.t -> dq:Cstruct.t -> q':Cstruct.t -> priv

(** Compute a {!priv} from a minimal description. *)
val priv' : e:Cstruct.t -> p:Cstruct.t -> q:Cstruct.t -> priv

(** Extract the public component from a private key. *)
val pub_of_priv : priv -> pub

(** [encrypt key message] is the encrypted [message].
  @raise Invalid_argument if [message] is too large for the [key]. *)
val encrypt : key:pub  -> Cstruct.t -> Cstruct.t

(** [decrypt mask key cyphertext] is the decrypted [cyphertext], left-padded
  with 0x00 up to [key] size.
  @raise Invalid_argument if [cyphertext] is too large for the [key]. *)
val decrypt : ?mask:mask -> key:priv -> Cstruct.t -> Cstruct.t

(** [generate g e bits] is a new {!priv}. [e] is given or [2^16+1]. [size] is
    in bits. *)
val generate : ?g:Rng.g -> ?e:Z.t -> int -> priv


(** Module providing operations with {b PKCS1} padding.

 The operations that take cleartext to ciphertext, {!sign} and {!encrypt},
 assume that the key has enough bits to encode the message and the padding, and
 raise exceptions otherwise. The operations that recover cleartext from
 ciphertext, {!verify} and !{decrypt}, return size and padding mismatches as
 [None].
 *)
module PKCS1 : sig

  (** [sign mask key message] gives a PKCS1-padded signature of the [message].
   @raise Invalid_argument if the key is too small. *)
  val sign : ?mask:mask -> key:priv -> Cstruct.t -> Cstruct.t

  (** [verify key signature] is either the message that was PKCS1-padded and
   transformed with [key]'s private counterpart, or [None] if the recovered
   padding is incorrect. *)
  val verify : key:pub -> Cstruct.t -> Cstruct.t option

  (** [encrypt g key message] gives a PKCS1-padded and encrypted [message].
   @raise Invalid_argument if the key is too small. *)
  val encrypt : ?g:Rng.g -> key:pub -> Cstruct.t -> Cstruct.t

  (** [decrypt mask key ciphertext] is decrypted [ciphertext] stripped of PKCS1
   padding, or [None] if the padding is incorrect. *)
  val decrypt : ?mask:mask -> key:priv -> Cstruct.t -> Cstruct.t option

end
