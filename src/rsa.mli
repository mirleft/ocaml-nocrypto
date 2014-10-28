
(** RSA public-key cryptography. *)

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

(** [encrypt key message] is the encrypted message.
  @raise Invalid_argument if [message] is too large for the [key]. *)
val encrypt   : key:pub  -> Cstruct.t -> Cstruct.t

(** [decrypt mask key message] is the decrypted message.
  @raise Invalid_argument if [message] is too larger for the [key]. *)
val decrypt   : ?mask:mask -> key:priv -> Cstruct.t -> Cstruct.t

(** [generate g e bits] is a new {!priv}. [e] is given or [2^16+1]. [size] is
    in bits. *)
val generate : ?g:Rng.g -> ?e:Z.t -> int -> priv


(** Module providing operations with {b PKCS1} padding. *)
module PKCS1 : sig

  val sign   : ?mask:mask -> key:priv -> Cstruct.t -> Cstruct.t option
  val verify : key:pub -> Cstruct.t -> Cstruct.t option

  val encrypt : key:pub -> Cstruct.t -> Cstruct.t
  val decrypt : ?mask:mask -> key:priv -> Cstruct.t -> Cstruct.t option

end
