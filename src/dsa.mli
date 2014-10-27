
(** DSA digital signature algorithm. *)

(** Private key. [p], [q] and [gg] comprise {i domain parameters}. *)
type priv = {
  p  : Z.t ; (** Modulus *)
  q  : Z.t ; (** Subgroup order *)
  gg : Z.t ; (** Group Generator *)
  x  : Z.t ; (** Private key proper *)
  y  : Z.t ; (** Public component *)
} with sexp

(** Public key, a subset of {!priv}. *)
type pub  = {
  p  : Z.t ;
  q  : Z.t ;
  gg : Z.t ;
  y  : Z.t ;
} with sexp

(** Key size request. Three {e Fips} variants refer to FIPS-standardized
    L-values ([p] size) and imply the corresponding N ([q] size); The last
    variants specifies L and N directly. *)
type keysize = [ `Fips1024 | `Fips2048 | `Fips3072 | `Exactly of int * int ]

(** Masking request. *)
type mask = [ `No | `Yes | `Yes_with of Rng.g ]

(** Construct a {!pub}. {!Cstruct.t} are taken to be big-endian. *)
val pub  : p:Cstruct.t -> q:Cstruct.t -> gg:Cstruct.t -> y:Cstruct.t -> pub

(** Construct a {!priv}. {!Cstruct.t} are taken to be big-endian. *)
val priv : p:Cstruct.t -> q:Cstruct.t -> gg:Cstruct.t -> x:Cstruct.t -> y:Cstruct.t -> priv

(** Extract the public component from a private key. *)
val pub_of_priv : priv -> pub

(** [generate g size] is a fresh {!priv} key. The domain parameters are derived
    using a modified FIPS.186-4 probabilistic process, but the derivation can
    not be validated. *)
val generate : ?g:Rng.g -> keysize -> priv

(** [sign mask k key digest] is the signature, a pair of {!Cstruct.t}
    representing [r] and [s] in big-endian.
    [digest] is the full digest of the actual message.
    [k], the random component, can either be provided, or is deterministically
    derived as per RFC6979, using SHA256. *)
val sign : ?mask:mask -> ?k:Z.t -> key:priv -> Cstruct.t -> Cstruct.t * Cstruct.t

(** [verify key (r, s) digest] verifies that the pair [(r, s)] is the signature
    of [digest], the message digest, under the private counterpart to [key]. *)
val verify : key:pub -> Cstruct.t * Cstruct.t -> Cstruct.t -> bool

(** [K_gen] can be instantiated over a hashing module to obtain an RFC6979
    compliant [k]-generator over that hash. *)
module K_gen (H : Hash.T) : sig
  (** [generate key digest] deterministically takes the given private key and
      message digest to a [k] suitable for seeding the signing process. *)
  val generate : key:priv -> Cstruct.t -> Z.t
end
