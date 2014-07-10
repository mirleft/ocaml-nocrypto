
(** Diffie-Hellman, MODP version. *)

(**
 Raised if the public key is degenerate. Implies either badly malfunctioning
 DH on the other side, or an attack attempt. *)
exception Invalid_public_key

(** A DH group. *)
type group = {
  p  : Z.t ; (** The modulus *)
  gg : Z.t ; (** The generator *)
  q  : Z.t option ; (** The subgroup order, if known *)
}

(** A private secret. *)
type secret = { x : Z.t }

(** Bit size of the modulus (not the subgroup order, which might not be known). *)
val apparent_bit_size : group -> int

(** [group p gg q ()] is a new {!group}.

 The parameters are not validated in any way, not even as a
 sanity check. Be sure to trust your group! *)
val group : p:Cstruct.t -> gg:Cstruct.t -> ?q:Cstruct.t -> unit -> group

(** [to_cstruct group] expands (p, gg) to {!Cstruct.t} *)
val to_cstruct : group -> Cstruct.t * Cstruct.t

(**
  [secret_of_cstruct group s] generates {! secret } and the public key, using
  [s] as secret.
  @raise Invalid_public_key if the secret is degenerate. *)
val secret_of_cstruct : group -> s:Cstruct.t -> secret * Cstruct.t

(** Generate a random {!secret} and the corresponding public message. *)
val gen_secret : ?g:Rng.g -> group -> secret * Cstruct.t

(**
  [shared group secret message] is the shared key, given a group, a previously
  generated {!secret} and the other party's public message.
  @raise Invalid_public_key if the public message is degenerate.
  *)
val shared : group -> secret -> Cstruct.t -> Cstruct.t

(**
  [gen_group bits] generates a random {!group} with modulus size [bits].
  Uses a safe prime [p = 2q + 1] (with prime [q]) as modulus, and [2] or [q] as
  the generator.
  Subgroup order is strictly [q].
  Runtime is on the order of minute for 1024 bits.  *)
val gen_group : ?g:Rng.g -> bits:int -> group

(** A small catalog of standardized groups. *)
module Group : sig

  val oakley_1   : group
  (** From RFC 2409. *)
  val oakley_2   : group
  (** From RFC 2409. *)

  val oakley_5   : group
  (** From RFC 3526. *)
  val oakley_14  : group
  (** From RFC 3526. *)
  val oakley_15  : group
  (** From RFC 3526. *)
  val oakley_16  : group
  (** From RFC 3526. *)
  val oakley_17  : group
  (** From RFC 3526. *)
  val oakley_18  : group
  (** From RF C3526. *)

  val rfc_5114_1 : group
  (** From RFC 5114. *)
  val rfc_5114_2 : group
  (** From RFC 5114. *)
  val rfc_5114_3 : group
  (** From RFC 5114. *)

end

open Sexplib

val sexp_of_group  : group -> Sexp.t
val group_of_sexp  : Sexp.t -> group

val sexp_of_secret : secret -> Sexp.t
val secret_of_sexp : Sexp.t -> secret
