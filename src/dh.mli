
(* MODP Diffie-Hellman *)

(* DH parameters: a modulus, a generator and the optional subgroup order. *)
type group = { p: Z.t ; gg : Z.t ; q : Z.t option }

(* A private secret. *)
type secret = { x : Z.t }

(* Construct group. *)
val group : p:Cstruct.t -> gg:Cstruct.t -> ?q:Cstruct.t -> unit -> group

(* Extract group to cstruct as (p, g). *)
val to_cstruct : group -> Cstruct.t * Cstruct.t

(* Given group and a string serving as secret, generate `secret` and the public
 * part. *)
val of_secret : group -> s:Cstruct.t -> secret * Cstruct.t

(* Generate a secret and the corresponding public message. *)
val gen_secret : ?g:Rng.g -> group -> secret * Cstruct.t

(* Given `group`, a `secret` and the other party's public message, recover the
 * shared secret. *)
val shared : group -> secret -> Cstruct.t -> Cstruct.t

(* Generate a `group` using a safe prime p = 2q + 1 (with q prime) as modulus, 2
 * or q as the generator and subgroup order of strictly q. *)
(* (Runtime on the order of minute for 1024 bits.) *)
val gen_group : ?g:Rng.g -> bits:int -> group

(* Some standard groups. *)
module Group : sig

  (* RFC2409 *)
  val oakley_1   : group
  val oakley_2   : group

  (* RFC3526 *)
  val oakley_5   : group
  val oakley_14  : group
  val oakley_15  : group
  val oakley_16  : group
  val oakley_17  : group
  val oakley_18  : group

  val rfc_5114_1 : group
  val rfc_5114_2 : group
  val rfc_5114_3 : group

end

open Sexplib

val sexp_of_group  : group -> Sexp.t
val group_of_sexp  : Sexp.t -> group

val sexp_of_secret : secret -> Sexp.t
val secret_of_sexp : Sexp.t -> secret
