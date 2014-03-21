(* MODP Diffie-Hellman *)

(* DH parameters: a modulus and a group generator. *)
type params = { p: Z.t ; gg : Z.t ; q : Z.t option }

(* A private secret. *)
type secret = { x : Z.t }

(* Construct `params`. *)
val params : p:Cstruct.t -> gg:Cstruct.t -> ?q:Cstruct.t -> unit -> params

(* Given params and a string serving as secret, generate `secret` and the public
 * part. *)
val of_secret : params -> s:Cstruct.t -> secret * Cstruct.t

(* Given params, a secret and the other party's public message, recover the
 * shared secret. *)
val shared : params -> secret -> Cstruct.t -> Cstruct.t

(* Generate parameters. *)
val gen_params : ?g:Rng.g -> int -> params

(* Generate a secret and the corresponding public message. *)
val gen_secret : ?g:Rng.g -> params -> secret * Cstruct.t

(* Some standard parameter sets. *)
module Params : sig
  val rfc_3526_5  : params
  val rfc_3526_14 : params
  val rfc_3526_15 : params
  val rfc_3526_16 : params
  val rfc_3526_17 : params
  val rfc_3526_18 : params
  val rfc_5114_1  : params
  val rfc_5114_2  : params
  val rfc_5114_3  : params
end
