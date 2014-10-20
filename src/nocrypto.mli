
module Module_types : module type of Module_types

module Base64   : module type of Base64
module Numeric  : module type of Numeric
module Uncommon : module type of Uncommon

module Hash          : module type of Hash
module Cipher_block  : module type of Cipher_block
module Cipher_stream : module type of Cipher_stream

module Fortuna : module type of Fortuna

(* XXX XXX XXX
 *
 * Inter-module references, packing and `module type of` don't like each
 * other. Figure something out to avoid re-pasting the interfaces here. *)

(* module Rng : module type of Rng *)
(* module Rsa : module type of Rsa *)
(* module Dh  : module type of Dh *)


module Rng : sig

  open Module_types

  module Numeric_of :
    functor (Rng : Random.Rng) -> Random.Numeric with type g = Rng.g

  type g = Fortuna.g

  include Random.Rng     with type g := g
  include Random.Numeric with type g := g

  val reseed  : Cstruct.t      -> unit
  val reseedv : Cstruct.t list -> unit
  val seeded  : unit           -> bool
  val set_gen : g:g            -> unit

  module Accumulator : sig
    val add    : source:int -> pool:int -> Cstruct.t -> unit
    val add_rr : source:int -> Cstruct.t -> unit
  end
end

module Rsa : sig

  type pub  = { e : Z.t ; n : Z.t ; } with sexp
  type priv = { e  : Z.t ; d  : Z.t ; n  : Z.t ; p  : Z.t ; q  : Z.t ; dp : Z.t ; dq : Z.t ; q' : Z.t ; } with sexp

  type mask = [ | `No | `Yes | `Yes_with of Rng.g ]

  val pub_bits  : pub -> int
  val priv_bits : priv -> int

  val pub  : e:Cstruct.t -> n:Cstruct.t -> pub
  val priv : e:Cstruct.t -> d:Cstruct.t -> n:Cstruct.t ->
             p:Cstruct.t -> q:Cstruct.t ->
             dp:Cstruct.t -> dq:Cstruct.t -> q':Cstruct.t -> priv

  val priv' : e:Cstruct.t -> p:Cstruct.t -> q:Cstruct.t -> priv
  val pub_of_priv : priv -> pub

  val encrypt   : key:pub  -> Cstruct.t -> Cstruct.t
  val decrypt   : ?mask:mask -> key:priv -> Cstruct.t -> Cstruct.t

  val generate : ?g:Rng.g -> ?e:Z.t -> int -> priv

  module PKCS1 : sig
    val sign   : key:priv -> Cstruct.t -> Cstruct.t option
    val verify : key:pub  -> Cstruct.t -> Cstruct.t option
    val encrypt :               key:pub  -> Cstruct.t -> Cstruct.t
    val decrypt : ?mask:mask -> key:priv -> Cstruct.t -> Cstruct.t option
  end
end

module Dsa : sig

  type pub = { p : Z.t ; q : Z.t ; g : Z.t ; y : Z.t } with sexp
  type priv = { p : Z.t ; q : Z.t ; g : Z.t ; x : Z.t ; y : Z.t } with sexp

  val pub : p:Cstruct.t -> q:Cstruct.t -> g:Cstruct.t -> y:Cstruct.t -> pub
  val priv : p:Cstruct.t -> q:Cstruct.t -> g:Cstruct.t -> x:Cstruct.t -> y:Cstruct.t -> priv
  val pub_of_priv : priv -> pub

  type mask = [ | `No | `Yes ]

  val generate_k : Hash.hash -> Cstruct.t -> Z.t -> Z.t -> Z.t

  val generate : int -> int -> priv

  val sign   : key:priv -> ?mask:mask -> ?k:Cstruct.t -> hash:Hash.hash -> Cstruct.t -> (Cstruct.t * Cstruct.t)
  val verify : key:pub -> hash:Hash.hash -> Cstruct.t -> (Cstruct.t * Cstruct.t) -> bool
end



module Dh : sig

  exception Invalid_public_key

  type group = { p  : Z.t ; gg : Z.t ; q  : Z.t option ; } with sexp
  type secret = { x : Z.t } with sexp

  val apparent_bit_size : group -> int
  val group : p:Cstruct.t -> gg:Cstruct.t -> ?q:Cstruct.t -> unit -> group
  val to_cstruct : group -> Cstruct.t * Cstruct.t
  val secret_of_cstruct : group -> s:Cstruct.t -> secret * Cstruct.t
  val gen_secret : ?g:Rng.g -> group -> secret * Cstruct.t
  val shared : group -> secret -> Cstruct.t -> Cstruct.t

  val gen_group : ?g:Rng.g -> bits:int -> group

  module Group : sig
    val oakley_1   : group
    val oakley_2   : group
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
end
