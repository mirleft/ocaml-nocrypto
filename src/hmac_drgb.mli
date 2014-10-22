module Make (H : Hash.T) : sig

  (** HMAC_DRBG: A NIST-specified RNG based on HMAC construction over the
      provided hash. *)

  type g

  val create : unit -> g
  val reseed : ?g:g -> Cstruct.t -> unit

  include Module_types.Random.Rng with type g := g
end
