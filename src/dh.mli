type params
type secret

val params : p:Z.t -> gg:Z.t -> params
val gen_params : ?g:Rng.g -> int -> params
val gen_secret : ?g:Rng.g -> params -> secret * Cstruct.t
val shared     : params -> secret -> Cstruct.t -> Cstruct.t

