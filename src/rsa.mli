
type pub
type priv

val pub   : e:Z.t -> n:Z.t -> pub
val priv  : e:Z.t -> d:Z.t -> n:Z.t -> p:Z.t -> q:Z.t -> dp:Z.t -> dq:Z.t -> q':Z.t -> priv
val priv' : e:Z.t -> p:Z.t -> q:Z.t -> priv

val pub_of_priv : priv -> pub

val encrypt_z :             key:pub  -> Z.t       -> Z.t
val decrypt_z : ?g:Rng.g -> key:priv -> Z.t       -> Z.t
val encrypt   :             key:pub  -> Cstruct.t -> Cstruct.t
val decrypt   : ?g:Rng.g -> key:priv -> Cstruct.t -> Cstruct.t

val generate : ?g:Rng.g -> ?e:Z.t -> int -> priv

val print_key : priv -> unit
