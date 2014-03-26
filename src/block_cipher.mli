open Algo_types.Block

module type T_CBC = Mode_CBC

module AES : sig
  module Raw : Cipher_raw
  module ECB : Mode
  module CBC : Mode_CBC
  module GCM : Mode_GCM
end

module DES : sig
  module Raw : Cipher_raw
  module ECB : Mode
  module CBC : Mode_CBC
end
