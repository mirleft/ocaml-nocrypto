open Algo_types.Block

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
