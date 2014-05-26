open Algo_types

module type T_RAW = sig include Block.Cipher_raw end
module type T_ECB = sig include Block.ECB end
module type T_CBC = sig include Block.CBC end
module type T_GCM = sig include Block.GCM end

module AES : sig
  module Raw : T_RAW
  module ECB : T_ECB
  module CBC : T_CBC
  module GCM : T_GCM
end

module DES : sig
  module Raw : T_RAW
  module ECB : T_ECB
  module CBC : T_CBC
end
