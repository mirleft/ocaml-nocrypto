open Algo_types

module type Counter = sig include Block.Counter end

module type T_RAW = sig include Block.Cipher_raw end
module type T_ECB = sig include Block.ECB end
module type T_CBC = sig include Block.CBC end
module type T_GCM = sig include Block.GCM end
module type T_CTR = functor (C : Block.Counter) -> sig include Block.CTR end

module Counters : sig
  module Inc_LE : Counter
  module Inc_BE : Counter
end

module AES : sig
  module Raw : T_RAW
  module ECB : T_ECB
  module CBC : T_CBC
  module CTR : T_CTR
  module GCM : T_GCM
end

module DES : sig
  module Raw : T_RAW
  module ECB : T_ECB
  module CBC : T_CBC
  module CTR : T_CTR
end
