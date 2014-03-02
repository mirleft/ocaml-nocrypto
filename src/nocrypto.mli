
module Hash : sig
  module SHA1 : Algo_types.Hash
  module MD5  : Algo_types.Hash
end

module Stream : sig
  module ARC4 : Algo_types.Stream_cipher
end

module Block : sig
  module AES : Algo_types.Block_cipher
end
