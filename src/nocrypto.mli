
open Algo_types

module Hash : sig
  module SHA1 : Hash
  module MD5  : Hash
end

module Stream : sig
  module ARC4 : Stream_cipher
end

module Block : sig
  module AES : sig
    include Block_cipher
    include ECB_cipher with type key := key
    include CBC_cipher with type key := key
    include GCM_cipher with type key := key
  end
end
