0.5.0 (trunk):
* support for AES-NI and SSE2
* support RSA-OAEP and RSA-PSS
* drop ctypes for internal C calls
* generate smaller secret exponents for DH, making operations on large groups much faster
* support dynamic switching of RNG algorithms and decouple Rng from Fortuna
* module for injectring entropy into RNG on pure Unix (optional)
* `Nocrypto_entropy_lwt.initialize` no longer need to be synchronized on
* renamed module signatures and modules containing only signatures from `T` to `S`
* changes to block cipher API

0.4.0 (2015-05-02):
* module for injecting entropy into RNG on Unix/Lwt (optional)
* module for injecting entropy into RNG on Mirage/Xen (optional; depends on mirage-entropy-xen)
* API changes in Rng
* do not 0-pad DH public and shared representations
* more named DH groups

0.3.1 (2015-02-01):
* support for Mirage/Xen (contributed by Thomas Leonard <talex5@gmail.com>)

0.3.0 (2014-12-21):
* removed ad-hoc key marshalling functions as key material typically comes
  non-trivially encoded anyways
* changed how module interfaces for the packed module are handled:
  `module type of` constructs are gone
* more consistent errors in rsa
* small api breakage here and there

0.2.2 (2014-11-04):
* replaced hashing sources with the ones from hs-cryptohash
  (https://github.com/vincenthz/hs-cryptohash) by Vincent Hanquez
* renamed various symbols likely to conflict with other crypto libraries

0.2.0 (2014-10-30):
* DSA (initial version contributed by Hannes Mehnert <hannes@mehnert.org>)
* CCM mode for AES (contributed by Hannes Mehnert <hannes@mehnert.org>)
* switched from hand written stubs to ctypes for intefacing with the C code
* packed the module to avoid clobbering global namespace; some modules renamed
* various bugfixes and improvements

0.1.0 (2014-07-08):
* initial (beta) release
