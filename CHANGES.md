0.5.3 (???):
* Move from Camlp4 to PPX.
* Tweaks the supporting Cstruct module's API.
* Dh.shared returns option instead of throwing if the public message is degenerate.
* Base64.decode returns option instead of throwing

0.5.2 (2015-12-03):
* Avoid including intrinsics-related headers if SSE/AES-NI is disabled.
* Replace opam variable `nocrypto-inhibit-modernity` with `$NOCRYPTO_NO_ACCEL`.
* Remove cstruct equality.

0.5.1 (2015-07-07):
* Disable AES-NI if not supported in the `./configure` step.
* Support the global opam variable `nocrypto-inhibit-modernity`.

0.5.0 (2015-07-02):
* Support for AES-NI and SSE2.
* Support RSA-OAEP and RSA-PSS.
* Drop `ctypes` for internal C calls.
* Generate smaller secret exponents for DH, making operations on large groups much faster.
* Support dynamic switching of RNG algorithms and decouple `Rng` from `Fortuna`.
* Module for injectring entropy into RNG on pure Unix (optional).
* `Nocrypto_entropy_lwt.initialize` no longer needs to be synchronized on.
* Renamed module signatures and modules containing only signatures from `T` to `S`.
* Changes to `CTR`, `CBC`, `Rsa` and `Dh` APIs.

0.4.0 (2015-05-02):
* Module for injecting entropy into RNG on Unix/Lwt (optional).
* Module for injecting entropy into RNG on Mirage/Xen (optional; depends on mirage-entropy-xen).
* API changes in `Rng`.
* Do not 0-pad DH public and shared representations.
* More named DH groups.

0.3.1 (2015-02-01):
* Support for Mirage/Xen (contributed by Thomas Leonard <talex5@gmail.com>).

0.3.0 (2014-12-21):
* Removed ad-hoc key marshalling functions as key material typically comes non-trivially encoded anyways.
* Changed how module interfaces for the packed module are handled: `module type of` constructs are gone.
* More consistent errors in `Rsa`.
* Small API breakage here and there.

0.2.2 (2014-11-04):
* Replaced hashing sources with the ones from hs-cryptohash
  (https://github.com/vincenthz/hs-cryptohash) by Vincent Hanquez.
* Renamed various symbols likely to conflict with other crypto libraries.

0.2.0 (2014-10-30):
* DSA (initial version contributed by Hannes Mehnert <hannes@mehnert.org>).
* CCM mode for AES (contributed by Hannes Mehnert <hannes@mehnert.org>).
* Switched from hand written stubs to ctypes for intefacing with the C code.
* Packed the module to avoid clobbering global namespace; some modules renamed.
* Various bugfixes and improvements.

0.1.0 (2014-07-08):
* Initial (beta) release.
