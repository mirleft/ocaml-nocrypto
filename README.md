[![Build Status](https://travis-ci.org/mirleft/ocaml-nocrypto.svg?branch=master)](https://travis-ci.org/mirleft/ocaml-nocrypto)

## Documentation

Comments in the single interface file, [`nocrypto.mli`][nocrypto-mli]. Also available [online][docs].

The documentation is a work in progress. :)

## FAQ

#### RNG seeding

You get something like `Fatal error: exception Uncommon.Boot.Unseeded_generator` and ask yourself: "Is there a simple way to forget about seeding and have the thing working?"

```OCaml
(* On pure Unix: *)
let () = Nocrypto_entropy_unix.initialize ()

(* On Lwt/Unix: *)
let () = ignore @@ Nocrypto_entropy_lwt.initialize ()
```

#### Illegal instructions

Anything linking to `Nocrypto` dies immediately:

```
Program terminated with signal SIGILL, Illegal instruction.
#0  _mm_aeskeygenassist_si128 (__C=<optimized out>, __X=...)
```

`Nocrypto` has CPU acceleration support (`SSE2`+`AES-NI`), but it has no run-time autodetection yet. You
compiled the library with acceleration, but you are using it on a machine that does not support it.

`./configure --disable-modernity` disables non-portable code.

`./configure --enable-modernity` enables non-portable code if the build machine supports it.

The flag defaults to `enable`.

A second way to disable this feature is by exporting `$NOCRYPTO_NO_ACCEL`
environment variable during build. This is desirable, for example, when building
via `opam`.

[docs]: http://mirleft.github.io/ocaml-nocrypto
[nocrypto-mli]: https://github.com/mirleft/ocaml-nocrypto/blob/master/src/nocrypto.mli
