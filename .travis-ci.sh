#!/bin/sh

case "$OCAML_VERSION" in
    4.01.0) ppa=avsm/ocaml41+opam12 ;;
    4.02.0) ppa=avsm/ocaml42+opam12 ;;
    *) echo Unknown $OCAML_VERSION; exit 1 ;;
esac

echo "yes" | sudo add-apt-repository ppa:$ppa
sudo apt-get update -qq
sudo apt-get install -qq ocaml ocaml-native-compilers camlp4-extra opam aspcud libgmp-dev

export OPAMYES=1

opam init git://github.com/ocaml/opam-repository >/dev/null 2>&1

opam pin -n add nocrypto .
opam install --deps-only nocrypto
opam install oUnit lwt

eval `opam config env`
ocaml setup.ml -configure --enable-tests
ocaml setup.ml -build
ocaml setup.ml -test

# check Xen support builds too
set -eu
opam pin add -n mirage-entropy-xen git://github.com/mirage/mirage-entropy

sudo add-apt-repository -y ppa:ubuntu-toolchain-r/test
sudo apt-get -qq update
sudo apt-get -qq install gcc-4.8
sudo update-alternatives --install /usr/bin/gcc gcc /usr/bin/gcc-4.8 90

wget http://mirrors.kernel.org/ubuntu/pool/main/b/binutils/binutils_2.24-5ubuntu3.1_amd64.deb
sudo dpkg -i binutils_2.24-5ubuntu3.1_amd64.deb

if opam install "mirage-xen>=2.2.0" mirage-entropy-xen; then
  make clean
  ./configure --enable-xen
  make
  ls -l _build/xen/dllnocrypto_xen_stubs.so
else
  echo "Mirage not installable, so not testing Xen build."
fi
