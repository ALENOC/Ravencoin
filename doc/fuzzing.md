Fuzz-testing Ravencoin
==========================

A special test harness `test_raven_fuzzy` is provided to provide an easy
entry point for fuzzers and the like. In this document we'll describe how to
use it with AFL.

Building AFL
-------------

It is recommended to always use the latest version of afl:
```
wget http://lcamtuf.coredump.cx/afl/releases/afl-latest.tgz
tar -zxvf afl-latest.tgz
cd afl-<version>
make
export AFLPATH=$PWD
```

Instrumentation
----------------

To build Raven Core using AFL instrumentation (this assumes that the
`AFLPATH` was set as above):
```
./configure --disable-ccache --disable-shared --enable-tests CC=${AFLPATH}/afl-gcc CXX=${AFLPATH}/afl-g++
export AFL_HARDEN=1
cd src/
make test/test_raven_fuzzy
```
We disable ccache because we don't want to pollute the ccache with instrumented
objects, and similarly don't want to use non-instrumented cached objects linked
in.

The fuzzing can be sped up significantly (~200x) by using `afl-clang-fast` and
`afl-clang-fast++` in place of `afl-gcc` and `afl-g++` when compiling. When
compiling using `afl-clang-fast`/`afl-clang-fast++` the resulting
`test_raven_fuzzy` binary will be instrumented in such a way that the AFL
features "persistent mode" and "deferred forkserver" can be used. See
https://github.com/mcarpenter/afl/tree/master/llvm_mode for details.

Preparing fuzzing
------------------

AFL needs an input directory with examples, and an output directory where it
will place examples that it found. These can be anywhere in the file system,
we'll define environment variables to make it easy to reference them.

```
mkdir inputs
AFLIN=$PWD/inputs
mkdir outputs
AFLOUT=$PWD/outputs
```

Example inputs are available from:

- https://download.visucore.com/bitcoin/bitcoin_fuzzy_in.tar.xz
- http://strateman.ninja/fuzzing.tar.xz

Extract these (or other starting inputs) into the `inputs` directory before starting fuzzing.

Fuzzing
--------

To start the actual fuzzing use:
```
$AFLPATH/afl-fuzz -i ${AFLIN} -o ${AFLOUT} -m52 -- test/test_raven_fuzzy
```

You may have to change a few kernel parameters to test optimally - `afl-fuzz`
will print an error and suggestion if so.

RIP-25 witness-v2 verifier target
-------------------------------

The tracked seed `src/test/fuzz/pq_witness_v2_seed` contains the readable
five-byte prefix `PQFZ` followed by a newline. The harness constructs one
valid ML-DSA-44 witness-v2 spend from a public test seed, signs its RIP-25
sighash once, and checks it with production `VerifyScript` and liboqs. Bytes
after the prefix mutate the signature, public key, witness stack, program,
transaction fields, network context, scriptSig, and witness version. The
program follows a mutated public key unless a program-mismatch mode is set,
so malformed keys of the correct length also reach the real verifier.

The first byte after the prefix is a bit mask: `0x01` mutates signature
bytes, `0x02` mutates public-key bytes, `0x04` changes the program, `0x08`
changes witness shape or item length, `0x10` changes transaction fields,
`0x20` changes network context, `0x40` changes scriptSig, and `0x80` changes
the witness version. Remaining bytes supply mutation data. The input cap is
1 MiB for both stdin and libFuzzer. The existing binary test IDs continue to
exercise transaction and other network deserialization separately.

A focused smoke check must succeed before fuzzing:

```
src/test/test_raven_fuzzy --pq-smoke
src/test/test_raven_fuzzy < src/test/fuzz/pq_witness_v2_seed
```

For a short AFL run, use this seed in a dedicated input directory, then run
the instrumented binary with `afl-fuzz`. Retain the output corpus and rerun
interesting cases under ASan and UBSan. The smoke check asserts one valid and
seven invalid outcomes, then runs 256 deterministic mutation inputs,
including full-length signature and public-key mutations. It does not
replace long-running fuzzing.
