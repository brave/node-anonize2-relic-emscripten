# node-anonize2-relic-emscripten
Javascript bindings to the [anonize2](https://gitlab.com/abhvious/anonize2) library,
using the [RELIC toolkit](https://github.com/relic-toolkit/relic)
and [Emscripten](https://github.com/kripken/emscripten)

The package will look for `anonize2.js.mem` in `__dirname` unless `__dirname` contains `"app.asar"`,
in which case the directory 

    ".../Contents/Resources/app.asar.unpacked/node_modules/node-anonize2-relic-emscripten/anonize2.js.mem"

is consulted instead.

## Licensing
This repository contains the [anonize2](https://gitlab.com/abhvious/anonize2) library,
which is licensed under [Apache v2.0 License](https://gitlab.com/abhvious/anonize2/blob/master/LICENSE.txt).
This repository also contains code derived from the [RELIC toolkit](https://github.com/relic-toolkit/relic),
which is available under a [modified LGPL](https://github.com/relic-toolkit/relic/blob/master/COPYING) license.
All other files are licensed under the [MPL-2.0](./LICENSE).

The RELIC toolkit license is LGPLv2.1 with these overriding provisions:

   1. Making modifications to RELIC configuration files, build scripts and
      configuration headers such as "relic_conf.h" in order to create a
      customized build setup of RELIC with the otherwise unmodified source code,
      does not constitute a derived work.

   2. Statically linking the RELIC library into a user application does not
      make the user application a derived work, and therefore does not require
      the user to distribute the source code or object code of their own
      application. The RELIC source code with all modifications must still be
      passed on in the same way as using RELIC as a shared library.

   3. Using source code obfuscation on the RELIC source code when distributing
      it is not permitted.

This package uses the `anonize2.js` and `anonize2.js.mem` files produced by the
[anonize2 build area](https://gitlab.com/abhvious/anonize2/builds),
which is then used by as an add-on for node.js,
it is believed that this package fully complies with the RELIC toolkit's licensing requirements.

## Making the emscripten version

* On the Mac:

  * `brew install emscripten cmake`

  * Edit `~/.emscripten` to set

        LLVM_ROOT = '/Users/mrose/homebrew/Cellar/emscripten/1.37.1/libexec/llvm/bin'

  * Install a JDK

* Run `cmake.sh`
