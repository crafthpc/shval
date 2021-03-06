# Shadow Value Analysis Library (SHVAL)

Real-valued arithmetic is crucial to the performance and accuracy of scientific
computation. Although IEEE 64-bit floating-point is the standard representation,
many developers are investigating the possibility of using either lower
precision (for better performance) or higher precision (for more accuracy).
However, exploring alternative representations often requires significant code
revision.

This Pintool simulates execution with alternative real number implementations at
the binary level. The tool supports x86\_64 programs and a variety of
alternative implementations, including IEEE single (32-bit) precision and
arbitrary precision using the GNU MPFR library. It also supports tracing
execution and generating a digraph of computation, optionally with the
difference between single- and double-precision calculated at each operation.

## Instructions

Building and using this project currently requires some experience in systems
development and tool infrastructure. This file includes some basic installation
and compilation instructions, but they may require some manual modification on
your specific platform.  Contact the author if you encounter issues.

Currently this project only works on x86\_64 Linux.

Dependencies:

* [Intel Pin 3.7](https://software.intel.com/en-us/articles/pintool-downloads)
  for most tools (Tested version: 97619)
* [Intel Pin 2.14](https://software.intel.com/en-us/articles/pintool-downloads)
  for MPFR tool (Tested version: 71313)

See the release notes for limitations on which versions of gcc are compatible.
For instance, with Pin 2.14 71313 "... you cannot use gcc versions 4.5 or newer
to compile Probe mode tools ..." Also, with older versions of Pin and 4.x Linux
kernels, you may have to use the `-ifeellucky` option.

You must set your `PIN_ROOT` environment variable to the root of the Pin
installation, and if you wish to use the `shval` wrapper script, you must also
set the `SHVAL_ROOT` environment variable to the root of this repository.

To build all tools, use the `./build.sh` command in the `tools` directory. To
run a tool, use a command similar to the following:

    pin -t /path/to/obj-intel64/shval-native32.so -- /path/to/app

This assumes that the `pin` wrapper is in your `PATH`. Application parameters
can be included at the end if necessary. In addition, most tools provide various
command-line options to customize their runtime behavior. To see descriptions of
each tool's options, run the tool without an app. These options must be
specified after the tool library but before the `--` separator.

There are a variety of tools; see `tools/makefile.rules` for the complete list.

Note: Pin 3.2 removed the `pin_isa.H` file, required by the `unum` tool, and the
MPFR tool is incompatible with Pin 3.x because it is an external library that
(currently) does not build against the Pin CRT. Both of these tools are
unsupported at the moment for this reason, although I anticipate that with some
work they could be made working again.

You can also use the provided `shval` wrapper script. Run `shval -h` to see the
list of options.


## Papers

* "[Floating-Point Shadow Value Analysis](http://dl.acm.org/citation.cfm?id=3018826)" (ESPT'16 at SC'16)

## Authors

SHVAL was originally written by Michael O. Lam, lam26@llnl.gov.

## License

SHVAL is released under an LGPL license. For more details see the LICENSE file.

LLNL-CODE-729118

