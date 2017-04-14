# Sum example

This very simple example adds a value of 0.1 ten times, which should result in
an answer of exactly 1.0. However, there are two sources of rounding error: 1)
the initial conversion of the source constant "0.1" to double precision during
compilation, and 2) the multiple addition operations.

To run this example, use the `run` make target (after compiling the tools):

    make run

This should give the following results:

* `native32` - The relative error should be near machine epsilon for 32-bit
  floating-point representation.

* `native64` - The relative error should be zero; this is essentially a
  verification routine.

* `mpfr` - The relative error should be near machine epsilon for 64-bit
  floating-point representation.

