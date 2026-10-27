# Patch style and report preferences

Racket CS is Racket on Chez Scheme. The fuzz targets run untrusted input through the reader, the printer, number parsing, regexps, fasl decoding, and the expander, compiler and runtime (`racket/src/fuzz/safe-eval.rkt`).

## Findings

Send findings to samth@racket-lang.org. Give a short reproducer that runs under plain `racket`, if the bug can be reached that way, as well as the fuzz input.

## Patches

- Write patches against racket/racket `master`. Write a fix to Chez Scheme against racket/ChezScheme, whose code is also in `racket/src/ChezScheme` of the Racket repository.
- One fix per patch.
- Add a test in `pkgs/racket-test-core` where possible.
- Racket CS builds from the generated files in `racket/src/cs/schemified/`. Change the Racket sources in `racket/src/expander`, `racket/src/io`, `racket/src/regexp` and the rest, not the generated files.
