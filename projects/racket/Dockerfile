# SPDX-License-Identifier: (Apache-2.0 OR MIT)
#
# Racket CS on the OSS Verify builder. tools/check passes REPO, COMMIT and BASE_BUILDER.
ARG BASE_BUILDER=oss-verify-base-builder
FROM ${BASE_BUILDER}
ARG REPO
ARG COMMIT
RUN fetch-commit $SRC/racket
# Chez Scheme's portable-bytecode boot files, so that Racket CS builds
# without an existing Racket or Chez Scheme. Racket's makefile names the
# branch of github.com/racket/pb for its version of Chez Scheme, which is
# never moved, and tools/check records the commit in its manifest.
RUN make -C $SRC/racket pb-fetch
COPY build.sh $SRC/
WORKDIR $SRC/racket
