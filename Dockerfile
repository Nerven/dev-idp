FROM --platform=$BUILDPLATFORM rust:1-alpine@sha256:a10e64dd139b7387337c7fbe8aca31b959b57b2fd4c8ae20a02cf1d6ea424dce AS build
RUN apk add --no-cache musl-dev cargo-auditable
WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY src ./src
ARG TARGETARCH
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/usr/local/cargo/git \
    --mount=type=cache,target=/src/target \
    case "$TARGETARCH" in \
      amd64) target=x86_64-unknown-linux-musl ;; \
      arm64) target=aarch64-unknown-linux-musl ;; \
      *) echo "unsupported TARGETARCH: $TARGETARCH" >&2; exit 1 ;; \
    esac \
    && if [ "$target" != "$(rustc -vV | sed -n 's/^host: //p')" ]; then \
         export RUSTFLAGS="-C linker=rust-lld"; \
       fi \
    && rustup target add "$target" \
    && cargo auditable build --release --locked --target "$target" \
    && cp "target/$target/release/dev-idp" /dev-idp

FROM scratch
COPY --from=build /dev-idp /dev-idp
EXPOSE 8383

ENTRYPOINT ["/dev-idp"]
CMD ["/config/dev-idp.toml"]
