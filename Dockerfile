FROM golang:1.19-alpine3.16@sha256:4e2a54594cfe7002a98c483c28f6f3a78e5c7f4010c355a8cf960292a3fdecfe AS builder
ARG VERSION=dev-snapshot
RUN mkdir /build
RUN apk add --update make
WORKDIR /build
COPY . /build
RUN make BUILD_VERSION=${VERSION}

FROM alpine:3.16@sha256:3d426b0bfc361d6e8303f51459f17782b219dece42a1c7fe463b6014b189c86d AS runner
LABEL org.opencontainers.image.source="https://github.com/DataDog/threatest/"
COPY --from=builder /build/dist/threatest /threatest
ENTRYPOINT ["/threatest"]
CMD ["--help"]