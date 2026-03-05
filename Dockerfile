FROM golang:1.23-alpine3.20 AS builder
ARG VERSION=dev-snapshot
RUN mkdir /build
RUN apk add --update make gcc musl-dev
WORKDIR /build
COPY . /build
RUN make BUILD_VERSION=${VERSION}

FROM alpine:3.20 AS runner
LABEL org.opencontainers.image.source="https://github.com/DataDog/threatest/"
COPY --from=builder /build/dist/threatest /threatest
ENTRYPOINT ["/threatest"]
CMD ["--help"]