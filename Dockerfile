FROM golang:1.25.4-alpine3.22 AS builder
LABEL authors="Andrei Yurevich"

WORKDIR /build

RUN apk add build-base flex bison linux-headers musl-dev pkgconf

ENV LIBPCAP_VERSION=1.10.5

RUN wget https://www.tcpdump.org/release/libpcap-$LIBPCAP_VERSION.tar.gz && \
        tar xvf libpcap-$LIBPCAP_VERSION.tar.gz && \
        cd libpcap-$LIBPCAP_VERSION && \
        ./configure --with-pcap=linux --disable-shared --enable-static && \
        make -j && make install

ENV CGO_ENABLED=1
ENV CGO_CFLAGS="-O2"
ENV CGO_LDFLAGS="-static -lpcap"

COPY . .

RUN go build -tags netgo,osusergo -ldflags='-s -w -linkmode external -extldflags "-static"' .

FROM alpine:3.22 AS vaverka
WORKDIR /vaverka

COPY --from=builder /build/Vaverka vaverka
ENTRYPOINT ["/vaverka/vaverka"]
