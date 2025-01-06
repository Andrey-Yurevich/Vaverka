FROM golang:1.23-alpine3.21 AS builder
LABEL authors="Andrei Yurevich"
ENV LIBPCAP_VERSION 1.10.5

WORKDIR /build

RUN apk add build-base flex bison linux-headers

RUN wget https://www.tcpdump.org/release/libpcap-$LIBPCAP_VERSION.tar.gz && \
        tar xvf libpcap-$LIBPCAP_VERSION.tar.gz && \
        cd libpcap-$LIBPCAP_VERSION && \
        ./configure --with-pcap=linux && \
        make

COPY . .

ENV LD_LIBRARY_PATH "-L/build/libpcap-$LIBPCAP_VERSION"
ENV CGO_LDFLAGS "-L/build/libpcap-$LIBPCAP_VERSION"
ENV CGO_CPPFLAGS "-I/build/libpcap-$LIBPCAP_VERSION"

RUN go build .

FROM alpine:3.21 AS vaverka
WORKDIR /vaverka

COPY --from=builder /build/Vaverka vaverka
ENTRYPOINT /vaverka/vaverka