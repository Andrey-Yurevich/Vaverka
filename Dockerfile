FROM golang:1.25.4-alpine3.22 AS builder
LABEL authors="Andrei Yurevich"

WORKDIR /build

RUN apk add build-base flex bison linux-headers

ENV LIBPCAP_VERSION=1.10.5

RUN wget https://www.tcpdump.org/release/libpcap-$LIBPCAP_VERSION.tar.gz && \
        tar xvf libpcap-$LIBPCAP_VERSION.tar.gz && \
        cd libpcap-$LIBPCAP_VERSION && \
        ./configure --with-pcap=linux && \
        make

COPY . .

ENV LD_LIBRARY_PATH="-L/build/libpcap-$LIBPCAP_VERSION"
ENV CGO_LDFLAGS="-L/build/libpcap-$LIBPCAP_VERSION"
ENV CGO_CPPFLAGS="-I/build/libpcap-$LIBPCAP_VERSION"

RUN go build .

FROM alpine:3.22 AS vaverka
WORKDIR /vaverka

COPY --from=builder /build/Vaverka vaverka
ENTRYPOINT ["/vaverka/vaverka"]
