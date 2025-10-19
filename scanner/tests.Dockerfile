FROM golang:1.25.3-alpine3.22

RUN apk add build-base flex bison linux-headers iproute2

WORKDIR /build

ENV LIBPCAP_VERSION=1.10.5
ENV LD_LIBRARY_PATH="-L/build/libpcap-$LIBPCAP_VERSION"
ENV CGO_LDFLAGS="-L/build/libpcap-$LIBPCAP_VERSION"
ENV CGO_CPPFLAGS="-I/build/libpcap-$LIBPCAP_VERSION"


RUN wget https://www.tcpdump.org/release/libpcap-$LIBPCAP_VERSION.tar.gz && \
        tar xvf libpcap-$LIBPCAP_VERSION.tar.gz && \
        cd libpcap-$LIBPCAP_VERSION && \
        ./configure --with-pcap=linux && \
        make

WORKDIR /app

COPY go.mod go.sum ./

RUN go mod download

COPY . .

#CMD ["go", "test", "-v", "./..."]
CMD ["sh", "-c", "go test -v ./..."]