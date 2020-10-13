FROM alpine:edge  AS builder
LABEL maintainer="Emilien Gobillot"

RUN apk add \ 
    bison \
    alpine-sdk \
    cmake \
    flex flex-dev \
    git \
    libedit-dev \
    llvm10-libs llvm10-static \
    llvm10-dev \
    clang-libs clang-dev \
    zlib-dev \
    libelf libelf-static elfutils-dev \
    coreutils \
    python2 python3 \
    linux-headers bash
    
RUN git clone https://github.com/iovisor/bcc.git

RUN mkdir bcc/build && \
    cd bcc/build && \
    cmake .. && \
    make -j$(nproc) && \
    make install && make clean

RUN cd bcc/build && cmake -DPYTHON_CMD=python3 .. && \
    cd src/python/ && \
    make -j $(nproc) && \
    make install && make clean


FROM alpine:edge
RUN apk add --no-cache python3 libelf clang-libs llvm10-libs bash

COPY --from=builder /usr/share/bcc /usr/share/bcc 
COPY --from=builder /usr/lib/python3.8/site-packages/bcc /usr/lib/python3.8/site-packages/bcc
COPY --from=builder /usr/lib64/libbcc.so /usr/lib/libbcc.so
RUN ln -s /usr/lib/libbcc.so /usr/lib/libbcc.so.0

COPY calltop.py ebpf.c usdt.c ./

CMD [ "python3", "./calltop.py" ]