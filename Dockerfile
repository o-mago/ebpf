FROM golang:1.24-alpine

RUN apk update && apk add llvm && apk add clang && apk add libbpf-dev && apk add linux-headers && apk add bash
