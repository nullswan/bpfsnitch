# Use Golang alpine image as the build environment
FROM golang:1.22-alpine AS builder

# Set the target architecture
ARG TARGETARCH
ENV TARGETARCH=${TARGETARCH}
ENV CGO_ENABLED=1 GOOS=linux GOARCH=${TARGETARCH} BPF_TARGET=${TARGETARCH}

# Install necessary packages
RUN apk add --no-cache clang llvm-dev libbpf-dev build-base

# Set the working directory
WORKDIR /build

# Copy and build BPF artifacts
COPY ./bpf ./bpf
RUN chmod +x ./bpf/build.sh && TARGETARCH=${TARGETARCH} sh ./bpf/build.sh

# Download Go module dependencies
COPY go.mod go.sum ./
RUN go mod download

# Copy the rest of the source code and build the project
COPY . .
RUN go build -o ./dist/ -v ./...

# Use a minimal alpine image for the runtime environment
FROM alpine:latest

# Set the working directory
WORKDIR /root/

# Copy the built executable from the builder stage
COPY --from=builder /build/dist .
COPY --from=builder /build/bpfsnitch_lib_*.o .

# Ensure the main executable has the right permissions
RUN chmod +x ./bpfsnitch

# Specify the default command to run the executable
CMD ["./bpfsnitch"]