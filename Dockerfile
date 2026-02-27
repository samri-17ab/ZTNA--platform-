FROM golang:1.22-alpine AS builder

WORKDIR /app
COPY go.mod ./
RUN go mod download

COPY main.go ./
RUN go build -o agent main.go

FROM alpine:latest
WORKDIR /root/
COPY --from=builder /app/agent .

CMD ["./agent"]
