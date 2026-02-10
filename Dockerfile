FROM golang:1.21-alpine AS builder

WORKDIR /app
COPY go.mod ./
COPY main.go ./
RUN go build -o server main.go

FROM alpine:latest
WORKDIR /app
COPY --from=builder /app/server .
COPY *.html ./
COPY *.css ./
COPY *.png ./
COPY *.svg ./

EXPOSE 8080
CMD ["./server"]
