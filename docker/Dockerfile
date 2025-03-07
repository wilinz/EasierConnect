# 第一阶段：编译阶段
FROM golang:1.23-alpine AS builder

# 设置工作目录
WORKDIR /app

# 复制其余的源代码
COPY . .
RUN go mod download
RUN go mod tidy
RUN go build -o ecapp main.go

# 第二阶段：运行阶段
FROM alpine:latest

# 设置工作目录
WORKDIR /root/

RUN apk add --no-cache tzdata

# 从编译阶段复制二进制文件
COPY --from=builder /app/ecapp .

# 运行二进制文件
CMD ["./ecapp"]