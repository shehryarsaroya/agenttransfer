FROM golang:1.25-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
ARG VERSION=0.6.0-docker
RUN CGO_ENABLED=0 go build -trimpath \
      -ldflags "-s -w -X github.com/shehryarsaroya/agenttransfer/internal/server.Version=${VERSION}" \
      -o /agenttransfer .

FROM alpine:3.21
RUN apk add --no-cache ca-certificates \
 && adduser -D -H -u 65532 agenttransfer \
 && mkdir /data && chown agenttransfer:agenttransfer /data
COPY --from=build /agenttransfer /usr/local/bin/agenttransfer
USER agenttransfer
ENV DATA_DIR=/data
# Persist certmagic state in the mounted volume in DOMAIN mode. Without these,
# an unprivileged container may try to write under a nonexistent home.
ENV HOME=/data XDG_DATA_HOME=/data
VOLUME /data
# 443/80 when DOMAIN is set (autocert), 8080 otherwise, 25 for inbound SMTP
EXPOSE 443 80 25 8080
ENTRYPOINT ["agenttransfer"]
CMD ["serve"]
