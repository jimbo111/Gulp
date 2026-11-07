# Build and run the Gulp Beacon OAST server. (M11 wires the real listeners.)
# Ports: DNS 53/udp+tcp, HTTPS 443. In production grant CAP_NET_BIND_SERVICE
# (docker run --cap-add=NET_BIND_SERVICE) or map the ports, rather than running as root.
FROM swift:6.0-noble AS build
WORKDIR /src
COPY . .
RUN swift build -c release --product gulp-beacon

FROM swift:6.0-noble-slim
WORKDIR /app
COPY --from=build /src/.build/release/gulp-beacon /app/gulp-beacon
EXPOSE 53/udp 53/tcp 443/tcp
ENTRYPOINT ["/app/gulp-beacon"]
