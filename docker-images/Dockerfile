
FROM ubuntu:18.04


RUN apt-get update && apt-get install -y \
    curl \
    && curl -fsSL https://github.com/opencontainers/runc/releases/download/v1.1.11/runc.amd64 -o /usr/local/bin/runc \
    && chmod +x /usr/local/bin/runc


RUN curl -fsSL https://github.com/moby/buildkit/releases/download/v0.12.4/buildkit-v0.12.4.linux-amd64.tar.gz | tar -xz -C /usr/local/bin/


RUN mkdir /app && echo "FROM scratch!" > /app/Dockerfile


EXPOSE 80 443

CMD ["/bin/bash"]
