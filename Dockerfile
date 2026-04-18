FROM mcr.microsoft.com/powershell:7.4-debian-12

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    ca-certificates \
    libssl-dev \
    make \
    pkg-config \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /opt/project
COPY . /opt/project

RUN chmod +x /opt/project/docker/run_all.sh

ENV CC=gcc
ENTRYPOINT ["/opt/project/docker/run_all.sh"]
