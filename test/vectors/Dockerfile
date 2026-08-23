FROM ubuntu:24.04 AS base

ENV DEBIAN_FRONTEND=noninteractive
ENV LANG=C.UTF-8
ENV LC_ALL=C.UTF-8

RUN apt-get update && apt-get install -y --no-install-recommends \
    nodejs \
    python3 \
    ruby \
    golang-go \
    default-jdk \
    perl libjson-perl \
    curl ca-certificates binutils \
    && rm -rf /var/lib/apt/lists/*

RUN SWIFT_URL="https://download.swift.org/swift-6.0.3-release/ubuntu2404/swift-6.0.3-RELEASE/swift-6.0.3-RELEASE-ubuntu24.04.tar.gz" \
    && curl -sL "$SWIFT_URL" | tar xz --strip-components=1 -C /usr \
    || echo "Swift install optional — skipping"

WORKDIR /app
COPY runners/ /app/runners/
COPY cross-sdk-diff.sh /app/
COPY generate-matrix.sh /app/
COPY protocol-vectors.json /app/

RUN chmod +x /app/cross-sdk-diff.sh /app/generate-matrix.sh

RUN cd /app/runners && javac Serialize.java

RUN useradd -m runner
USER runner

ENTRYPOINT ["/app/cross-sdk-diff.sh"]
CMD []
