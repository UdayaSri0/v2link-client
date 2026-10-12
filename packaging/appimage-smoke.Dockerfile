ARG UBUNTU_VERSION=22.04
FROM ubuntu:${UBUNTU_VERSION}
RUN apt-get -o Acquire::Retries=3 -o Acquire::http::Timeout=30 -o Acquire::https::Timeout=30 update \
    && DEBIAN_FRONTEND=noninteractive apt-get -o Acquire::Retries=3 -o Acquire::http::Timeout=30 -o Acquire::https::Timeout=30 install -y --no-install-recommends \
    python3 binutils xvfb xauth x11-utils libgl1 libegl1 libdbus-1-3 fontconfig fonts-dejavu-core \
    && rm -rf /var/lib/apt/lists/* \
    && for package in libxcb-icccm4 libxcb-cursor0 libxcb-image0 libxcb-keysyms1 libxcb-render-util0 libxcb-util1 libxkbcommon-x11-0; do \
      if dpkg-query -W -f='${Status}' "$package" 2>/dev/null | grep -q 'install ok installed'; then \
        echo "Unexpected Qt/XCB utility in clean environment: $package"; exit 1; \
      fi; \
    done
COPY scripts/smoke_appimage.py scripts/prepare_appdir.py /test/
USER 65534:65534
CMD ["python3", "-u", "/test/smoke_appimage.py", "/artifacts/app.AppImage", "--log-dir", "/logs"]
