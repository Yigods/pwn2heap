FROM ubuntu:24.04
LABEL auther_template="CTF-Archives"
ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends         xinetd ca-certificates     && rm -rf /var/lib/apt/lists/*     && (userdel -r ubuntu 2>/dev/null || true)     && useradd -u 1000 -m ctf

WORKDIR /home/ctf

# Chroot runtime base, following CTF-Archives/ctf-docker-template pwn layout.
RUN mkdir -p /home/ctf/usr     && cp -a /lib /lib64 /home/ctf/ 2>/dev/null || true     && cp -a /usr/lib /home/ctf/usr/ 2>/dev/null || true     && mkdir -p /home/ctf/dev /home/ctf/bin     && mknod /home/ctf/dev/null c 1 3     && mknod /home/ctf/dev/zero c 1 5     && mknod /home/ctf/dev/random c 1 8     && mknod /home/ctf/dev/urandom c 1 9     && chmod 666 /home/ctf/dev/*     && cp /bin/sh /home/ctf/bin/     && cp /bin/ls /home/ctf/bin/     && cp /bin/cat /home/ctf/bin/     && cp /usr/bin/timeout /home/ctf/bin/ 2>/dev/null || true     && cp /usr/bin/id /home/ctf/bin/ 2>/dev/null || true     && mkdir -p /home/ctf/usr/lib64     && if [ -e /home/ctf/usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2 ]; then ln -sf ../lib/x86_64-linux-gnu/ld-linux-x86-64.so.2 /home/ctf/usr/lib64/ld-linux-x86-64.so.2; fi

COPY ./config/ctf.xinetd /etc/xinetd.d/ctf
RUN echo "Blocked by ctf_xinetd" > /etc/banner_fail
COPY ./service/docker-entrypoint.sh /docker-entrypoint.sh
RUN chmod +x /docker-entrypoint.sh

COPY ezpz2_patched /home/ctf/attachment
COPY ld-linux-x86-64.so.2 libc.so.6 /home/ctf/

RUN chown -R root:ctf /home/ctf     && chmod -R 750 /home/ctf     && chmod 711 /home/ctf/attachment     && chmod 755 /home/ctf/ld-linux* 2>/dev/null || true     && chmod 744 /home/ctf/libc*.so* 2>/dev/null || true     && touch /home/ctf/flag     && chmod 744 /home/ctf/flag \
    && chmod 666 /home/ctf/dev/*

EXPOSE 9999
ENTRYPOINT ["/bin/bash", "/docker-entrypoint.sh"]
