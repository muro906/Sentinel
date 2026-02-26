FROM zeek/zeek:lts

USER root
RUN apt-get update && apt-get install -y --no-install-recommends \
    inotify-tools bash \
    && rm -rf /var/lib/apt/lists/*

ENV PATH="/usr/local/zeek/bin:/opt/zeek/bin:${PATH}"

COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]
