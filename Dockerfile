FROM python:3.10

WORKDIR /app
COPY . /app
ENV CRON_FREQUENCY "*/30 * * * *"

# Install cron and setup the cron job
RUN apt-get -y update && apt-get -y install cron git libsodium-dev shadowsocks-libev build-essential autoconf libtool libssl-dev libpcre3-dev libev-dev asciidoc xmlto automake
RUN pip install six asciidoc && pip install -r requirements.txt

RUN { \
    echo "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"; \
    echo "${CRON_FREQUENCY} cd /app && python /app/main.py --url-file ./subscription/subscription --mode pingonly >> /app/logs/cron.log 2>&1"; \
    } > /etc/cron.d/my-cron-job
RUN chmod 0644 /etc/cron.d/my-cron-job
RUN crontab /etc/cron.d/my-cron-job

RUN git clone https://github.com/shadowsocks/simple-obfs.git
RUN cd simple-obfs && git submodule update --init --recursive && ./autogen.sh && ./configure && make && make install
RUN ln -s /usr/local/bin/obfs-local /usr/local/bin/simple-obfs
RUN mkdir /app/subscription /app/results /app/logs && touch /app/logs/cron.log
RUN chmod +x /app/clients/v2ray-core/v2ray

CMD ["cron", "-f"]
VOLUME ["/app/subscription", "/app/results", "/app/logs"]
