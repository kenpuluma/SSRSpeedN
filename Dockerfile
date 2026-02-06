FROM python:3.10

WORKDIR /app
COPY . /app
ENV CRON_FREQUENCY "*/30 * * * *"

# Install cron and dependencies
RUN apt-get -y update && apt-get -y install cron
RUN pip install six && pip install -r requirements.txt
RUN ln -snf /usr/share/zoneinfo/Asia/Shanghai /etc/localtime && echo Asia/Shanghai >/etc/timezone

# Setup cron job
RUN { \
    echo "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"; \
    echo "${CRON_FREQUENCY} cd /app && python /app/main.py --url-file ./subscription/subscription --mode pingonly"; \
    } > /etc/cron.d/my-cron-job
RUN chmod 0644 /etc/cron.d/my-cron-job
RUN crontab /etc/cron.d/my-cron-job

RUN mkdir -p /app/subscription /app/results /app/logs

CMD ["cron", "-f"]
VOLUME ["/app/subscription", "/app/results", "/app/logs"]
