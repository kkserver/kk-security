FROM alpine:latest

RUN echo "Asia/shanghai" >> /etc/timezone

COPY ./main /bin/kk-security

RUN chmod +x /bin/kk-security

COPY ./config /config

COPY ./app.ini /app.ini

ENV KK_ENV_CONFIG /config/env.ini

VOLUME /config

CMD kk-security $KK_ENV_CONFIG

