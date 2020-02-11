# get python image
FROM python:3.7-alpine
ENV PYTHONUNBUFFERED 1
# create root directory for web app
RUN mkdir -p /data/web
WORKDIR /data/web
# copy web app data
COPY . /data/web/
# install requirements
RUN apk add --no-cache postgresql-libs \
  && apk add --no-cache bash \
  && apk add --no-cache --virtual .build-deps \
  gcc \
  musl-dev \
  postgresql-dev \
  py3-cffi \
  libffi-dev \
  && pip install --no-cache-dir -r requirements_dev.txt \
  && apk del .build-deps
# entrypoint
ENTRYPOINT ["/data/web/docker-entrypoint.sh"]
EXPOSE 8000