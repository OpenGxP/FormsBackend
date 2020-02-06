# get python image
FROM python:3.7
ENV PYTHONUNBUFFERED 1
# create root directory for web app
RUN mkdir -p /data/web
WORKDIR /data/web
# copy web app data
COPY . /data/web/
# install requirements
RUN pip install --no-cache-dir -r requirements_dev.txt

# entrypoint
ENTRYPOINT ["/data/web/docker-entrypoint.sh"]
EXPOSE 8000