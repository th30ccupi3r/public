FROM erlang:25-alpine

WORKDIR /app
RUN apk add --no-cache build-base git

COPY run.sh .

EXPOSE 4369
EXPOSE 4368

CMD ["sh", "./run.sh"]

