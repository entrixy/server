# The websocket worker. It is a single static binary: the runtime image carries
# no language, no extensions and no package manager, only the program and the
# certificates it needs to call a webhook over https.
#
# The worker's dependencies are in the repository (ws/vendor), so the build
# fetches nothing: on a machine that can only reach its distribution's mirrors
# and the image registry, this still works.
FROM golang:1.23-alpine AS build
WORKDIR /src
COPY ws/ ./
RUN CGO_ENABLED=0 go build -mod=vendor -trimpath -ldflags="-s -w" -o /entrixy-ws .

FROM alpine:3.20
RUN apk add --no-cache ca-certificates tzdata
COPY --from=build /entrixy-ws /usr/local/bin/entrixy-ws
USER nobody
CMD ["entrixy-ws"]
