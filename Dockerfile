# syntax=docker/dockerfile:1
FROM golang:1.26.9 AS build
WORKDIR /src
COPY go.mod ./
RUN go mod download
COPY . .
ARG VERSION=dev
ARG COMMIT=unknown
ARG BUILD_DATE=unknown
RUN CGO_ENABLED=0 go build -trimpath -buildvcs=false \
    -ldflags "-s -w \
      -X github.com/PrPlanIT/zitadel-flatroles/src/version.Version=${VERSION} \
      -X github.com/PrPlanIT/zitadel-flatroles/src/version.Commit=${COMMIT} \
      -X github.com/PrPlanIT/zitadel-flatroles/src/version.BuildDate=${BUILD_DATE}" \
    -o /out/flatroles ./cmd/flatroles

# Pure stdlib server — no runtime tooling, no CA bundle needed.
FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/flatroles /usr/local/bin/flatroles
USER nonroot:nonroot
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/flatroles"]
