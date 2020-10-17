## We specify image we need for our go application build
FROM golang:1.15.3-alpine3.12 AS build

## "go get" command requires git
RUN apk add git

RUN mkdir /app

# copy source only
COPY te_check_file.go /app

WORKDIR /app

## download dendencies
RUN go get github.com/Jeffail/gabs && go get github.com/h2non/filetype && go get github.com/utahta/go-openuri

## we run go build to compile the binary
## executable of our Go program
RUN go build -o te_check_file .

# runtime image
FROM alpine:3.12
# bring exe from build image step
COPY --from=build /app/te_check_file /bin/te_check_file
# output
WORKDIR /out
# main service
ENTRYPOINT ["/bin/te_check_file"]