# ip.wtf

The code behind https://ip.wtf

## Using

Just visit it.

What's my IP in a script?
```sh
IPV4=$(curl -s v4.ip.wtf)
IPV6=$(curl -s v6.ip.wtf)
echo "Public IPv4: $IPV4, Public IPv6: $IPV6"
```

## Why?

Because I can.

Sites like this give you details like the headers their reverse proxy server
injects so the results aren't very trustworthy, the "Raw HTTP request" is really
the bytes your browser (or a proxy on your side of the connection) sent.

In general this aims to be as privacy preserving as possible, while revealing
details about your browser and connection, that might be sensitive.

## Building and running

### Testing

```sh
go run .
```

Use http://localhost:8080

### Production

Something like:

```sh
$ docker run --name=ip.wtf -d --net=host ghcr.io/dgl/ip.wtf:latest
$ curl localhost:8080
127.0.0.1
```

In reality you'll need a few more pieces for a full production setup:

- Put haproxy in front of this and enable the PROXY
  protocol support, see
  https://dgl.cx/2022/04/showing-you-your-actual-http-request
- Provide the MaxMind database files in /data, e.g. add `-v db:/data`

## Licence

This product includes GeoLite2 data created by MaxMind, available from
<a href="https://www.maxmind.com">https://www.maxmind.com</a>.

Otherwise; 0BSD, no warranty. http://©.st/dgl
