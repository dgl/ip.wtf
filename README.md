# ip.wtf

The code behind http://ip.wtf

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

```sh
sudo setcap cap_net_bind_service=+ep ./ipdcx
./ipdcx -listen :http -v4-host v4.ip.d.cx -v6-host v6.ip.d.cx
```

## Licence

This product includes GeoLite2 data created by MaxMind, available from
<a href="https://www.maxmind.com">https://www.maxmind.com</a>.

Otherwise; WTFPLv2, no warranty. https://dgl.cx/licence
