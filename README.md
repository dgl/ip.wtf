# ip.d.cx

The code behind http://ip.d.cx/

## Using

Just visit it.

What's my IP in a script?
```sh
IPV4=$(curl -s v4.ip.d.cx)
IPV6=$(curl -s v6.ip.d.cx)
echo "Public IPv4: $IPV4, Public IPv6: $IPV6"
```

## Building and running

### Testing

```sh
go build .
./ipdcx
```

Use http://localhost:8080/

### Production

```sh
sudo setcap cap_net_bind_service=+ep ./ipdcx
./ipdcx -listen :http -v4-host v4.ip.d.cx -v6-host v6.ip.d.cx
```

## Licence

WTFPLv2, no warranty. https://dgl.cx/licence
