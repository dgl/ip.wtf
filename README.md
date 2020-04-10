# ip.d.cx

The code behind http://ip.d.cx/

## Building and running

### Testing

```sh
go build .
./ipdcx
```

### Production

```sh
sudo setcap cap_net_bind_service=+ep ./ipdcx
./ipdcx -listen :http
```

## Licence

WTFPLv2, no warranty. https://dgl.cx/licence
