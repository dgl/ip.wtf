## About

[This site](/) shows you information about your [IP
address](https://en.wikipedia.org/wiki/IP_address) and web browser.

It's not going to try to sell you a VPN. Don't listen to the misinformation
about VPNs, instead watch [this
excellent](https://www.youtube.com/watch?v=WVDQEoe6ZWY) Tom Scott video.

## API

Is there an API?  Yes.

At its simplest you can do:

<pre><code id="your-ip">
$ curl ip.wtf
[your IP]</code></pre>

<script>
  (async function() {
    let res = await fetch("https://ip.wtf", { headers: { Accept: "text/plain" } });
    let data = await res.text();
    document.querySelector("#your-ip").textContent = "$ curl ip.wtf\n" + data;
  })();
</script>

To get the IP address you're connecting from; the API detects access from curl
and automatically defaults to just the text version.

In code add a header `Accept: text/plain` to get the plain text version. You
can also use `application/json` to get a bit more information.

JavaScript example:

    let res = await fetch("https://ip.wtf", { headers: { Accept: "application/json" } });
    let data = await res.json();
    console.log(data);

Which gives you:

<pre><code id="json-output"></code></pre>
<script>
  (async function() {
    let res = await fetch("https://ip.wtf", { headers: { Accept: "application/json" } });
    let data = await res.json();
    document.querySelector("#json-output").textContent = JSON.stringify(data, "", "  ");
  })();
</script>

If you use the hostname `ip.wtf` the client (browser or other HTTP client) will
pick the IP protocol to use. You can also use the hostnames `v4.ip.wtf` or
`v6.ip.wtf` to force a particular protocol, or otherwise ask the client to pick
the relevant protocol.

For example with curl you can do:

    $ curl -4 ip.wtf
    $ curl -6 ip.wtf

Access works over http or https; API access from a non-browser is never
redirected to HTTPS (browsers may choose to use HTTPS though). If you want to
force HTTP you can use the hostnames `nossl.ip.wtf` or `neverssl.ip.wtf`. (You
can also use those hostnames manually in a similar way to
[neverssl.com](http://neverssl.com).)

Reasonable use is fine (i.e. 1 req/hour per source IP and not in something that
is widely deployed). If you need more contact us first, we reserve the right to
block unreasonable access otherwise.

## Fun

For a little easter egg try: `curl ip.wtf/moo`

There's a small collection of fun things, which is slowly growing into a set of
demos; see [ip.wtf/fun](https://ip.wtf/fun).

## Privacy

This site collects data about your device and connection to the site in order
to implement its primary purpose of showing you this information.

The information displayed includes your IP address and hostname.

Depending on your configuration some of the tests performed by this site may
reveal a different IP address; this data is only aggregated client side and
never stored on a server.

In order to look up your hostname a reverse DNS lookup is performed, this uses
a third party DNS provider (Google Public DNS, see
[privacy](https://developers.google.com/speed/public-dns/privacy)).

Any information collected that identifies your IP address is not stored for
longer than one day, unless necessary to prevent abuse of the site, or if you
otherwise share the data with us (e.g. send us an email, Twitter, etc).

This site does not use cookies, or store data on your device.

This product includes GeoLite2 data created by MaxMind, available from
<a href="https://www.maxmind.com">https://www.maxmind.com</a>.

## Sponsor

If you like this, you can say thank you: https://ko-fi.com/webgl

## Contact

You can find us on [Twitter](https://twitter.com/ip_wtf) or you can email us
here (click twice due to abuse prevention measures).

<span id="contact-us"></span>

<script>
const t = "Contact us";
let a = document.createElement("a");
if (window.name.length == 4) {
  const h = (window.name + "\x2eoo").split(/\./).slice(-2);
  const m = location.hostname.split(/\./).slice(-2).join("") + '\x40' + h.reverse().join(".");
  a.href = "\x6d\x61\x69\x6c\x74\x6f\x3a" + m + "?body=" +
    encodeURIComponent("[Please put your words here]");
  a.textContent = t + ": " + m;
} else {
  a.addEventListener("click", e => { window.name = "fail" });
  a.textContent = t;
  a.href = "";
}
document.querySelector('#contact-us').appendChild(a);
</script>.
