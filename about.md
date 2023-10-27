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
    p = document.querySelector("#json-output").textContent = JSON.stringify(data, "", "  ");
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
otherwise share the data with us (e.g. send us an email, etc.).

This site does not use cookies, or store data on your device.

This product includes GeoLite2 data created by MaxMind, available from
<a href="https://www.maxmind.com">https://www.maxmind.com</a>.

## Sponsor

If you like this, you can say thank you:
[ko-fi.com/webgl](https://ko-fi.com/webgl). See <a href="https://dgl.c&#x78;/"
id="me">dgl.cx</a> for more on my projects.

## Contact

You can <span id="contact-link"> <noscript><a href="https://dgl.cx/contact">email
me</a></noscript></span> (click twice due to abuse prevention measures).

<style>
  #contact-link { text-decoration: underline; color: blue; }
</style>

<script>
const sd = {{ if .Devel }}"ip.wtf";{{ else }}location.hostname.split(/\./).slice(-2).join("");{{ end }}
const t = "email me";

let a = document.createElement("a");
{{ if ($.Request.FormValue "cy_") -}}
if (name.length == 2) {
  const h = (window.name + "\x2edgl").split(/\./).slice(-2);
  const m = "web-contact-" + sd + '\x40' + h.reverse().join(".");
  a.href = "\x6d\x61\x69\x6c\x74\x6f\x3a" + m;
  a.textContent = t + ": " + m;
} else {{ end -}}
{
  (async function() {
    let res = await fetch("https://8.8.8.8/resolve?name=__" + ([...document.querySelectorAll("h2")].at(-1).id) + "." + sd + "&type=TXT");
    let data = await res.json();
    x = data.Answer[0].data;
  })();
  a.addEventListener("click", e => { name = document.querySelector("#me").href.match(/\.(..)\//)[1] });
  a.textContent = t;
  let pp; pp = () => {
    if (window.p && window.x)
      a.href = "/about?" + window.p.match(new RegExp(x.replace(/x(..)/g, (_,x)=>String.fromCharCode(parseInt(x, 16)))))[2] + "=" + Math.random() + "#contact";
    else
      setTimeout(pp, 100);
  };
  window.addEventListener("mousemove", pp);
  window.addEventListener("keypress", pp);
  window.addEventListener("touchstart", pp);
}
document.querySelector('#contact-link').appendChild(a);
</script>
