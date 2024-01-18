# Just some fun

Want to add some fun to your IP address? You've found the right place.

These are little self contained demos, that might do something fun, or make a
point somehow.

## How?

Easy! Copy emoji.html and adjust it to your liking. Then submit a PR for it!

Because it's so simple you shouldn't need a web server, just open the file
directly in your browser for development.

These files should be self contained, i.e. you only add an HTML file to the
repo, using inline JavaScript. Best practices be damned. If you need to use
external code, pull it in via unpkg.com.

### Details

ip.wtf has a simple API, which allows anywhere to use CORS to fetch your IP
address.

Add this snippet of JavaScript inside an async function (see emoji.html for a
working example):

```js
let res = await fetch("http://ip.wtf", { headers: { Accept: "text/plain" }});
let ip = res.text();
ip = ip.trim();
```

Then do something fun to present `ip` to the user!

That's it.

## Licence

These are under 0BSD, by submitting a PR you're agreeing to this, unless you
change the `SPDX-License-Identifier` in your submission.
