# MYProxy

Intends to let me see the requests any applications are making in my computer.  
It acts as a local proxy server that intercepts and logs HTTP/HTTPS requests and it's contents.

---

## How to use
You'll need to trust the certificates generated once you first run it.  
(Build it or w/ `go run` idk).


After trusting the certificates, you'll need to set your system to use `localhost:8888` as proxy.
You'll prolly need to set some firewall rules as well.

Once everything is set, just run the application.

You can see the requests and its contents on **http://127.0.0.1:8081** :)

There are some bugs on the body content visualization. If you want to fix it, ok.
Also, some headers are being hidden for "safety". Include or exclude as you want.

You can also add uls to bypass MITM, just push then to this:

```golang
var mitmBypass = map[string]struct{}{}
```

Why? Because why would you trust any comercial tools?
