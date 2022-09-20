---
description: >-
  Nowadays, novel HTTP request smuggling techniques rely on subtle deviations
  from the HTTP standard. Here, I discuss some of my recent findings and novel
  techniques.
---

# HTTP Request Smuggling in the Multiverse of Parsing Flaws

Some time earlier this year, I conducted a bit of independent research on HTTP request smuggling and found a couple of vulnerabilities.&#x20;

This article expands on my talk on the topic at [BSides Singapore ](https://bsidessg.org/)2022.

## What is HTTP Request Smuggling?

To understand HTTP request smuggling, we have to first take a trip down memory lane.

The HTTP protocol has undergone several changes since its inception, and the latest protocol version is HTTP/3. While HTTP/2 is the most popular version today, HTTP/1.x still comprises a significant amount of web traffic and is crucially important in understanding HTTP request smuggling.

<figure><img src="../.gitbook/assets/image (2).png" alt=""><figcaption></figcaption></figure>

The major difference between HTTP/1.x and HTTP/2 is the fact that HTTP/2 evolved from a purely text-based protocol to a binary protocol. In HTTP/1.x, the `Content-Length` and `Transfer-Encoding` headers determined the length of an HTTP request. It is this reliance on two special headers that enabled the earliest discoveries of HTTP request smuggling.

<figure><img src="../.gitbook/assets/HTTP Request Smuggling - BSidesSG2022-06.jpg" alt=""><figcaption></figcaption></figure>

But this alone is not enough. In HTTP/1.0, one TCP connection is used for each HTTP request - any two HTTP requests cannot interfere with each other. With HTTP/1.1 came along, the concept of persistent connections was introduced. This introduced an entirely new vector of attack - if one request earlier in the TCP stream could interfere with another downstream request, a variety of vulnerabilities could occur.

<figure><img src="../.gitbook/assets/HTTP Request Smuggling - BSidesSG2022-07.jpg" alt=""><figcaption></figcaption></figure>

This becomes particularly relevant when considering architectures comprising a frontend proxy (such as Nginx, Apache HTTP Server and HAProxy) with backend web servers. Consider the following example.

<figure><img src="../.gitbook/assets/HTTP Request Smuggling - BSidesSG2022-10.jpg" alt=""><figcaption></figcaption></figure>

The frontend proxy parses the `Content-Length` header, forwarding the `GET /internal` request as part of the 53-byte request body.

The backend web server, on the other hand, parses the `Transfer-Encoding: chunked` header and interprets the first request to end at the `0` chunk size. This meant that from the perspective of the backend server, there are two requests - one to `/` and one to `/internal`.

Note that in this case, the backend is spec-compliant and the frontend proxy is not. According to [RFC7230 section 3.3.3](https://datatracker.ietf.org/doc/html/rfc7230#section-3.3.3), the `Transfer-Encoding` header overrides the `Content-Length`.

> If a message is received with both a Transfer-Encoding and a Content-Length header field, the Transfer-Encoding overrides the Content-Length. Such a message might indicate an attempt to perform request smuggling (Section 9.5) or response splitting (Section 9.4) and ought to be handled as an error. A sender MUST remove the received Content-Length field prior to forwarding such a message downstream.

## Enter the Multiverse

This section would be split into different groups of parsing flaws. Because I often compile multiple issues into a single report, the resulting CVEs comprise of multiple issues. It is more meaningful to discuss the various types of issues rather than each CVE individually.

### Some Observations

When I was looking into various web servers and proxies, I noticed some things that I would like to point out.

First, it seems like lots of research has been done on web proxy technologies, but not a lot has been done on backend servers. This is also reflected in the relative security of projects like Nginx and HAProxy against request smuggling. It is important to note that in most cases, a request smuggling attack reveals a two-pronged issue that requires both the frontend proxy and the backend server to be somewhat non-compliant.

This sometimes makes it difficult to demonstrate impact when disclosing vulnerabilities, as the impact often has to be qualified with a precondition that some other server in the stack is also non-compliant. It is important for maintainers not to dismiss request smuggling vectors as low impact or insignificant just because of this.

Second, most "traditional" request smuggling techniques have been patched. These are techniques that have been popularly taught and demonstrated, for example:

* Duplicate `Content-Length` headers (CL.CL)
* Frontend server uses `Content-Length`, backend uses `Transfer-Encoding` (CL.TE)
* Frontend server uses `Transfer-Encoding`, backend uses `Content-Length` (TE.CL)

The next part of this article will discuss _subtle_ deviations from the HTTP standard that can lead to request smuggling. These are vectors that may seem trivial but are often neglected.

Last, when implementing [RFC7230](https://datatracker.ietf.org/doc/html/rfc7230#section-4.1.1), often the `SHOULD` clauses are equally important in preventing HTTP request smuggling. Sometimes differences in interpreting such clauses can lead to disagreements between servers.

### Number Parsing Flaws

According to the RFC, the `Content-Length` value comprises of any number of `DIGIT`s.

{% code overflow="wrap" %}
```
Content-Length = 1*DIGIT
...
Any Content-Length field value greater than or equal to zero is valid.
```
{% endcode %}

A `DIGIT` in the ABNF standard consists of strictly 0-9 only. However, due to number parsing implementations, many parsers will accept non-conformant values like `+23`.

Consider the following requests.

{% code overflow="wrap" %}
```http
GET / HTTP/1.1
Content-Length: +23

GET / HTTP/1.1
Dummy: GET /forbidden HTTP/1.1
```
{% endcode %}

In a previous version of [Apache Traffic Server](https://trafficserver.apache.org/), the `+23` content length is silently ignored, and the first request is interpreted as having zero content length.

Many web servers, however, will interpret `+23` as a valid content length. This means that the requests will now be interpreted very differently. The first request has a 23-byte body, ending at the `Dummy` header.

```http
GET / HTTP/1.1
Content-Length: +23

GET / HTTP/1.1
Dummy: 
```

The second request will now instead be routed to `/forbidden`.

```http
GET /forbidden HTTP/1.1
```

This starts to get more interesting when negative numbers are involved. For example, the following was the behaviour of [Twisted Web](https://github.com/twisted/twisted) when encountering negative content lengths.

<figure><img src="../.gitbook/assets/HTTP Request Smuggling - BSidesSG2022-17.jpg" alt=""><figcaption></figcaption></figure>

Chunk sizes also present a similar issue - servers should not accept the `0x` prefix. Because of differences in parsing hexadecimal numbers, this simple request can be interpreted differently.

```http
GET / HTTP/1.1
Transfer-Encoding: chunked

0x12
GET / HTTP/1.1

0
```

Some parsers will simply parse the number up to the first non-hex digit. This leads to the early termination of the request and consequently the smuggling of a second request.

```http
GET / HTTP/1.1
Transfer-Encoding: chunked

0
GET / HTTP/1.1

0
```

We can see how language-specific behaviour plays a part in these scenarios. In fact, the behaviour of the Python-based servers was in line with how `int()` handles integer strings, and Puma's behaviour was in line with Ruby's `to_i` (which parses integer strings up to the first non-decimal character).

#### Summary

| CVE ID         | Server (Language) | Behavior                                                             |
| -------------- | ----------------- | -------------------------------------------------------------------- |
| CVE-2022-24761 | Waitress (Python) | Accept ‘signed’ (±) and 0x-prefixed `Content-Length` and chunk sizes |
| CVE-2022-24801 | Twisted (Python)  | Accept ‘signed’ (±) and 0x-prefixed `Content-Length` and chunk sizes |
| CVE-2022-24790 | Puma (Ruby)       | <p>abc → 0</p><p>99 balloons → 99</p>                                |

### Whitespace is More Than 0x20

Headers allow for optional whitespace (`OWS`) before and after the field values.&#x20;

{% code overflow="wrap" %}
```
OWS = *( SP / HTAB )
header-field   = field-name ":" OWS field-value OWS
```
{% endcode %}

Importantly, only two whitespace characters are considered valid here - space and horizontal tab. But this definition of whitespace is often incompatible with that of generic stripping functions in most programming languages.

Consider the following request. If a proxy were to interpret the transfer coding as `\rchunked`, this may be interpreted as an invalid encoding and ignored.

<figure><img src="../.gitbook/assets/HTTP Request Smuggling - BSidesSG2022-23.jpg" alt=""><figcaption></figcaption></figure>

The second request would then contain a 23-byte body including `GET /admin`.

But a server that incorrectly strips the `\r` character from the `Transfer-Encoding` header would not see it the same way.

<figure><img src="../.gitbook/assets/HTTP Request Smuggling - BSidesSG2022-24.jpg" alt=""><figcaption></figcaption></figure>

A much more classic technique involves whitespace between the header names and colon. By stripping the header names of whitespace, headers like `Content-Length : 5` were allowed in [mitmproxy](https://mitmproxy.org/). This particular case is clearly addressed in the RFC.

{% code overflow="wrap" %}
```
No whitespace is allowed between the header field-name and colon.  In the past, differences in the handling of such whitespace have led to security vulnerabilities in request routing and response handling.  A server MUST reject any received request message that contains whitespace between a header field-name and colon with a response code of 400 (Bad Request).  A proxy MUST remove any such whitespace from a response message before forwarding the message downstream.
```
{% endcode %}

#### Summary

| CVE ID         | Server (Language)     | Behavior                                |
| -------------- | --------------------- | --------------------------------------- |
| CVE-2022-28129 | Apache Traffic Server | `Content-Length[\x0b]: 0` accepted      |
| CVE-2022-24766 | mitmproxy (Python)    | `Content-Length[SP]: X` accepted        |
| CVE-2022-1705  | net/http (Golang)     | `Transfer-Encoding: \rchunked` accepted |

### Transfer-Encoding - You Had One Job

A quick primer on the `Transfer-Encoding` header - encodings are stated from first to last, so `gzip, chunked` would mean that the decoding server needs to decode the `chunked` body as `gzip` data.

According to RFC 7230, `chunked` must be the final value in the `Transfer-Encoding` header.

{% code overflow="wrap" %}
```
If a Transfer-Encoding header field is present in a request and the chunked transfer coding is not the final encoding, the message body length cannot be determined reliably; the server MUST respond with the 400 (Bad Request) status code and then close the connection.
```
{% endcode %}

But the deprecated [RFC 2616](https://www.rfc-editor.org/rfc/rfc2616) actually allows the `identity` encoding, which means "the use of no transformation whatsoever". In fact, in this RFC, the `chunked` transfer-coding is only used when the `Transfer-Encoding` value is not `identity`.

{% code overflow="wrap" %}
```
If a Transfer-Encoding header field (section 14.41) is present and has any value other than "identity", then the transfer-length is defined by use of the "chunked" transfer-coding (section 3.6), unless the message is terminated by closing the connection.
```
{% endcode %}

[Puma](https://github.com/puma/puma), in particular, assumed the opposite - as long as _any_ of the `Transfer-Encoding` values is `chunked`, the message is parsed with chunked encoding. This means that the following request is considered `chunked`, although the final transformation is `identity`.

```http
GET / HTTP/1.1
Host: example.com
Transfer-Encoding: chunked, identity
```

Up till recently, many major proxies still supported the `identity` transfer-coding. This meant that any of these proxies used in combination with Puma would have allowed for request smuggling through the above request.

It is also important to reject any invalid `Transfer-Encoding` value. Servers often accept invalid values due to parsing flaws, and silently ignoring these malformed transfer-codings opens the door to request smuggling. When no supported `Transfer-Encoding` values are found, Puma would silently ignore the header altogether.

<figure><img src="../.gitbook/assets/HTTP Request Smuggling - BSidesSG2022-29.jpg" alt=""><figcaption></figcaption></figure>

This is a good example of how research on web servers is equally important to that on web proxies. While the argument could be made that the fault lies with Apache Traffic Server for accepting the malformed `"chunked"` value, the attack would not have been possible if Puma threw a `400 Bad Request`  when encountering it.

<figure><img src="../.gitbook/assets/HTTP Request Smuggling - BSidesSG2022-30.jpg" alt=""><figcaption></figcaption></figure>

Because of the variability of the `Transfer-Encoding` header, the parsing behaviour of various servers when it comes to this header is quite interesting. In particular, I noted an interesting behaviour in the Node.js `http` module.

<figure><img src="../.gitbook/assets/image (1).png" alt=""><figcaption></figcaption></figure>

In the original code, when `chunked` is matched, a check is made to see if `chunked` is the final encoding. If a CRLF sequence is encountered, `chunked` is taken to be the final encoding, and the request body will be parsed as chunked. Otherwise, it attempts to match `chunked` again.

But this logic forgets to look for a `,` seperator if the CRLF sequence is not found, meaning that the following is a valid chunked request.

```http
GET / HTTP/1.1
Host: example.com
Transfer-Encoding: chunkedchunked

...
```

#### Summary

| CVE ID         | Server (Language) | Behavior                                                                                                       |
| -------------- | ----------------- | -------------------------------------------------------------------------------------------------------------- |
| CVE-2022-24766 | Puma (Ruby)       | <ul><li>Does not check that chunked is the final encoding</li><li>Silently ignores invalid encodings</li></ul> |
| CVE-2022-1705  | http (Node.js)    | Accepts malformed encodings, e.g. `chunkedchunked`                                                             |

### obs-fold - Not So Obsolete

Historically, multi-line headers were allowed by starting each extra line with either a space or horizontal tab. RFC 7230 deprecates such line-folding (`obs-fold`).

{% code overflow="wrap" %}
```
field-value    = *( field-content / obs-fold )
obs-fold       = CRLF 1*( SP / HTAB )
```
{% endcode %}

For backwards compatibility, `obs-fold` is supported by most servers. This is spec-compliant.

{% code overflow="wrap" %}
```
A server that receives an obs-fold in a request message that is not within a message/http container MUST either reject the message by sending a 400 (Bad Request), preferably with a representation explaining that obsolete line folding is unacceptable, or replace each received obs-fold with one or more SP octets prior to interpreting the field value or forwarding the message downstream.
```
{% endcode %}

The trouble begins when implementing the rest of the spec while supporting `obs-fold`. As we saw above, one assumption made by the Node.js parser was that the `Transfer-Encoding` header would end when encountering the CRLF sequence - `chunked` followed by CRLF would mean that the transfer-coding is `chunked`.

This makes sense until we consider that the parser also supports `obs-fold`, so the following multi-line header would be interpreted wrongly.

```http
GET / HTTP/1.1
Host: example.com
Transfer-Encoding: chunked
[SP], identity
```

Instead of parsing the transfer-coding as `identity`, `chunked` is used instead.

#### Summary

| CVE ID         | Server (Language) | Behavior                                                     |
| -------------- | ----------------- | ------------------------------------------------------------ |
| CVE-2022-32215 | http (Node.js)    | Early termination of multi-line `Transfer-Encoding` headers. |

### Bonus: LF vs. CRLF

This discussion was not included in my talk because this is a slightly more contested topic and it is sometimes ambiguous whether this is a legitimate issue.

```http
GET / HTTP/1.1
Dummy: x[\n]Content-Length: 23

GET / HTTP/1.1
Dummy: GET /forbidden HTTP/1.1
```

Note that each line above is delimited by the CRLF sequence.

If a proxy strictly delimits each line by CRLF and incorrectly allows the `\n` character as a valid character in header values, a backend that delimits each line by only a bare LF will interpret the requests as

```http
GET / HTTP/1.1
Dummy: x
Content-Length: 23

GET / HTTP/1.1
Dummy: GET /forbidden HTTP/1.1
```

While this seems dangerous, the spec actually allows for a single LF to be used to delimit lines, albeit in a `MAY` clause.

{% code overflow="wrap" %}
```
Although the line terminator for the start-line and header fields is the sequence CRLF, a recipient MAY recognize a single LF as a line terminator and ignore any preceding CR.
```
{% endcode %}

Some servers like Waitress and Node.js have taken this potential vector into consideration and switched to the most-spec-compliant method of delimiting lines with the CRLF sequence.

### Bonus: Other Findings

There are some individual findings that didn't fit into any of the above groups but are interesting to discuss nonetheless. This discussion was not included in my talk for brevity.

#### Puma - Duplicate Content-Length Headers (CL.CL)

This one is a relatively common technique. Puma allowed multiple `Content-Length` headers.

```http
Content-Length: 0
Content-Length: 5
```

Note that internally, this will result in a final `Content-Length` value of `0, 5`, but Ruby's `to_i` function will stop parsing at the first non-decimal character, and therefore the first `Content-Length` header is used to determine the request length. This is non-compliant.

{% code overflow="wrap" %}
```
If a message is received without Transfer-Encoding and with either multiple Content-Length header fields having differing field-values or a single Content-Length header field having an invalid value, then the message framing is invalid and the recipient MUST treat it as an unrecoverable error.  If this is a request message, the server MUST respond with a 400 (Bad Request) status code and then close the connection.
```
{% endcode %}

If an upstream proxy processes the second `Content-Length` header instead, request smuggling attacks can occur.

#### Node.js - Whitespace  Before First Header

This one is quite interesting. According to the RFC, whitespace between the start-line and the first header field is not allowed. It even explicitly mentions the associated security risks.

{% code overflow="wrap" %}
```
A sender MUST NOT send whitespace between the start-line and the first header field.  A recipient that receives whitespace between the start-line and the first header field MUST either reject the message as invalid or consume each whitespace-preceded line without further processing of it (i.e., ignore the entire line, along with any subsequent lines preceded by whitespace, until a properly formed header field is received or the header section is terminated).

The presence of such whitespace in a request might be an attempt to trick a server into ignoring that field or processing the line after it as a new request, either of which might result in a security vulnerability if other implementations within the request chain interpret the same message differently.  Likewise, the presence of such whitespace in a response might be ignored by some clients or cause others to cease parsing.
```
{% endcode %}

Node.js allowed whitespace in this location, leading to some potentially interesting vectors. In the following request, the content length header name is taken to be the literal string `" Content-Length"` and different from the normal `"Content-Length"` header. It is therefore not indicative of the request body.

```http
GET / HTTP/1.1
[SP]Content-Length: 23
Foo: Bar

GET / HTTP/1.1
Dummy: GET /forbidden HTTP/1.1
```

If a frontend proxy parses the malformed `Content-Length` header, smuggling attacks can occur. However, I have yet to find a proxy that exhibits such behaviour - most will correctly reject the request as per the RFC.

Since there was limited demonstrable impact, this was handled by the Node.js team as a [public issue](https://github.com/nodejs/llhttp/issues/152).

## 14 Million Futures

### HTTP/2 Request Smuggling

Previously we discussed how HTTP/2 uses a binary protocol, instead of the text-based one that HTTP/1.x used. Each HTTP/2 data frame now had an associated length field built into the protocol, ensuring that there is no ambiguity in HTTP/2 request body lengths.&#x20;

<figure><img src="../.gitbook/assets/image (3).png" alt=""><figcaption></figcaption></figure>

While this sounds good on paper, taking a closer look at the type of architecture required for request smuggling attacks reveals that many of our old techniques are still relevant here.&#x20;

Even if HTTP/2 is used between the client and frontend proxy, there is no real reason to use HTTP/2 between the proxy and its backend servers. This means that HTTP/2 requests are often _rewritten_ to HTTP/1.x before being forwarded to HTTP/1.x backend servers.

<figure><img src="../.gitbook/assets/HTTP Request Smuggling - BSidesSG2022-39.jpg" alt=""><figcaption></figcaption></figure>

One interesting consequence of this was that since the CRLF sequence was no longer used to delimit request lines in HTTP/2, we could potentially perform CRLF injection on the downgraded HTTP/1.1 request by simply supplying these characters in a HTTP/2 header.

I came across one interesting application of this in [Apache Traffic Server](https://trafficserver.apache.org/). By injecting the CRLF sequence in the HTTP/2 headers frame, we could inject new headers into the rewritten HTTP/1.1 request. More broadly, we could also modify everything below the injection point, including the request body.

<figure><img src="../.gitbook/assets/HTTP Request Smuggling - BSidesSG2022-42.jpg" alt=""><figcaption></figcaption></figure>

While header injection can be sufficient to cause smuggling attacks, I noticed an interesting aspect of this particular vulnerability. Any headers added _below_ our injection point could be forced into the request body by injecting the double-CRLF sequence.

Consider a request that stores the request body that can be later recovered. Sensitive headers being pushed into the request body might lead to information leakage, depending on the application logic.

<figure><img src="../.gitbook/assets/HTTP Request Smuggling - BSidesSG2022-43.jpg" alt=""><figcaption></figcaption></figure>

#### Summary

| CVE ID         | Server (Language)     | Behavior                                                |
| -------------- | --------------------- | ------------------------------------------------------- |
| CVE-2022-25763 | Apache Traffic Server | CRLF injection when downgrading from HTTP/2 to HTTP/1.1 |

### Client-Side Attacks

Just as I'm writing this, new research has been released on [client-side desync attacks](https://portswigger.net/web-security/request-smuggling/browser/client-side-desync). I found this new development particularly interesting because it forces a paradigm shift on how we approach smuggling attacks. Client-side desync does not require a proxy-server architecture, only a browser and a single web server.

It would be interesting to see how the community will build on this research to find new and interesting discoveries.
