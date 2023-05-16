---
description: Stumbling upon an XSS paradise.
cover: >-
  https://images.unsplash.com/photo-1481627834876-b7833e8f5570?crop=entropy&cs=tinysrgb&fm=jpg&ixid=MnwxOTcwMjR8MHwxfHNlYXJjaHwxfHxsaWJyYXJ5fGVufDB8fHx8MTY3NDY3MTAyNw&ixlib=rb-4.0.3&q=80
coverY: 0
---

# ReadiumJS Cloud Reader — Everybody Gets an XSS!

## Introduction

Late last year, I participated in a bug bounty programme organized by Singapore's [Ministry of Defence (MINDEF)](https://www.mindef.gov.sg/) where I received the [Top Bug Bounty Hunter award](https://www.linkedin.com/feed/update/urn:li:activity:6993394788045606914/) (yay!).

Finding these bugs required a deep dive into the targets and their underlying technologies. This meant that, among other things, I learnt about the existence of the [EPUB format](https://www.w3.org/AudioVideo/ebook/) and the world of EPUB cloud readers.

This led me to discover a (surprisingly, somewhat known) XSS vulnerability in the [Readium](https://github.com/readium) cloud reader that affects many university websites and online libraries.

<figure><img src="../.gitbook/assets/78utju.jpeg" alt=""><figcaption></figcaption></figure>

I have attempted to get in touch with the maintainers to remediate the issue, but have not yet received any response. Going by the conventional 90-day disclosure timeline, I am now sharing details on this vulnerability.

## What is an EPUB? What is a Readium?

The EPUB format is an XML-based ebook format created by the [International Digital Publishing Forum (IDPF)](https://idpf.org/). It is one of the major ebook formats around today. Unlike other proprietary formats such as Amazon's Kindle KF8, the EPUB format is vendor-independent.

The [Readium](https://readium.org/) project was started by IDPF, and is one of the cited EPUB readers on the [W3 website](https://www.w3.org/AudioVideo/ebook/).

<figure><img src="../.gitbook/assets/Screenshot 2023-01-26 at 10.31.10 PM.png" alt=""><figcaption></figcaption></figure>

To see it in action, we can visit the Readium cloud reader [demo](https://readium.firebaseapp.com/). We can quickly see that the cloud reader renders `iframe`s containing pages of the ebook.

<figure><img src="../.gitbook/assets/Screenshot 2023-01-26 at 11.00.24 PM.png" alt=""><figcaption></figcaption></figure>

Each page is fetched from the location indicated in `data-src` and converted into the final rendered HTML. The pages are XHTML files and are called EPUB [content documents](https://www.w3.org/publishing/epub3/epub-contentdocs.html). For example, page 1 of La Page Blanche contains the following content.

```markup
<?xml version="1.0" encoding="UTF-8"?>
<html xmlns="http://www.w3.org/1999/xhtml" xmlns:epub="http://www.idpf.org/2007/ops">
    <head>
        <meta charset="utf-8" />
        <meta name="viewport" content="width=1200, height=1577" />
        <title>La Page Blanche</title>
        <link href="../Style/style.css" type="text/css" rel="stylesheet" />
    </head>
    <body>
        <div class="page" epub:type="frontmatter titlepage"><img
                src="../Image/PageBlanche_Page_001.jpg" alt="page 1" /></div>
    </body>
</html>
```

## Popping Alerts

First of all, we could see that the `iframe` does not have the `sandbox` attribute present. This means that any scripts firing within the `iframe` would execute on the same origin as its `src`.

Readium will create a `Blob` containing the page data and create a new `blob:` URL for it ([source](https://github.com/readium/readium-js/blob/999d7c32bcdd1184bcc248312267c6e744d737b9/js/epub-fetch/iframe\_zip\_loader.js#L117-L125)). This is the URL that the frame `src` is set to ([source](https://github.com/readium/readium-js/blob/999d7c32bcdd1184bcc248312267c6e744d737b9/js/epub-fetch/iframe\_zip\_loader.js#L280-L281)).

```javascript
// prefer BlobBuilder as some browser supports Blob constructor but fails using it
if (window.BlobBuilder) {
    var builder = new BlobBuilder();
    builder.append(contentDocumentData);
    blob = builder.getBlob(contentType);
} else {
    blob = new Blob([contentDocumentData], {'type': contentType});
}
documentDataUri = window.URL.createObjectURL(blob);

...

if (isBlobHandled) {
    iframe.setAttribute("src", documentDataUri);
```

Unfortunately, this means that the `iframe`'s origin will always be that of the parent page.

<figure><img src="../.gitbook/assets/Screenshot 2023-01-26 at 11.43.55 PM.png" alt=""><figcaption></figcaption></figure>

### Stored XSS

Suppose we are able to upload an ebook to an online library using Readium. We might upload a malicious EPUB that runs some evil JavaScript. Any user that opens our ebook would then have their account compromised.

To create such an EPUB, I copied an example EPUB from the Readium demo and changed the home page. An example PoC can be found [here](https://github.com/zeyu2001/readium-xss).

Note that we are using `x:script` to make the payload work with XHTML parsers.

```markup
<!DOCTYPE html>

<html>
    <body>
        Hello world!
    </body>
    <x:script xmlns:x="http://www.w3.org/1999/xhtml">alert(document.domain)</x:script>
</html>
```

### Reflected XSS

The above scenario requires us to have privileges on the target site to upload arbitrary EPUBs and serve them to other users. It turns out, however, that the cloud reader is able to load remote EPUBs as well.

The cloud reader uses [medialize/URI.js](https://github.com/medialize/URI.js) to normalize the `epub` query parameter, which is a relative URL ([source](https://github.com/readium/readium-js/blob/master/js/Readium.js#L171-L181)).

```javascript
ebookURL = new URI(ebookURL).absoluteTo(thisRootUrl).toString();
```

However, when `ebookURL` is an absolute URL, `absoluteTo` retains the original base URL.

<figure><img src="../.gitbook/assets/Screenshot 2023-01-27 at 12.05.21 AM.png" alt=""><figcaption></figcaption></figure>

This means that by simply passing our hosted exploit URL to the `epub` query parameter, we have a reflected XSS! This does not require us to have any permissions on the target site.

Using the example PoC on the Readium demo should pop an alert:

`https://readium.firebaseapp.com/?epub=https://zeyu2001.github.io/readium-xss/`

<figure><img src="../.gitbook/assets/Screenshot 2023-01-27 at 12.12.53 AM.png" alt=""><figcaption></figcaption></figure>

## Who Uses Readium?

The Readium cloud reader is a rather old project. While more recent and popular cloud readers have been developed, some sites still use the Readium cloud reader, including the IDPF's own website and several university sites.

I have made best effort attempts at identifying these sites (e.g. through Google dorking) and reaching out to the responsible teams to remediate this vulnerability before the release of this post.

The sites that have since remediated the vulnerability include the [University of Minnesota's College of Education and Human Development website](https://www.cehd.umn.edu/), which no longer contains the cloud reader page.

<figure><img src="../.gitbook/assets/Screenshot 2023-01-27 at 12.18.10 AM.png" alt=""><figcaption></figcaption></figure>

## Known Issue?

Interestingly, after doing some digging, I found that this was somewhat of a known issue. [This](https://readium.org/architecture/server/origin.html#serving-contents-in-the-web-context) documentation explains the issue.

> One should note that if a cloud reader aims to support JavaScript, all publications will at least share the same database, which means it is possible for an author to access data that originated in a different publication.

However, it leaves only the following suggestions to mitigate the vulnerability.

> Currently, the only options to protect against attacks (see "Security Concerns" section) are:
>
> * `iframe` sandboxing;
> * the Content Security Policy;
> * the Feature Policy.

These suggestions are _not_ implemented in the default installation of [readium-js-viewer](https://github.com/readium/readium-js-viewer).

## Remediation

Since this is quite an old project, the best remediation might be to move to a more modern cloud reader. If Readium needs to be used, the `iframe`s on the page should have the `sandbox` attribute set.

Additionally, the page's Content Security Policy can be used to restrict where scripts can be loaded from.

## Disclosure Timeline

* 11 October 2022: Contacted maintainers through OSS platform [huntr.dev](https://huntr.dev/)
* 16 December 2022: Contacted maintainers through GitHub issue
* 27 January 2022: This blog post is released
* 12 April 2023: CVE-2023-24720 assigned
