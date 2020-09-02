你好！
很冒昧用这样的方式来和你沟通，如有打扰请忽略我的提交哈。我是光年实验室（gnlab.com）的HR，在招Golang开发工程师，我们是一个技术型团队，技术氛围非常好。全职和兼职都可以，不过最好是全职，工作地点杭州。
我们公司是做流量增长的，Golang负责开发SAAS平台的应用，我们做的很多应用是全新的，工作非常有挑战也很有意思，是国内很多大厂的顾问。
如果有兴趣的话加我微信：13515810775  ，也可以访问 https://gnlab.com/，联系客服转发给HR。
# json-sig

This is a [Go](http://golang.org) language package that implements cryptographic signatures of JSON documents, using the algorithm described [here](https://github.com/couchbase/couchbase-lite-ios/wiki/Signed-Documents).

Signing a document provides these benefits:
* Any unauthorized modification of the document can be detected, as it'll invalidate the signature.
* The enclosed public key can be used as an identifier of the entity that signed the document.

Thus a signature serves as a form of authentication. Why do we need this when servers like the Sync Gateway and CouchDB already supports several types of authentication?
* The signature authenticates a _document_, not a _connection_. This is a very important distinction when documents are replicated, especially when they can pass between multiple servers. A document may be forwarded by an entity that didn't create it, so the fact that the replicator connection is authenticated does _not_ authenticate the document. The document has to carry its own credentials.
* Public keys allow for many types of identity and authentication. In the simplest case, an entity can create a key-pair and use the public key as its sole identification; this is useful even though it doesn't tie that entity to any external form of ID. More complex systems can use a hierarchical public-key infrastructure like X.509 or a "web of trust" like PGP.

Unlike some other JSON-signature systems, the object being signed doesn't need to be specially encoded. This is important because it doesn't get in the way of systems (like Couchbase Lite or CouchDB) that read the object.

Another advantage is that the signature doesn't need to be contained in the signed object (or vice versa.) It is common for the signature to be contained -- and there's a special `(signed)` property defined for it -- but there are situations where this isn't practical. For example, some storage systems may require metadata such as a signature to be stored externally. In this case it's up to the application to have a way to find the signature of an object.

## Example

Here's a signature by itself:

```json
{
    "digest": ["SHA", "CVVhu8Ux+kv7dZHV+9gV7q5tWVA="],
    "key": [
        "RSA",
        "MIIBCgKCAQEAyjt5YE/R0f8fkQS95RjV0KqogjtNIIMiv7EuxYZLXL0AxXHKH13VmUTUis9PjtlsW3CoBNldPUyj5Xmujn39AlIhTioUXtBOrySrfAiaqfo28ytavY2q2X75YzQwLbTt1mRaP4Vl/NyYFf1sx7EfBoC807VcXbSbajxf7T5E9o/zwBgTME6nvXy1OPT+LkOHPmoat9RM37rOhBhA1hLHG2zxeQum31Ck0TrKJrefgmITQQ/SQsX5d8b9vXwvYrc7enGU0EfxBL4Ni62+mPYuFkh6uYrvoTNZ0wqSnhljF8C8JsxwQZ7zUWvRFhpsR1Xk71XYGcis/ZxiWXOQ+7LvAQIDAQAB"
    ],
    "sig": "nBMh3nrOPwsQIrduAhHSaXIwtHQ74xFz0S4YN2IrSPhxUtTomuRSwO0vHHjHHZFKyReYJUikmVrJ7gkObdO325E07bRYfRG2phao1R1D/Jmj0rBEhAXaDbkfSd99URJjzsjxCagwRXU2JjrjNsih53dUJXKwYcyPpjgwhBy7Nzs8PjJCr4szA//ckLtSBI8G5pjY8eTrPR2udLIflwUgji51sxRvT6+GRFjqWH9JeLPoyvK6J1E3+xsCj397dUAcodCgomotnjghC/VywK/O7wDjgA9aj8/OyMhTyf3MPGjF05zQj2ggjo76Yuqz9Z7aHp5A9eJeARNKqTy2646gWQ=="
}
```
