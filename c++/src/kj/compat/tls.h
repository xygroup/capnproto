// Copyright (c) 2016 Sandstorm Development Group, Inc. and contributors
// Licensed under the MIT License:
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
// THE SOFTWARE.

#ifndef KJ_COMPAT_TLS_H_
#define KJ_COMPAT_TLS_H_
// This file implements TLS (aka SSL) encrypted networking. It is actually a wrapper, currently
// around OpenSSL / BoringSSL / LibreSSL, but the interface is intended to remain
// implementation-agnostic.
//
// Unlike OpenSSL's API, the API defined in this file is intended to be hard to use wrong.

#include <kj/async-io.h>

namespace kj {

class TlsPrivateKey {
public:
  TlsPrivateKey(kj::ArrayPtr<const byte> asn1);
  TlsPrivateKey(kj::StringPtr pem);
  ~TlsPrivateKey() noexcept(false);

  TlsPrivateKey(const TlsPrivateKey& other);
  TlsPrivateKey& operator=(const TlsPrivateKey& other);
  // Copy-by-refcount.

  inline TlsPrivateKey(TlsPrivateKey&& other): pkey(other.pkey) { other.pkey = nullptr; }
  inline TlsPrivateKey& operator=(TlsPrivateKey&& other) {
    pkey = other.pkey; other.pkey = nullptr;
    return *this;
  }

private:
  void* pkey;  // actually type EVP_PKEY*

  friend class TlsContext;
};

class TlsCertChain {
  // A TLS certificate, possibly with chained intermediate certificates.
  //
  // TODO(now): rename to TlsCertificate?

public:
  TlsCertChain(kj::ArrayPtr<const kj::ArrayPtr<const byte>> asn1);
  TlsCertChain(kj::ArrayPtr<const byte> asn1);  // no chain; just one cert
  TlsCertChain(kj::StringPtr pem);
  ~TlsCertChain() noexcept(false);

  TlsCertChain(const TlsCertChain& other);
  TlsCertChain& operator=(const TlsCertChain& other);
  // Copy-by-refcount.

  inline TlsCertChain(TlsCertChain&& other) {
    memcpy(chain, other.chain, sizeof(chain));
    memset(other.chain, 0, sizeof(chain));
  }
  inline TlsCertChain& operator=(TlsCertChain&& other) {
    memcpy(chain, other.chain, sizeof(chain));
    memset(other.chain, 0, sizeof(chain));
    return *this;
  }

private:
  void* chain[10];
  // Actually type X509*[10].
  //
  // Note that OpenSSL has a default maximum cert chain length of 10. Although configurable at
  // runtime, you'd actually have to convince the _peer_ to reconfigure, which is unlikely except
  // in specific use cases. So to avoid excess allocations we just assume a max of 10 certs.
  //
  // If this proves to be a problem, we should maybe use STACK_OF(X509) here, but stacks are not
  // refcounted -- the X509_chain_up_ref() function actually allocates a new stack and uprefs all
  // the certs.

  friend class TlsContext;
};

struct TlsKeypair {
  // A pair of a private key and a certificate, for use by a server.

  TlsPrivateKey privateKey;
  TlsCertChain certificate;
};

class TlsSniCallback {
  // Callback object to implement Server Name Indication, in which the server is able to decide
  // what key and certificate to use based on the hostname that the client is requesting.

public:
  virtual kj::Promise<TlsKeypair> getKey(kj::StringPtr hostname) = 0;
};

enum class TlsVersion {
  SSL_3,     // DO NOT USE; cryptographically broken
  TLS_1_0,
  TLS_1_1,
  TLS_1_2
};

class TlsContext {
  // TLS system. Allocate one of these, configure it with the proper keys and certificates, and
  // then use it to wrap the standard KJ network interfaces in implementations that transparently
  // use TLS.

public:
  struct Options {
    Options();
    // Initializes all values to reasonable defaults.

    bool useSystemTrustStore;
    // Whether or not to trust the system's default trust store. Default: true.

    kj::ArrayPtr<const TlsCertChain> trustedCertificates;
    // Additional certificates which should be trusted. Default: none.

    TlsVersion minVersion;
    // Minimum version. Defaults to minimum version that hasn't been cryptographically broken.
    // If you override this, consider doing:
    //
    //     options.minVersion = kj::max(myVersion, options.minVersion);

    kj::StringPtr cipherList;
    // OpenSSL cipher list string. The default is a curated list designed to be compatible with
    // almost all software in curent use (specifically, based on Mozilla's "intermediate"
    // recommendations). The defaults will change in future versions of this library to account
    // for the latest cryptanalysis.
    //
    // Generally you should only specify your own `cipherList` if:
    // - You have extreme backwards-compatibility needs and wish to enable obsolete and/or broken
    //   algorithms.
    // - You need quickly to disable an algorithm recently discovered to be broken.

    kj::Maybe<const TlsKeypair&> defaultKeypair;
    // Default keypair to use for all connections. Required for servers; optional for clients.

    kj::Maybe<TlsSniCallback&> sniCallback;
    // Callback that can be used to choose a different key/certificate based on the specific
    // hostname requested by the client.
  };

  TlsContext(Options options = Options());
  ~TlsContext() noexcept(false);
  KJ_DISALLOW_COPY(TlsContext);

  kj::Promise<kj::Own<kj::AsyncIoStream>> wrapClient(
      kj::Own<kj::AsyncIoStream> stream, kj::StringPtr expectedServerHostname);
  kj::Promise<kj::Own<kj::AsyncIoStream>> wrapServer(kj::Own<kj::AsyncIoStream> stream);
  // Upgrade a regular network stream to SSL. You must specify whether this is the client or server
  // end of the stream.

  kj::Own<kj::ConnectionReceiver> wrapPort(kj::Own<kj::ConnectionReceiver> port);
  // Wrap the given port, producing one that returns TLS connections.

  kj::Own<kj::Network> wrapNetwork(kj::Network& network);
  // Wrap the given network, producing one that always forms TLS connections. The network will
  // only be able to parse addresses of the form "hostname" and "hostname:port". It will
  // automatically use SNI and verify certificates.

private:
  void* ctx;  // actually type SSL_CTX
};

} // namespace kj

#endif // KJ_COMPAT_TLS_H_
