pysrp
=====
Tom Cocagne &lt;tom.cocagne@gmail.com&gt;

pysrp provides a Python implementation of the [Secure Remote Password
protocol](http://srp.stanford.edu/) (SRP).


SRP Overview
------------

SRP is a cryptographically strong authentication
protocol for password-based, mutual authentication over an insecure
network connection.

Unlike other common challenge-response autentication protocols, such
as Kerberos and SSL, SRP does not rely on an external infrastructure
of trusted key servers or certificate management. Instead, SRP server
applications use verification keys derived from each user's password
to determine the authenticity of a network connection.

SRP provides mutual-authentication in that successful authentication
requires both sides of the connection to have knowledge of the
user's password. If the client side lacks the user's password or the
server side lacks the proper verification key, the authentication will
fail.

Unlike SSL, SRP does not directly encrypt all data flowing through
the authenticated connection. However, successful authentication does
result in a cryptographically strong shared key that can be used
for symmetric-key encryption.

For a full description of the pysrp package and the SRP protocol, please refer
to the [pysrp documentation](http://pythonhosted.org/srp/)

Note: RFC5054 now provides the de-facto standard for the hashing algorithm used
for interoperable SRP implementations. When using pysrp to interact with
another SRP implementation, use the srp.rfc5054_enable() method to enable
RFC5054 compatibility. Otherwise a pysrp-specific default implementation will
be used.


Usage Example
-------------

```python
import srp

# Consider enabling RFC5054 compatibility for interoperation with non pysrp SRP-6a implementations
#srp.rfc5054_enable()

# The salt and verifier returned from srp.create_salted_verification_key() should be
# stored on the server.
salt, vkey = srp.create_salted_verification_key( 'testuser', 'testpassword' )

class AuthenticationFailed (Exception):
    pass

# ~~~ Begin Authentication ~~~

usr      = srp.User( 'testuser', 'testpassword' )
uname, A = usr.start_authentication()

# The authentication process can fail at each step from this
# point on. To comply with the SRP protocol, the authentication
# process should be aborted on the first failure.

# Client => Server: username, A
svr      = srp.Verifier( uname, salt, vkey, A )
s,B      = svr.get_challenge()

if s is None or B is None:
    raise AuthenticationFailed()

# Server => Client: s, B
M        = usr.process_challenge( s, B )

if M is None:
    raise AuthenticationFailed()

# Client => Server: M
HAMK     = svr.verify_session( M )

if HAMK is None:
    raise AuthenticationFailed()

# Server => Client: HAMK
usr.verify_session( HAMK )

# At this point the authentication process is complete.

assert usr.authenticated()
assert svr.authenticated()
```

Custom Group Parameters (SRP-6a)
--------------------------------

SSO and other integrations that mandate specific SRP-6a group parameters
can supply their own prime modulus `N` and generator `g` (hex-encoded) via
`srp.NG_CUSTOM`. Custom parameters are validated on use: `N` must be an odd
integer of at least 512 bits and `g` must satisfy `2 <= g <= N-2`.

```python
n_hex = 'AC6BDB41324A9A9BF166DE5E1389582FAF72B6651987EE07FC3192943DB56050A37329CBB4...'
g_hex = '2'

salt, vkey = srp.create_salted_verification_key( 'testuser', 'testpassword',
                                                 ng_type=srp.NG_CUSTOM,
                                                 n_hex=n_hex, g_hex=g_hex )
usr = srp.User( 'testuser', 'testpassword', ng_type=srp.NG_CUSTOM,
                n_hex=n_hex, g_hex=g_hex )
# ... same handshake as above; pass ng_type/n_hex/g_hex to srp.Verifier as well
```

Proof Verification & Replay Protection
--------------------------------------

The protocol proofs are verified on both sides: the server verifies the
client's proof `M1` in `Verifier.verify_session()` before releasing its own
proof `M2` (`H_AMK`), and the client verifies `M2` in `User.verify_session()`.
All proof comparisons are performed in constant time, and a `User` that has
not yet processed a challenge can never be marked authenticated.

To prevent replayed proofs from being accepted:

* `Verifier` instances are single-use. `verify_session()` may be called at
  most once per instance; create a fresh `Verifier` for every authentication
  attempt.
* For protection across restarts or worker processes, pass a shared
  `srp.ReplayCache` (or any `set`-like object) as `replay_cache`. Already
  seen client proofs are rejected. `ReplayCache` entries expire after
  `ttl_seconds` (default 300).

```python
cache = srp.ReplayCache( ttl_seconds=300 )

svr = srp.Verifier( uname, salt, vkey, A, replay_cache=cache )
```

The `srp/test_rfc5054.py` test cross-checks both backends against the
official SRP-6a test vectors from RFC 5054 Appendix B.

Installation
------------

```
$ pip install srp
```

Implementation
--------------

It consists of 3 modules: A pure Python implementation, A ctypes +
OpenSSL implementation, and a C extension module. The ctypes &
extension modules are approximately 10-20x faster than the pure Python
implementation and can take advantage of multiple CPUs. The extension
module will be used if available, otherwise the library will fall back
to the ctypes implementation followed by the pure Python
implementation.

Note: The test_srp.py script prints the performance timings for each
combination of hash algorithm and prime number size. This may be of
use in deciding which pair of parameters to use in the unlikely
event that the defaults are unacceptable.

Installation from source:
```
   $ python setup.py install
```

Documentation:
```
   $ cd srp/doc
   $ sphinx-build -b html . <desired output directory>
```

Validity & Performance Testing:
```
   $ python setup.py build
   $ python srp/test_srp.py
```
