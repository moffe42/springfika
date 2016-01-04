# SpringFika #

SpringFika is a simple selfcontained php script  written as part of the Géant3 project (Joint Research Activity 3, task 2 (identity federations). Springfika is developed by WAYF (www.wayf.dk) - but contributions, comments and suggestions are very welcome.

The aim is to develop a SAML2 based attribute collector and to learn about and experiment with the SAML2 protocol in general.

Springfika's main datastructure is the SAML assertions, requests and responses represented as php arrays. There is no abstraction layer between the script and the saml entities so all manipulation is done directly on the arrays/entities.

The "real" SAML xml is converted to arrays coming in to the script and vice versa on their way out. In the name of
simplicity i have cut some corners in the conversion so it does not cover all possible saml messages. It is possible, at the cost of some added complexity, to configure the conversion to be more general. PHP arrays are really ordered maps so element sequence can be preserved and constructed.

Saml system entities can be idp's or sp's and in SpringFika they are always both ie. they are always bridges/proxies. This is because a sp have an idp interface to present its assertions to the application proper and an idp have a sp side to get the
user authenticated. One might think of these interfaces as
"internal" in that they do not need access to the same metadata
and pki as the federation visible external interfaces. To make
these internal interfaces simpler to develop (in the app and
auth mechanism) but stil allowing access to the full saml
message SpringFika can send and receive them in a json
representation. They can be signed using a simple shared secret
schema. SpringFika is thus always "remote" in the sense that
applications are always seen as remote sp's and authentication
mechanisms are always seen as remote idp's. As default
SpringFika does not keep any session information (besides what
is needed when acting as a proxy - remembering an incoming
request while waiting for the response).

SpringFika has a notion of co-hosted system entities -
communication between co-hosted entities is done by an internal
binding mechanism (ie. no browser involvement) for performance
reasons.

SpringFika is somewhat geared towards a proxy environment as the
Danish Wayf.dk federation, but it can be used to learn about and
experiment with a peer to peer federation as well.

If you have installed SpringFika so it is webaccessible at
https://example.com/!SpringFika.php the following system entities are
preconfigured:

(The cookies are always secure so if you want to experiment with
the proxy functionality you will have to run it on a secure
connection. Otherwise you will only be able to use the peer2peer
functionality which - as distributed - does not use sessions.)

One sp: https://example.com/springfika.php/main/

The first element after the scripname is always a short id for
the system entity.

And a number of idps:

  * https://example.com/springfika.php/proxy - a proxy which is used by most of the examples
  * https://example.com/springfika.php/idp1 - a normal idp with a simple embedded authentication ie. just click ok and you areauthenticated ...
  * https://example.com/springfika.php/idp2 - an idp which authenticates atidp1 using proxy as proxy, but releases its own attributes ie. an attribute authority
  * https://example.com/springfika.php/vidp1 - a "virtual" idp which hasidp1, idp2 and idp3 as "backend" idps. A virtual idp is an idp which syntesesis the attributes from multiple backend idps/aas. In this case it uses AuthnRequests.

springfika supports:

  * AuthnRequests - including Scoping with ProxyCount, IDPList/ProviderID and RequesterID, assertions with AuthenticatingAuthority
  * Bindings: redirect, post, artifact, uri
  * Signing and encryption of requests, responses and assertions -and encrypted attributes as well

Handling of IsPassive and ForceAuthn is delegated to Authn Mechanisms and the apps.
Handling of SingleSignon ie. session keeping is also as default delegated to the Auth Mechs.

No single-logout is handled at all.

A simple demo is available here https://wayf.ruc.dk/els/s/springfika.php/main/demoapp (the default selected idp does an attribute collection at two idps - with autologin - and shows the response in print\_r format. Try using the net inspector in firebug - with persist on - to see what is going on).

