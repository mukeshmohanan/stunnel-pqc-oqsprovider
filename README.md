# stunnel-with-pqc-oqsprovider

This repo contains prcoedure to build Stunnel to support PQC algorithm (For Securing TLS connection) and use it to secure tls connection between a client and Server App (Spring boot) which support using pqc algorithm. The connection between the Stunnel Client and Stunnel Server Instances will be configured to use PQC algortihms(Kyber preferably in this example)

For this test both the client Instances and Server Instances are deployed in same localhost 

# Target Deployment model 
![deployment](diagram_screenshots/stunne_pqc.drawio.svg)

# Overall Build Steps 

## Openssl 3.x build 
Follow the standard Openssl build process [here](https://github.com/openssl/openssl/blob/master/NOTES-UNIX.md) to get the 3.x version of the same  


### liboqs build using the openssl 3.x version

follow the standard procedure defined [here](https://github.com/open-quantum-safe/liboqs#linuxmacos) , make sure that liboqs built id done using the openssl version built in the previous step 

### oqsprovider build 

Follow the build procedure outlined in the [official page](https://github.com/open-quantum-safe/oqs-provider/blob/main/README.md) liboqs and openssl 3.x is pre-requiiste this should be already available follwing the previous steps

Verify the openss 3.x have the oqs provider available as a default option , example output shown below

```
aishwaryanarayanan@Aishwaryas-MBP bin % pwd  

/Users/aishwaryanarayanan/mukesh/oqs/oqs-provider/.local/bin  

mukesh@Mukeshs-MBP bin % ./openssl list -providers  
Providers:  

  default  
    name: OpenSSL Default Provider
    version: 3.2.0
    status: active  
    
  oqsprovider  
    name: OpenSSL OQS Provider
    version: 0.5.2-dev
    status: active  
    
mukesh@Mukeshs-MBP bin % 

```

### ReConfigure Openssl 3.x to use specific algorithms with PQC algorithms as preffered one for TLS 

This can be achived by amending below section in the openssl.cnf as shown in the below 

```
[openssl_init]  

providers = provider_sect  

ssl_conf = ssl_sect  

[ssl_sect]  

system_default = system_default_sect  

[system_default_sect]  

Groups = kyber768:kyber1024:X25519:P-256:X448:P-521:P-384:dilithium3  

#Groups = kyber768:kyber1024  

[provider_sect]  

default = default_sect  

#default = oqsprovider_sect  

oqsprovider = oqsprovider_sect  

```

### Stunnel Build 
Download the stunnel zipped file from the [offical site](https://www.stunnel.org/downloads.html) and extract the same 
configure the stunnel to point to the directory where openssl 3.x is available , make sure that there is no errors 

```
#mukesh@Mukeshs-MBP src % pwd
/Users/mukesh/oqs/stunnel-5.70/src
#mukesh@Mukeshs-MBP src % ./configure --prefix=/Users/mukesh/mukesh/oqs/oqs-provider/.local
```
### Stunnel configuration 

#### Server side config

#Classical RSA signed Certificates are used in the stunnel instances , which means kem is handled using PQC algorithm not the authentication piece 

#Kyber768 would be the preffered algorithm used be the stunnel service for TLS handshake 

```
aishwaryanarayanan@Aishwaryas-MBP oqs % cat stunnel-5.70/src/stunnel.conf
#fips = yes
debug = 7
output = /usr/local/etc/stunnel/stunnel.log

#TLS front-end to the spring boot Server App 
[https]
accept  = 11113
connect = 8443
#transparent = source
cert = /Users/aishwaryanarayanan/mukesh/oqs/server-cert.pem
key = /Users/aishwaryanarayanan/mukesh/oqs/server-key.pem
#CAfile = /Users/aishwaryanarayanan/mukesh/oqs/RSArootCA.crt
curve = kyber768:frodo640shake:x25519_kyber512:x25519
```
##### Stunnel Client Instance configuration
```
aishwaryanarayanan@Aishwaryas-MBP oqs % cat stunnel-5.70/src/stunnel_client.conf
#fips = yes
debug = 7
output = /usr/local/etc/stunnel/stunnel_client.log
client = yes
#TLS client
[https]
accept  = 11111
connect = 11113
#transparent = source
cert = /Users/aishwaryanarayanan/mukesh/oqs/client-cert.pem
key = /Users/aishwaryanarayanan/mukesh/oqs/client-key.pem
CAfile = /Users/aishwaryanarayanan/mukesh/oqs/RSArootCA.crt
curve = kyber768:frodo640shake:x25519_kyber512:x25519
aishwaryanarayanan@Aishwaryas-MBP oqs % 
```

####Stunnel Service Start 

```
aishwaryanarayanan@Aishwaryas-MBP src % ./stunnel stunnel.conf
[ ] Initializing inetd mode configuration
[ ] Clients allowed=31999
[.] stunnel 5.70 on aarch64-apple-darwin22.5.0 platform
[.] Compiled/running with OpenSSL 3.2.0-dev 
[.] Threading:PTHREAD Sockets:POLL,IPv6 TLS:ENGINE,OCSP,PSK,SNI
[ ] errno: (*__error())
[ ] Initializing inetd mode configuration
[.] Reading configuration from file /Users/aishwaryanarayanan/mukesh/oqs/stunnel-5.70/src/stunnel.conf
[.] UTF-8 byte order mark not detected
[.] FIPS mode disabled
[ ] Compression disabled
[ ] No PRNG seeding was required
[ ] Initializing service [https]
[ ] OpenSSL security level is used: 2
[ ] Ciphers: HIGH:!aNULL:!SSLv2:!DH:!kDHEPSK
[ ] TLSv1.3 ciphersuites: TLS_AES_256_GCM_SHA384:TLS_AES_128_GCM_SHA256:TLS_CHACHA20_POLY1305_SHA256
[ ] TLS options: 0x2100000 (+0x0, -0x0)
[ ] Session resumption enabled
[ ] Loading certificate from file: /Users/aishwaryanarayanan/mukesh/oqs/server-cert.pem
[ ] Certificate loaded from file: /Users/aishwaryanarayanan/mukesh/oqs/server-cert.pem
[ ] Loading private key from file: /Users/aishwaryanarayanan/mukesh/oqs/server-key.pem
[:] Insecure file permissions on /Users/aishwaryanarayanan/mukesh/oqs/server-key.pem
[ ] Private key loaded from file: /Users/aishwaryanarayanan/mukesh/oqs/server-key.pem
[ ] Private key check succeeded
[ ] No trusted certificates found
[ ] DH initialization skipped: no DH ciphersuites
[ ] ECDH initialization
[ ] ECDH initialized with curves kyber768:frodo640shake:x25519_kyber512:x25519
[.] Configuration successful
[ ] Deallocating deployed section defaults
[ ] Binding service [https]
[ ] Listening file descriptor created (FD=9)
[ ] Setting accept socket options (FD=9)
[ ] Option SO_REUSEADDR set on accept socket
[.] Binding service [https] to :::11113: Address already in use (48)
[ ] Listening file descriptor created (FD=9)
[ ] Setting accept socket options (FD=9)
[ ] Option SO_REUSEADDR set on accept socket
[.] Binding service [https] to 0.0.0.0:11113: Address already in use (48)
[!] Binding service [https] failed
[ ] Unbinding service [https]
[ ] Service [https] closed
[ ] Deallocating deployed section defaults
[ ] Deallocating section [https]
[ ] Initializing inetd mode configuration
aishwaryanarayanan@Aishwaryas-MBP src %
```
```
aishwaryanarayanan@Aishwaryas-MBP src % ./stunnel stunnel_client.conf
[ ] Initializing inetd mode configuration
[ ] Clients allowed=31999
[.] stunnel 5.70 on aarch64-apple-darwin22.5.0 platform
[.] Compiled/running with OpenSSL 3.2.0-dev 
[.] Threading:PTHREAD Sockets:POLL,IPv6 TLS:ENGINE,OCSP,PSK,SNI
[ ] errno: (*__error())
[ ] Initializing inetd mode configuration
[.] Reading configuration from file /Users/aishwaryanarayanan/mukesh/oqs/stunnel-5.70/src/stunnel_client.conf
[.] UTF-8 byte order mark not detected
[.] FIPS mode disabled
[ ] Compression disabled
[ ] No PRNG seeding was required
[ ] Initializing service [https]
[ ] OpenSSL security level is used: 2
[ ] Ciphers: HIGH:!aNULL:!SSLv2:!DH:!kDHEPSK
[ ] TLSv1.3 ciphersuites: TLS_AES_256_GCM_SHA384:TLS_AES_128_GCM_SHA256:TLS_CHACHA20_POLY1305_SHA256
[ ] TLS options: 0x2100000 (+0x0, -0x0)
[ ] Session resumption enabled
[ ] Loading certificate from file: /Users/aishwaryanarayanan/mukesh/oqs/client-cert.pem
[ ] Certificate loaded from file: /Users/aishwaryanarayanan/mukesh/oqs/client-cert.pem
[ ] Loading private key from file: /Users/aishwaryanarayanan/mukesh/oqs/client-key.pem
[:] Insecure file permissions on /Users/aishwaryanarayanan/mukesh/oqs/client-key.pem
[ ] Private key loaded from file: /Users/aishwaryanarayanan/mukesh/oqs/client-key.pem
[ ] Private key check succeeded
[ ] Configured trusted server CA: CN=demo.root.com, C=US, L=San Fransisco
[:] Service [https] needs authentication to prevent MITM attacks
[ ] DH initialization skipped: client section
[ ] ECDH initialization
[ ] ECDH initialized with curves kyber768:frodo640shake:x25519_kyber512:x25519
[.] Configuration successful
[ ] Deallocating deployed section defaults
[ ] Binding service [https]
[ ] Listening file descriptor created (FD=9)
[ ] Setting accept socket options (FD=9)
[ ] Option SO_REUSEADDR set on accept socket
[.] Binding service [https] to :::11111: Address already in use (48)
[ ] Listening file descriptor created (FD=9)
[ ] Setting accept socket options (FD=9)
[ ] Option SO_REUSEADDR set on accept socket
[.] Binding service [https] to 0.0.0.0:11111: Address already in use (48)
[!] Binding service [https] failed
[ ] Unbinding service [https]
[ ] Service [https] closed
[ ] Deallocating deployed section defaults
[ ] Deallocating section [https]
[ ] Initializing inetd mode configuration
aishwaryanarayanan@Aishwaryas-MBP src %
```
#### Start the Spring boot application  


Its been configured to use mTLS and clients autherization is done by whitelisting the CN name of the client (Not Stunnel client the actual client app) certificate , please refer 
[here](https://github.com/mukeshmohanan/stunnel-pqc-oqsprovider/blob/6942b74980096e8995c1761cf6e81352d2a556bd/example-spring-rest-service/complete/src/main/java/com/example/restservice/config/SecurityConfiguration.java#L35)

```
aishwaryanarayanan@Aishwaryas-MBP complete % pwd
/Users/aishwaryanarayanan/mukesh/oqs/sample_spring_boot/gs-rest-service/complete
aishwaryanarayanan@Aishwaryas-MBP complete % 
aishwaryanarayanan@Aishwaryas-MBP complete % 
aishwaryanarayanan@Aishwaryas-MBP complete % java -jar target/rest-service-complete-0.0.1-SNAPSHOT.jar --trace -Djavax.net.debug=ssl:handshake:keymanager
```
#### Client connect

Connect the spring boot API end point from Postman , connection is made via the socket connection to Stunnel client instance  , Please make sure to configure the client certiifcate (whose CN name whitelisetd in Springboot App) at the post man and also the CA certiifcate is configured 

#### Verification of TLS connection 

validate the Keyshare or kem greoup used in each connection by scanning the connection using wireshark and also verify the Spring boot logs which authenitcate the certificate used at the postman side.  


Though the connection is routed via the Stunnel Client --> Stunnel Server --> Spring boot App the actual authenticaiton to the app is done with the context of the certificate used at the postman side, This proves that though we implement the Stunnel in b/w the Client and app the existing mTLS connection should work without any problem
