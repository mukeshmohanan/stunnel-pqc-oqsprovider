# stunnel-with-pqc-oqsprovider

This repo contains prcoedure to build Stunnel to support PQC algorithm (For Securing TLS connection) and use it to secure tls connection between a client and Server App (Spring boot) which support using pqc algorithm. The connection between the Stunnel Client and Stunnel Server Instances will be configured to use PQC algortihms(Kyber preferably in this example)

For this test both the client Instances and Server Instances are deployed in same localhost 

# Target Deployment model 
![deployment](diagram_screenshots/stunne_pqc.drawio.svg)

# Overall Build Steps 

## Openssl 3.x build 
Follow the standard Openssl build process [here]([https://website-name.com](https://github.com/openssl/openssl/blob/master/NOTES-UNIX.md)https://github.com/openssl/openssl/blob/master/NOTES-UNIX.md) to get the 3.x version of the same  


### liboqs build using the openssl 3.x version

follow the standard procedure defined [here]([https://website-name.com](https://github.com/open-quantum-safe/liboqs#linuxmacos) , make sure that liboqs built id done using the openssl version built in the previous step 

### oqsprovider build 

Follow the build procedure outlined in the [official page ] (https://github.com/open-quantum-safe/oqs-provider/blob/main/README.md) liboqs and openssl 3.x is pre-requiiste this should be already available follwing the previous steps

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
Download the stunnel zipped file from the [offical site] (https://www.stunnel.org/downloads.html) and extract the same 
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

# Start the Spring boot application 
Its been configured to use mTLS and clients autherization is done by whitelisting the CN name 


