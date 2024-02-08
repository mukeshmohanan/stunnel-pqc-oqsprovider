# stunnel-with-pqc-oqsprovider

This repo contains prcoedure to build Stunnel to support PQC algorithm (For Securing TLS connection) and use it to secure tls connection between a client and Server App (Spring boot) which support using pqc algorithm. The connection between the Stunnel Client and Stunnel Server Instances will be configured to use PQC algortihms(Kyber preferably in this example)

For this test both the client Instances and Server Instances are deployed in same localhost 

# Target Deployment model 
![deployment](diagram_screenshots/stunne_pqc.drawio.svg)
