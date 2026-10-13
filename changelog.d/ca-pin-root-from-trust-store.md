### Fixed: `SENSOR_CA_FINGERPRINT` can pin a root the platform does not send

- A pinned CA fingerprint was accepted only when the server sent that certificate in its TLS chain. The built-in gateway (internal TLS) sends the server certificate and the intermediate, not the root whose fingerprint the console shows, so pinning that root refused every connection.
- When the pinned certificate is not sent, the chain is now verified against the API trust (`SENSOR_CA_CERT_FILE`, else the system trust store) and accepted only when a verified chain contains the pinned certificate. Name, validity and usage are still checked; a trusted CA other than the pinned one (an interception proxy, a second CA in the file) is still refused.
- Operators pinning the gateway root: put the root in `SENSOR_CA_CERT_FILE` as well as its fingerprint in `SENSOR_CA_FINGERPRINT`.
