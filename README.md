# Redfish Certrobot

Manage certificates on BMCs via Redfish / ACME DNS-01

This is a small-ish python script, which uses
- [Lego](https://go-acme.github.io/lego/) for ACME DNS-01 challenge
- [Sushy](https://pypi.org/project/sushy/) for Redfish api access to
  - generate a CSR for the BMC using its key
  - Replace the certificate by a signed one
- [Ironic](https://wiki.openstack.org/wiki/Ironic) storing all servers and their credentials

As it is supposed to run as a cronjob in kubernetes, the configration
is happening via environment variables.

## Steps

1. The script fetches all nodes stored in Ironic
3. For each node, check the active certificate on the BMC (port 443) (mismatching name or issuer CN, missing SAN, expiring soon)
4. If not okay, requests a new CSR with the correct values via Redfish
5. Using Lego (ACME DNS-01 ), get the CSR signed
6. Install the Cert in the BMC

## Configuration

All configuration happens via environment variables

| Variable                | Description                                                                         |
|-------------------------|-------------------------------------------------------------------------------------|
| ISSUER                  | Common-Name of the expected issuer                                                  |
| DNS_RESOLVERS           | Comma-separated list of the dns-resolvers to check the propagation                  |
| ACME_SERVER             | URL to the ACME server (presumably you want a private one here, not Let's Encrypt)  |
| CSR_COUNTRY             | Country in the CSR                                                                  |
| CSR_STATE               | State                                                                               |
| CSR_CITY                | City                                                                                |
| CSR_ORGANIZATIONAL_UNIT | Organizational Unit                                                                 |
| CSR_ORGANIZATION        | Organization                                                                        |


The CSR values are all required to be set by some BMCs.

Technically, we are not bound by Designate,configuration for [Lego Dns Providers](https://go-acme.github.io/lego/dns/),
it has only been tested with Designate through.

| Variable                | Description                                                                         |
|-------------------------|-------------------------------------------------------------------------------------|
| OS_DOMAIN_NAME          | Name of the domain                                                                  |
| OS_AUTH_URL             | Identity endpoint URL                                                               |
| OS_PASSWORD             | Password                                                                            |
| OS_PROJECT_NAME         | Project name                                                                        |
| OS_REGION_NAME          | Region name                                                                         |
| OS_USERNAME             | Username                                                                            |
| OS_DOMAIN_NAME          | Domain name                                                                         |

