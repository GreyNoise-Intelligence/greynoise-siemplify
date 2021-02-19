[![main](https://github.com/GreyNoise-Intelligence/greynoise-siemplify/workflows/Build/badge.svg)](https://github.com/GreyNoise-Intelligence/greynoise-siemplify/actions?query=workflow%3ABuild)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

# GreyNoise Siemplify Integration

The GreyNoise Siemplify Integration is a set of actions and connectors that can be used in the Siemplify platform.

More details about Siemplify here: [https://www.siemplify.co/](https://www.siemplify.co/)

## Usage

### Initial Configuration
In order to use the GreyNoise Integration for Siemplify, install the Integration from the Siemplify marketplace.  Then,
configure the integration using a GreyNoise API key.

If you don't have a GreyNoise API key, you can sign up for a free trial at 
[https://viz.greynoise.io/signup](https://viz.greynoise.io/signup)

### Actions

The GreyNoise Actions allow for IPs to be queried in the different GreyNoise API endpoints and for a more complex 
GNQL query to be executed as part of a Case workflow.

#### Quick IP Lookup
The Quick IP Lookup action is designed to take all Address entities associated with a case/alert and enrich them against
the GreyNoise Quick API.

#### Context IP Lookup
The Context IP Lookup action is designed to take all Address entities associated with a case/alert and enrich them 
against the GreyNoise Context API.  It also provides an Insight on the Case for each IP entity that is found.

#### RIOT IP Lookup
The RIOT IP Lookup action is designed to take all Address entities associated with a case/alert and enrich them against
the GreyNoise RIOT API.  It also provides an Insight on the Case for each IP entity that is found.

#### Execute GNQL Query
The Execute GNQL Query action is designed to perform a GNQL query against the GreyNoise query endpoint and return all
matching records, up to the supplied limit (default is 10 results).

### Connectors

The GreyNoise Connector allows for a GNQL to be used to generate alerts.

#### Generate Alert from GreyNoise GNQL
The Generate Alert from GreyNoise GNQL connector is primarily designed to be an alerting system for when GreyNoise
begins observing mass-internet scanning activity of a monitored IP.  The primary use case is to query daily for a CIDR
block, using a query similar to: `ip:85.32.32.0/24 last_seen:1d`

Using a query similar to the above, this would generate an alert for an IP in the provided range if GreyNoise observes
the IP performing mass-internet scanning.

## Contributing

Please read [CONTRIBUTING.md](CONTRIBUTING.md) for details on our code of conduct, and the process for submitting pull
requests to us.

## Versioning

We use [SemVer](http://semver.org/) for versioning. For the versions available, see
the [tags on this repository](https://github.com/GreyNoise-Intelligence/os-template/tags).

## Authors

* **Brad Chiappetta** - *Initial work* - [bradchiappetta](https://github.com/bradchiappetta)

See also the list of [contributors](https://github.com/GreyNoise-Intelligence/os-template/contributors) who participated
in this project.

## Acknowledgments

* Siemplify Community and Support members for help with the initial development.

## Links

* [GreyNoise.io](https://greynoise.io)
* [GreyNoise Terms](https://greynoise.io/terms)
* [GreyNoise Developer Portal](https://developer.greynoise.io)

## Contact Us

Have any questions or comments about GreyNoise? Contact us at [hello@greynoise.io](mailto:hello@greynoise.io)

## Copyright and License

Code released under [MIT License](LICENSE).

