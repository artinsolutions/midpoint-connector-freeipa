# connector-freeipa

Polygon/ConnId connector for FreeIPA

## Description

Connector for [FreeIPA](https://www.freeipa.org/) using [REST API](https://www.freeipa.org/page/API_Examples). 

## Capabilities and Features

* Schema: YES
* Provisioning: YES
* Live Synchronization: No
* Password: YES
* Activation: YES
* Script execution: No 

FreeIPA Connector contains support for USER, ROLE and GROUP entity.  

## Build

[Download](https://github.com/artinsolutions/midpoint-connector-freeipa) and build the project with usual:

```
mvn clean install
```

After successful the build, you can find `connector-freeipa-1.0.0.0.jar` in `target` directory.

## Configuring resource

* create user in FreeIPA
* set membership to user groups: ipausers, trust admins, admins 
* inspire by [sample](https://github.com/artinsolutions/midpoint-connector-freeipa/tree/master/sample) to configure your own resource

## License

Licensed under the [Apache License 2.0](/LICENSE).

## Status

FreeIPA Connector is intended for production use. Tested with MidPoint version 4.0 LTS. The connector was introduced as a contribution to midPoint project by [ARTIN](https://www.artinsolutions.com) and is not officially supported by Evolveum.
If you need support, please contact idm@artinsolutions.com.