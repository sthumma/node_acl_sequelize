# Node Acl Sequelize Backend
_acl-sequelize_

[![npm version](https://img.shields.io/npm/v/acl-sequelize.svg)](https://www.npmjs.com/package/acl-sequelize)
[![Build Status](https://travis-ci.org/yonjah/node_acl_sequelize.svg?branch=master)](https://travis-ci.org/yonjah/node_acl_sequelize)
[![codecov](https://codecov.io/gh/yonjah/node_acl_sequelize/branch/master/graph/badge.svg)](https://codecov.io/gh/yonjah/node_acl_sequelize)
[![Known Vulnerabilities](https://snyk.io/test/npm/acl-sequelize/badge.svg)](https://snyk.io/test/npm/acl-sequelize)
[![License](https://img.shields.io/npm/l/acl-sequelize.svg?maxAge=2592000?style=plastic)](https://github.com/yonjah/node_acl_sequelize/blob/master/LICENSE)

[Sequelize](https://github.com/sequelize/sequelize) is an SQL ORM that supports many sql servers (mysql, mariadb, sqlite, postgres and mssql) [flash-oss/node_acl](https://github.com/flash-oss/node_acl).

## Features & Documentation
For ACL general, use please see [flash-oss/node_acl](https://github.com/flash-oss/node_acl).
For Sequelize general, use please see [Sequelize Docs](http://docs.sequelizejs.com/en/latest/).

## Installation

Using npm:

```javascript
npm install acl2
npm install sequelize
npm install [DIALECT] #One of the supported Sequelize dialects
npm install acl-sequelize
```

## Getting Started
```javascript
    Acl       = require('acl');
    Sequelize = require('sequelize'),
    AclSeq    = require('acl-sequelize');
    db        = new Sequelize( 'DB', 'USER', 'PASSWORD'),    
    acl       = new Acl(new AclSeq(db, { prefix: 'acl_' }));
```

## Extra Options 
The second parameter sent to the backend constructor can have supports the following options -

`prefix` - prefix for table names in the database _default ''_

`defaultSchema` - Sequlize Schema settings for all buckets with no specific schema _default schema has two columns key: Primary STRING, value: STRING_

`schema` - Object with Sequlize Schema settings per bucket (meta|parents|permissions|resources|roles|users ) to override default schema

## Creating tables manually
ACL-Sequelize will automatically register and sync needed schemes
if for some reason you need to register your own tables and the schema override parameters are not good enough you can register the schemes yourself before initiating the `backend`. ACL-Sequelize will use the existing schema instead of adding a new one (Register schema should follow `prefix`+`bucket_name` convention and have key, value columns)

## Testing
### Test setup
The test database connection settings are in the `test/runner.js`. The current setting uses sqlite for tests.

### Running tests
```javascript
npm test
```

### Changelog
See [changelog file](CHANGELOG.md)

### Security issues
This project participates in the Responsible Disclosure Policy program for the Node.js Security Ecosystem. see [security.md](security.md) for more info

## Known Issues
- default schema limit each column 255 chars, if you have a lot of resources / permissions / complex hierarchy, You'll probably need to set your own schema with higher limit.
- node ACL has a race condition bug I would avoid setting multiple permissions until the [issue](https://github.com/OptimalBits/node_acl/pull/112) is resolved
- I haven't done any performance tweaks, this can probably be implemented in a much more efficient way using relational schema and JOINS, but I'm not sure node ACL API is flexible enough to make it beneficial 

P.S Thanks for Robert Kaufmann III <rok3@rok3.me> who originally registered the npm module.
