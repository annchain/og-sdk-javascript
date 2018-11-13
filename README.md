# js-og-sdk
[![Codacy Badge](https://api.codacy.com/project/badge/Grade/ba02977b6c9846cb91e5eb85ab80d1d1)](https://app.codacy.com/app/tonyStig-tao/js-og-sdk?utm_source=github.com&utm_medium=referral&utm_content=tonyStig-tao/js-og-sdk&utm_campaign=Badge_Grade_Dashboard)
[![license](https://img.shields.io/cpan/l/Config-Augeas.svg)](https://github.com/annchain/js-og-sdk/blob/master/LICENSE)

js-og-sdk is a Node.js node_module for OG DAG chain. OG JavaScript API.


## New Features!

  - generate secp256k1 privKey and get publicKey & address
  - sign the message with the privKey


You can also:
  - set the servers whatever you want
  - query the chain data through the functions.

## Quick start
Using npm to include js-og-sdk in your own project:
```shell
npm install --save og-sdk
```

## Install

### To use as a module in a Node.js project
1. Install it using npm:
  ```shell
  npm install --save og-sdk
  ```

2. require/import it in your JavaScript:
  ```js
  var OG = require('og-sdk');
  ```
  
## Usage
For information on how to use js-og-sdk, take a look at the [example.js](https://github.com/annchain/js-og-sdk/blob/master/example.js).

## Todos

 - create Raw transaction
 - sign the transaction and send to PRC

License
----

**GNU Lesser General Public License v2.1**
