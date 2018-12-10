# js-og-sdk
[![Codacy Badge](https://api.codacy.com/project/badge/Grade/ba02977b6c9846cb91e5eb85ab80d1d1)](https://app.codacy.com/app/tonyStig-tao/js-og-sdk?utm_source=github.com&utm_medium=referral&utm_content=tonyStig-tao/js-og-sdk&utm_campaign=Badge_Grade_Dashboard)
[![license](https://img.shields.io/cpan/l/Config-Augeas.svg)](https://github.com/annchain/js-og-sdk/blob/master/LICENSE)

js-og-sdk is a Node.js node_module for OG DAG chain. OG JavaScript API.

# New Features!

  - generate raw transaction
  - sign the raw transaction and send to og

You can also:
  - set the servers whatever you want
  - query the chain data through the functions.
  - generate secp256k1 privKey and get publicKey & address
  - sign the message with the privKey

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

 ```js
var OG = require('og-sdk');
var og = new OG;
var privateKey = Buffer.from('942f9a3d695bb54a8748ef942e88a148de7d0a7fa3ad88d801615f812bd5b672', 'hex')
var txParams = {
        from : "0x05452b3d60ca312fa85b39c29864d6980a6eb436",
        to : "0xa7656df695f2e74b060e3c9a3c8e425cf2107c25",
        value : 0,
        publicKey : "08a69e709e264fcc370d407f2e83ade02d6aaaac7543f87da99f692588cbf72ed35bfac2ace827e507fee6c8435e74ea58dc496013fd92128e979b8ce7b34625",
        publicKey_raw : "0408a69e709e264fcc370d407f2e83ade02d6aaaac7543f87da99f692588cbf72ed35bfac2ace827e507fee6c8435e74ea58dc496013fd92128e979b8ce7b34625",
        height : 10,
        nonce : 1
    }
var signTarget = og.genRawTransaction(txParams);    //gen tx sign target
var signature = og.signRawTransaction(signTarget,privateKey).signature;    //sign the tx
var tx = og.makeUpTransaction(txParams,signature);    //put signature into txParams
og.sendTransaction(tx);    //send the complete tx to og
  ```

License
----

**GNU Lesser General Public License v2.1**
