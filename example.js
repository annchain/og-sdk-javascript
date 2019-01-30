var OG = require('./index.js');
var secp256k1 = require('secp256k1');
var { randomBytes } = require('crypto');
var assert = require('assert')
var createKeccakHash = require('keccak');
var _ = require('underscore');



var og = new OG;

og.setProvider(
    new OG.providers.HttpProvider('http://localhost:8000')
);

var new_account = og.newAccount();
var address = new_account.address;

var pri = 'fc18efa380250fa31e768154e9b77fd397d6bdd7d15bf4b4dad967898e193b89';
var recoverAccount = og.recoveryAccount(pri);
console.log('aaaa',recoverAccount)

var a = og.publicToAddress('fc18efa380250fa31e768154e9b77fd397d6bdd7d15bf4b4dad967898e193b89')
console.log('here',a)

og.genesis().then(function(data){
    // console.log('genesis',data);
});

og.net_info().then(function(data){
    // console.log('net_info',data);
});

og.og_peers_info().then(function(data){
    // console.log('og_peers_info',data);
});

og.peers_info().then(function(data){
    // console.log('peers_info',data);
});

og.sequencer().then(function(data){
    // console.log('sequencer',data);
});

og.status().then(function(data){
    // console.log('status',data);
});

og.validators().then(function(data){
    // console.log('validators',data);
});

var hash = '0x0187627b7585ff993bcaad3155ba5fbf1768899ec6de17b92bc01c48471e39d8';

og.getBalance(address).then(function(data){
    // console.log('getBalance',data);
});

og.getNonce(address).then(function(data){
    // console.log('getNonce',data);
});

og.getReceipt(hash).then(function(data){
    // console.log('getReceipt',data);
});

og.getTransaction(hash).then(function(data){
    // console.log('getTransaction',data);
});

og.confirm(hash).then(function(data){
    // console.log('confirm',data);
})

//gen and send a transaction example
// og.getNonce(new_account.address).then(function(data){
//     nonce = data.data + 1; //get account nonce
// }).then(function(){
//     var txParams = {
//         from : new_account.address,
//         to : '0xa7656df695f2e74b060e3c9a3c8e425cf2107c25',
//         value : 0,
//         publicKey : new_account.public,
//         publicKey_raw : new_account.public_raw,
//         height : 10,
//         nonce : nonce
//     }
//     var signTarget = og.genRawTransaction(txParams);
//     var signature = og.signRawTransaction(signTarget,new_account.privateKey).signature;
//     var tx = og.makeUpTransaction(txParams,signature);
//     // console.log(tx);
//     og.sendTransaction(tx).then(function(data){
//         console.log(data.body);
//         data = JSON.parse(data.body);
//         return og.getTransaction(data.data);
//     }).then(function(data){
//         console.log(data);
//     });
// });

var pri = '70e6b713cd32904d07a55b3af5784e0b23eb38589ebf975f0ab89e6f8d786f01'
var acc = og.recoveryAccount(pri)
// console.log(acc)
    var txParams = {
        from : acc.address,
        to : "0x6d8daedbd7ed0f772d1079b91ee84d57ed20dbce",
        value : 123,
        publicKey : acc.public,
        publicKey_raw : acc.public_raw,
        height : 10,
        nonce : 1
    }
var signTarget = og.genRawTransaction(txParams);
console.log(signTarget.toString('hex'))

var signature = og.signRawTransaction(signTarget,pri).signature;
console.log(signature)
console.log(signature.toString('hex'))

function genRawTransaction (txParams) {
    var tx = {};
    publicKey = new Buffer(txParams.publicKey,'hex');
    tx.From = formatAddress(publicToAddress(publicKey).toString('hex'));
    tx.To = txParams.to;
    tx.Value = txParams.value;
    tx.Nonce = txParams.nonce;
    tx.TxBase = {};
    tx.TxBase.PublicKey = publicKey.toString('hex');
    tx.TxBase.Height = txParams.height;

    var signTarget_Nonce = intToUint64(tx.Nonce);
    var signTarget_from = tx.From.slice(2);
    var signTarget_To = tx.To.slice(2);
    var signTarget_Value = intToHex(tx.Value);
    var signTarget = signTarget_Nonce+signTarget_from+signTarget_To+signTarget_Value;
    // console.log(signTarget)
}

function formatAddress (addr, format){
    if(_.isUndefined(format) || !_.isString(format))
        format = 'hex';

    if(_.isUndefined(addr)
       || !_.isString(addr))
        addr = '0000000000000000000000000000000000000000';

    if(addr.substr(0, 2) == '0x' && format == 'raw')
        addr = addr.substr(2);

    if(addr.substr(0, 2) != '0x' && format == 'hex')
        addr = '0x' + addr;

    return addr;
};

function intToUint64 (i){
    var hex = i.toString(16); // eslint-disable-line
    if (hex.length < 16){
        return (Array(16).join("0") + hex).slice(-16);
    }else if (hex.length = 16){
        return hex;
    }else{
        error
    }
}

function publicToAddress (pubKey,sanitize){
    pubKey = toBuffer(pubKey)
    if (sanitize && (pubKey.length !== 64)) {
      pubKey = secp256k1.publicKeyConvert(pubKey, false).slice(1);
    }
    assert(pubKey.length == 64)
    // Only take the lower 160bits of the hash
    return keccak(pubKey).slice(-20)
}

function toBuffer(v) {
    if (!Buffer.isBuffer(v)) {
      if (Array.isArray(v)) {
        v = Buffer.from(v)
      } else if (typeof v === 'string') {
        if (isHexString(v)) {
          v = Buffer.from(padToEven(exports.stripHexPrefix(v)), 'hex')
        } else {
          v = Buffer.from(v)
        }
      } else if (typeof v === 'number') {
        v = exports.intToBuffer(v)
      } else if (v === null || v === undefined) {
        v = Buffer.allocUnsafe(0)
      } else if (BN.isBN(v)) {
        v = v.toArrayLike(Buffer)
      } else if (v.toArray) {
        // converts a BN to a Buffer
        v = Buffer.from(v.toArray())
      } else {
        throw new Error('invalid type')
      }
    }
    return v
  }

  function keccak (a, bits) {
    a = toBuffer(a)
    if (!bits) bits = 256
  
    return createKeccakHash('keccak' + bits).update(a).digest()
  }

  function intToHex(i){
    var hex = i.toString(16); // eslint-disable-line
    if (hex.length%2){
        hex = '0'+hex;
    }
    return hex;
}
// sorce:
// {"nonce":"0",
//  "from":"0xe0f83f11d769c000d04b1765838c4daed6c9f6c3",
//  "to":"0xa7656df695f2e74b060e3c9a3c8e425cf2107c25",
//  "value":"0",
//  "signature":"0x7bd30f5481640303d64a924f1c0b9d6c35f4666b6b13b4299a4200fcfffeb4f87119599ee32e8ce347eb649504d13ed4aedcd4f6cd2baea361b3d1927fffaf3600",
//  "pubkey":"0x0104ae60c54ccdab2a4a36637d9d6b2bad586dfd107c54652f2c3280dfa5ce16e3bf97006ca8d99d669cde2375fec5eeed63cdba80cfecb7e0154ce3974072d9ac40"}
// res:
// {"hash":"0x999c8594193af73cb43d4648d6f5cbc5e45f4ea738ff03f98f5a3bedff5b39cf"}
// tx in og:
// { Type: 0,
//   Hash: '0x999c8594193af73cb43d4648d6f5cbc5e45f4ea738ff03f98f5a3bedff5b39cf',
//   ParentsHash: [ '0x2ddfd0ac643642e497d8a0d1573a225ee34505f3ca5cce1a32a997d0bd26d848' ],
//   AccountNonce: 0,
//   Height: 1,
//   PublicKey: 'BK5gxUzNqypKNmN9nWsrrVht/RB8VGUvLDKA36XOFuO/lwBsqNmdZpzeI3X+xe7tY826gM/st+AVTOOXQHLZrEA=',
//   Signature: 'e9MPVIFkAwPWSpJPHAudbDX0ZmtrE7QpmkIA/P/+tPhxGVme4y6M40frZJUE0T7UrtzU9s0rrqNhs9GSf/+vNgA=',
//   MineNonce: 1,
//   From: '0xe0f83f11d769c000d04b1765838c4daed6c9f6c3',
//   To: '0xa7656df695f2e74b060e3c9a3c8e425cf2107c25',
//   Value: '0' }