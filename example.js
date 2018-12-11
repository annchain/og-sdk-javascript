var OG = require('./index.js');
var secp256k1 = require('secp256k1');
var { randomBytes } = require('crypto');

var og = new OG;

og.setProvider(
    new OG.providers.HttpProvider('http://localhost:8000')
);

var new_account = og.newAccount();
var address = new_account.address;

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

var hash = '0xd1b2606032d8bdd217f0ba69c2c3a7c2469cc5a6cf9491b14e4705c56db7a0f4';

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

//gen and send a transaction example
og.getNonce(new_account.address).then(function(data){
    nonce = data.nonce + 1; //get account nonce
}).then(function(){
    var txParams = {
        from : new_account.address,
        to : '0xa7656df695f2e74b060e3c9a3c8e425cf2107c25',
        value : 0,
        publicKey : new_account.public,
        publicKey_raw : new_account.public_raw,
        height : 10,
        nonce : nonce
    }
    var signTarget = og.genRawTransaction(txParams);
    var signature = og.signRawTransaction(signTarget,new_account.privateKey).signature;
    var tx = og.makeUpTransaction(txParams,signature);
    console.log(tx);
    og.sendTransaction(tx).then(function(data){
        console.log(data.body);
        data = JSON.parse(data.body);
        return og.getTransaction(data.hash);
    }).then(function(data){
        console.log(data);
    });
});

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