var OG = require('./index.js');
var secp256k1 = require('secp256k1');
var { randomBytes } = require('crypto');

var og = new OG;

og.setProvider(
    new OG.providers.HttpProvider('http://localhost:8000')
);

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

var address = '0x0b5d53f433b7e4a4f853a01e987f977497dda262';
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

var new_account = og.newAccount();
console.log(new_account);

// var from = "0xb276f14504557c13e69ef04bc01334d3e332e26b";
var from = new_account.address;
var to = '0xa7656df695f2e74b060e3c9a3c8e425cf2107c25';
var value = 0;
var publicKey = new_account.public;
var publicKey_raw = new_account.public_raw;
var prikey = new_account.privateKey;
// var publicKey = "331/c1d6d2b6cfefb4f2a5faa7fccd07e025682e3667951dbbd954550413d4c90da5fef46b167886d199eb4ef12cbc6972a4bed80400c4911a27834ccee663d44";
// var prikey = "e271b1414efa510d79d7f3293b7c143fa76ebdf993302c006d435c3b1adfc482"
var height = 10;
og.getNonce(from).then(function(data){
    nonce = data.nonce + 1;
}).then(function(){
    console.log(from,to,value,publicKey,height,nonce);
    var rawTx = og.genRawTransaction(to,value,publicKey,height,nonce);
    var signature = og.signRawTransaction(rawTx,prikey).signature;
    console.log(signature);
    var tx = {
        "nonce" : nonce.toString(),
        "from" : from,
        "to" : to,
        "value" : value.toString() ,
        "signature": "0x" + signature.toString('hex'),
        "pubkey": "0x01" + publicKey_raw
    }
    var tx = JSON.stringify(tx);
    og.sendTransaction(tx).then(function(data){
        console.log(data);
        data = JSON.parse(data.body);
        return og.getTransaction(data.hash);
    }).then(function(data){
        console.log(data);
    });
});


// {
// 	"nonce":"0",
// 	"from":"0x61a74d3f7f8e24b5d46ef4cffb421c3fa3a483dd",
// 	"to":"0xa7656df695f2e74b060e3c9a3c8e425cf2107c25",
// 	"value":"10",
// 	"signature":"0xa93be7758c52dd3cb1f747f44844235b631391dbca8eebde32318b897aad454f2e9709face3438e55901e5e34f43162caf5743ced13b0b45d81f6dbfc816733f",
// 	"pubkey":"0x01969b0aa2a95da2f17a7ddfdad63839cf07c811b6fa122080c3e12d7fde9eb4a40bab371f97a6ca932186a75d3a56c99ebaf6f7b994045f5122cc5bebcf7ea9ae"
// }