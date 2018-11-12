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

var newAccount = og.newAccount();
// console.log(newAccount);

var msg = randomBytes(32);
var result = og.signRawTransaction(msg,newAccount.privateKey);
console.log(result);
