var version = require('./version.json');
var secp256k1 = require('secp256k1');
var HttpProvider = require('./OG/httpProvider');
var RequestManager = require('./OG/requestManager');
var Net = require('./OG/methods/net');
var request = require('request');
var promise = require('bluebird');

function OG (provider) {
    this._requestManager = new RequestManager(provider);
    this.currentProvider = provider;
    this.net = new Net(this);
    this.version = {
        api: version.version
    };
    this.providers = {
        HttpProvider: HttpProvider
    };
}

OG.providers = {
    HttpProvider: HttpProvider
};

OG.prototype.setProvider = function (provider) {
    this._requestManager.setProvider(provider);
    this.currentProvider = provider;
};

OG.prototype.isConnected = function(){
    return (this.currentProvider && this.currentProvider.isConnected());
};

OG.prototype.reset = function (keepIsSyncing) {
    this._requestManager.reset(keepIsSyncing);
    this.settings = new Settings();
};


//PRC
OG.prototype.genesis = function(){
    var url = this.currentProvider.host;
    var method = "/genesis";
    return new promise(function(resolve,reject){
        request(url+method, function (error, response, body) {
            if (error){
                reject(error)
            }else{
                var result = {};
                result.response = response.statusCode;
                result.body = body; 
                resolve(result);
            }
        });
    });
}

OG.prototype.net_info = function(){
    var url = this.currentProvider.host;
    var method = "/net_info";
    return new promise(function(resolve,reject){
        request(url+method, function (error, response, body) {
            if (error){
                reject(error)
            }else{
                var result = {};
                result.response = response.statusCode;
                result.body = body; 
                resolve(result);
            }
        });
    });
}

OG.prototype.og_peers_info = function(){
    var url = this.currentProvider.host;
    var method = "/og_peers_info";
    return new promise(function(resolve,reject){
        request(url+method, function (error, response, body) {
            if (error){
                reject(error)
            }else{
                var result = {};
                result.response = response.statusCode;
                result.body = body; 
                resolve(result);
            }
        });
    });
}

OG.prototype.peers_info = function(){
    var url = this.currentProvider.host;
    var method = "/peers_info";
    return new promise(function(resolve,reject){
        request(url+method, function (error, response, body) {
            if (error){
                reject(error)
            }else{
                var result = {};
                result.response = response.statusCode;
                result.body = body; 
                resolve(result);
            }
        });
    });
}

OG.prototype.sequencer = function(){
    var url = this.currentProvider.host;
    var method = "/sequencer";
    return new promise(function(resolve,reject){
        request(url+method, function (error, response, body) {
            if (error){
                reject(error)
            }else{
                var result = {};
                result.response = response.statusCode;
                result.body = body; 
                resolve(result);
            }
        });
    });
}

OG.prototype.status = function(){
    var url = this.currentProvider.host;
    var method = "/status";
    return new promise(function(resolve,reject){
        request(url+method, function (error, response, body) {
            if (error){
                reject(error)
            }else{
                var result = {};
                result.response = response.statusCode;
                result.body = body; 
                resolve(result);
            }
        });
    });
}

OG.prototype.validators = function(){
    var url = this.currentProvider.host;
    var method = "/validators";
    return new promise(function(resolve,reject){
        request(url+method, function (error, response, body) {
            if (error){
                reject(error)
            }else{
                var result = {};
                result.response = response.statusCode;
                result.body = body; 
                resolve(result);
            }
        });
    });
}

// @param {buffer}{Bytes(32)} msg
// @param {buffer}{Bytes(32)} pk
OG.prototype.signRawTransaction = function (msg,pk) {
    var sig = secp256k1.sign(msg, pk)
    return sig;
};

// TODO JSONRPC

module.exports = OG;