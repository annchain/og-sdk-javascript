var version = require('./version.json');
var _ = require('underscore');
var createKeccakHash = require('keccak')
var secp256k1 = require('secp256k1');
var { randomBytes } = require('crypto');
var assert = require('assert')
var HttpProvider = require('./OG/httpProvider');
var RequestManager = require('./OG/requestManager');
var Net = require('./OG/methods/net');
var request = require('request');
var promise = require('bluebird');
var Buffer = require('safe-buffer').Buffer;

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
                resolve(JSON.parse(result.body));
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
                resolve(JSON.parse(result.body));
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
                resolve(result.body);
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
                resolve(result.body);
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
                resolve(JSON.parse(result.body));
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
                resolve(JSON.parse(result.body));
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
                resolve(JSON.parse(result.body));
            }
        });
    });
}

OG.prototype.getBalance = function(address){
    var url = this.currentProvider.host;
    var method = "/query_balance?address=" + address;
    return new promise(function(resolve,reject){
        request(url+method, function (error, response, body) {
            if (error){
                reject(error)
            }else{
                var result = {};
                result.response = response.statusCode;
                result.body = body; 
                resolve(JSON.parse(result.body));
            }
        });
    });
}

OG.prototype.getNonce = function(address){
    var url = this.currentProvider.host;
    var method = "/query_nonce?address=" + address;
    return new promise(function(resolve,reject){
        request(url+method, function (error, response, body) {
            if (error){
                reject(error)
            }else{
                var result = {};
                result.response = response.statusCode;
                result.body = body; 
                resolve(JSON.parse(result.body));
            }
        });
    });
}

OG.prototype.getReceipt = function(hash){
    var url = this.currentProvider.host;
    var method = "/query_receipt?hash=" + hash;
    return new promise(function(resolve,reject){
        request(url+method, function (error, response, body) {
            if (error){
                reject(error)
            }else{
                var result = {};
                result.response = response.statusCode;
                result.body = body; 
                resolve(JSON.parse(result.body));
            }
        });
    });
}

OG.prototype.getTransaction = function(hash){
    var url = this.currentProvider.host;
    var method = "/transaction?hash=" + hash;
    return new promise(function(resolve,reject){
        request(url+method, function (error, response, body) {
            if (error){
                reject(error)
            }else{
                var result = {};
                result.response = response.statusCode;
                result.body = body; 
                resolve(JSON.parse(result.body));
            }
        });
    });
}

OG.prototype.newAccount = function(){
    var privateKey = new Buffer(randomBytes(32), 'hex');
    var public = secp256k1.publicKeyCreate(privateKey, false).slice(1);
    var address = formatAddress(publicToAddress(public).toString('hex'));
    var accountObject = {
        address : address,
        privateKey : privateKey.toString('hex'),
        public : public.toString('hex'),
        encrypted : false,
        locked : false

    };
    return accountObject
}

// @param {buffer}{Bytes(32)} msg
// @param {buffer}{Bytes(32)} pk
OG.prototype.signRawTransaction = function (msg,pk) {
    pk = new Buffer(pk, 'hex');
    msg  = new Buffer(msg, 'hex');
    var sig = secp256k1.sign(msg, pk);
    return sig;
};

var formatAddress = function(addr, format){
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

var publicToAddress = function(pubKey,sanitize){
    pubKey = exports.toBuffer(pubKey)
    if (sanitize && (pubKey.length !== 64)) {
      pubKey = secp256k1.publicKeyConvert(pubKey, false).slice(1)
    }
    assert(pubKey.length === 64)
    // Only take the lower 160bits of the hash
    return exports.keccak(pubKey).slice(-20)
}

exports.toBuffer = function (v) {
    if (!Buffer.isBuffer(v)) {
      if (Array.isArray(v)) {
        v = Buffer.from(v)
      } else if (typeof v === 'string') {
        if (exports.isHexString(v)) {
          v = Buffer.from(exports.padToEven(exports.stripHexPrefix(v)), 'hex')
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

  exports.keccak = function (a, bits) {
    a = exports.toBuffer(a)
    if (!bits) bits = 256
  
    return createKeccakHash('keccak' + bits).update(a).digest()
  }

// TODO JSONRPC

module.exports = OG;