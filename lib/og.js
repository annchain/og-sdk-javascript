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
var BN = require('bn.js');
Object.assign(exports, require('ethjs-util'));

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

OG.prototype.sync_status = function(){
    var url = this.currentProvider.host;
    var method = "/sync_status";
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

// @param {string} to
// @param {Number} value
// @param {string} PublicKey
// @param {Number} height
OG.prototype.genRawTransaction = function(to,value,publicKey,height){
    var tx = {};
    tx.From = formatAddress(publicToAddress(publicKey).toString('hex'));
    tx.To = to;
    tx.value = value;
    tx.TxBase = {};
    tx.TxBase.PublicKey = 'PublicKey';
    tx.TxBase.Height = height;
    return tx;
}

// @param {buffer}{Bytes(32)} msg
// @param {buffer}{Bytes(32)} pk
OG.prototype.signRawTransaction = function (msg,pk) {
    pk = new Buffer(pk, 'hex');
    msg  = new Buffer(msg, 'hex');
    var sig = secp256k1.sign(msg, pk);
    return sig;
};

// @param {string}{HEX format} code
OG.sendTransaction = function(code){
    return code;
}

// @param {object} tx
OG.sendRawTransaction = function(tx){
    return tx;
}

OG.prototype.toBuffer = function (v){
    return exports.toBuffer(v);
}

// @param {buffer}{ArrayBuffer} buffer
OG.prototype.buf2hex = function (buffer){
    return Array.prototype.map.call(new Uint8Array(buffer), x => ('00' + x.toString(16)).slice(-2)).join('');
}

// @param {hex} hex
OG.prototype.hextoString = function (hex){
    var arr = hex.split("");
    var out = "";
    for (var i = 0; i < arr.length / 2; i++) {
      var tmp = "0x" + arr[i * 2] + arr[i * 2 + 1];
      var charValue = String.fromCharCode(tmp);
      out += charValue;
    }
    return out;
}

// @param {string} str
OG.prototype.stringtoHex = function(string){
    var val = "";
    for (var i = 0; i < str.length; i++) {
      if (val == "")
        val = str.charCodeAt(i).toString(16);
      else
        val += str.charCodeAt(i).toString(16);
    }
    val += "0a";
    return val;
}

// @param {Number} i
OG.prototype.intToHex = function (i) {
    var hex = i.toString(16); // eslint-disable-line
  
    return `0x${hex}`;
  }

// @param {Number} i
OG.prototype.intToBuffer = function (i) {
    var hex = intToHex(i);
  
    return new Buffer(padToEven(hex.slice(2)), 'hex');
  }

//@param {String} string in hex
//@returns {String} ascii string representation of hex value
OG.prototype.toUtf8 = function (hex){
    var bufferValue = new Buffer(padToEven(stripHexPrefix(hex).replace(/^0+|0+$/g, '')), 'hex');

    return bufferValue.toString('utf8');
}

//@param {String} string in hex
//@returns {String} ascii string representation of hex value
OG.prototype.toAscii = function(hex){
    var str = ''; // eslint-disable-line
    var i = 0, l = hex.length; // eslint-disable-line
  
    if (hex.substring(0, 2) === '0x') {
      i = 2;
    }
  
    for (; i < l; i += 2) {
      const code = parseInt(hex.substr(i, 2), 16);
      str += String.fromCharCode(code);
    }
  
    return str;
}

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

/**
 * Converts a `Buffer` to a `Number`
 * @param {Buffer} buf
 * @return {Number}
 * @throws If the input number exceeds 53 bits.
 */
exports.bufferToInt = function (buf) {
    return new BN(exports.toBuffer(buf)).toNumber()
  }

/**
 * Converts a `Buffer` into a hex `String`
 * @param {Buffer} buf
 * @return {String}
 */
exports.bufferToHex = function (buf) {
    buf = exports.toBuffer(buf)
    return '0x' + buf.toString('hex')
  }

/**
 * Creates Keccak hash of the input
 * @param {Buffer|Array|String|Number} a the input data
 * @param {Number} [bits=256] the Keccak width
 * @return {Buffer}
 */
  exports.keccak = function (a, bits) {
    a = exports.toBuffer(a)
    if (!bits) bits = 256
  
    return createKeccakHash('keccak' + bits).update(a).digest()
  }

// TODO JSONRPC

module.exports = OG;