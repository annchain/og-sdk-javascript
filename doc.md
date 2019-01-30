# **JS-OG-SDK Document** 

## **SET PROVIDER**
Set the connection

**Parameter**:  

| Parameter | Type | Required | Remark
| --- | --- | --- | ---
| URL | string | yes | the URL of connection

**Constructor**
```js
og.setProvider(
    new OG.providers.HttpProvider(URL)
);
```
---
## **NET INFO**
**Method**:
```js
og.net_info()
```
**Return**:
```json
{ "data":
   { "id": "cf6b7187767f9dab5e71110f6fc36c...b0803c4d7374e2b189d89ee168c3e1f7ad4e834008ffb9a",
     "short_id": "cf6b7...f9dab",
     "name": "og",
     "enode": "enode://cf6b7187767f9d...168c3e1f7ad4e834008ffb9a@[::]:8001",
     "ip": "::",
     "ports": { 
        "discovery": 8001,
        "listener": 8001 
     },
     "listenAddr": "[::]:8001",
     "protocols": { og: [Object] } 
   },
    "message": ""
}
```
---
## **OG PEER INFO**
**Method**:
```js
og.og_peer_info()
```
**Return**:
```json
{
    "data":[],
    "message":""
}
```
---
## **PEER INFO**
**Method**:
```js
og.peer_info()
```
**Return**:
```json
{
    "data":[],
    "message":""
}
```
---
## **GENESIS**
**Methods**
```js
og.genesis()
```
**Return**:
```json
{ "data":
   { "Type": 1,
     "Hash": "0x1dfb6fea83e3d62...3ba4f98c80ae0ea9e3db97d3736e",
     "ParentsHash": null,
     "AccountNonce": 0,
     "Height": 0,
     "PublicKey": "s+G4MG4bqxXtUaTCS...KHE55jfTFL8NYcudHH7g==",
     "Signature": "MEQCIBIwK9fJUfy/7...iBCTXEC2on0R7KMU6rjiKzwulcAjIBI9eNNwRdlscq39g==",
     "MineNonce": 0,
     "Id": 0,
     "Issuer": "0x0000000000000000000000000000000000000000",
     "ContractHashOrder": [] 
   },
    "message": ""
}
```
---
## **SEQUENCER**
**Method**:
```js
og.sequencer()
```
**Return**:
```json
{ "data":
   { "Type": 1,
     "Hash": "0x958d9e9fdb93...389e66ee24e1d1708e3",
     "ParentsHash":
      [ "0xfa031a8c3c790...35f775f5ccc25cf4389",
        "0x2fd14e4348de6...52257727bfdf6502c80" ],
     "AccountNonce": 2386,
     "Height": 116,
     "PublicKey": "BIDG6ARHwZsp...wqi0xkXyXnI10gHt8RtnRHzrI=",
     "Signature": "R7iqPg4VioLn...788kvk0sSlUTxCpSjw8cIcSwA=",
     "MineNonce": 1,
     "Id": 116,
     "Issuer": "0x7349f7a6f622378d5fb0e2c16b9d4a3e5237c187",
     "ContractHashOrder": [] 
   },
    "message": "" 
}
```
---
## **STATUS**
**Method**:
```js
og.status()
```
**Return**:
```json
{ "data":
   { "node_info":
      { "id": "cf6b7187767f9...b0803c4d7374e2b189d89ee168c3e1f7ad4e834008ffb9a",
        "short_id": "cf6b7187767f9dab",
        "name": "og",
        "enode": "enode://cf6b718776...46b04e834008ffb9a@[::]:8001",
        "ip": "::",
        "ports": [Object],
        "listenAddr": "[::]:8001",
        "protocols": [Object] 
      },
     "peers_info": [] 
   },
    "message": "" 
}
```
---
## **ACCOUNT BALANCE**
**Method**:
```js
og.getBalance(address).then(function(data){});
```
**Parameter**:  

| Parameter | Type | Required | Remark
| --- | --- | --- | ---
| address | string | yes | the address balance you want to query

**Return**:
```json
{ "data":
   { "address": "0x50c184bd1d896b5050dbb2c04f8fce2fc039f267",
     "balance": "0" 
   },
  "message": "" 
}
```
---
## **ACCOUNT NONCE**
**Method**:
```js
og.getNonce(address).then(function(data){});
```
**Parameter**:  

| Parameter | Type | Required | Remark
| --- | --- | --- | ---
| address | string | yes | the address nonce you want to query

**Return**:
```json
{ 
    "data": -1,
    "message": "" 
}
```
---
## **TRANSACTION RECEIPT**
**Method**:
```js
og.getReceipt(hash).then(function(data){});
```
**Parameter**:  

| Parameter | Type | Required | Remark
| --- | --- | --- | ---
| hash | string | yes | the transaction hash you want to query

**Return**:
```json
{ "data":
   { "tx_hash": "0x0187627b7585ff993bcaad3155ba5fbf1768899ec6de17b92bc01c48471e39d8",
     "status": 1,
     "result": "",
     "contract_address": "0x0000000000000000000000000000000000000000"
    },
  "message": "" 
}
```
---
## **GET TRANSACTION**
**Method**:
```js
og.getTransaction(hash).then(function(data){});
```
**Parameter**:  

| Parameter | Type | Required | Remark
| --- | --- | --- | ---
| hash | string | yes | the transaction hash you want to query

**Return**:
```json
{ "data":
   { "Type": 0,
     "Hash": "0x0187627b7585ff99...9ec6de17b92bc01c48471e39d8",
     "ParentsHash":
      [ "0xc6adf0300799d6...23ab0ac4d24fdb8becd966d78",
        "0x8d44c04d5387bd...f4a3ab9869f8a5e58f44c9c7a" ],
     "AccountNonce": 8061,
     "Height": 417,
     "PublicKey": "BKVH401d4INGypO...IoJGIkRt5Rk+eGR+I=",
     "Signature": "fh1p/58PRiZuafN...Ve9AaKtZcAOgjiFgE=",
     "MineNonce": 1,
     "From": "0x96f4ac2f321...1f268f6f1d5406",
     "To": "0x4a10e5baa3325...d92a011ef312",
     "Value": "0",
     "Data": null 
   },
  "message": "" 
}
```
---
## **TRANSACTION CONFIRMATION**
**Method**:
```js
og.confirm(hash).then(function(data){});
```
**Parameter**:  

| Parameter | Type | Required | Remark
| --- | --- | --- | ---
| hash | string | yes | the transaction hash you want to query

**Return**:
```json
{ 
    "data": true,
    "message": "" 
}
```
---
## **NEW ACCOUNT**
**Method**:
```js
og.newAccount()
```
**Return**:
```json
{ 
    "address": "0x54e50d4fba...4fbd71544096",
    "privateKey": "ddc0fd455b01f4dc...756ad5b5f272e5ce2b634eb8d",
    "public_raw": "04156d87d306421f363...49f6a81b7dcc1acd3eda523d4231b844235b92af26",
    "public": "156d87d306421f3636035c69a3...49f6a81b7dcc1acd3eda523d4231b844235b92af26",
    "encrypted": false,
    "locked": false 
}
```
---
## **RECOVERY ACCOUNT**
**Method**:
```js
og.recoveryAccount(privateKey)
```
**Parameter**:  

| Parameter | Type | Required | Remark
| --- | --- | --- | ---
| privateKey | string | yes |

**Return**:
```json
{ 
    "address": "0x54e50d4fba...4fbd71544096",
    "privateKey": "ddc0fd455b01f4dc...756ad5b5f272e5ce2b634eb8d",
    "public_raw": "04156d87d306421f363...49f6a81b7dcc1acd3eda523d4231b844235b92af26",
    "public": "156d87d306421f3636035c69a3...49f6a81b7dcc1acd3eda523d4231b844235b92af26",
    "encrypted": false,
    "locked": false 
}
```
---
## **inspect 0x**
**Method**:
```js
og.inspect_0x(str)
```
**Parameter**:  

| Parameter | Type | Required | Remark
| --- | --- | --- | ---
| str | string | yes |

---
## **CREATE NEW TRANSACTION**
**Method**:
```js
og.genRawTransaction(txParams)
```
**Parameter**:  

| Parameter | Type | Required | Remark
| --- | --- | --- | ---
| txParams | object | yes |
| txParams.nonce | int string | yes |
| txParams.from | hex string | yes |
| txParams.to | hex string | no | can be null when creat a contract
| txParams.value | int string | yes | 
| txParams.pubkey | hex string | yes |
| txParams.data | hex string | no | 

**Example**:  
```js
txParams = {
 	"nonce":1,
 	"from":"0x61a74d3f7f8e24b5d46ef4cffb421c3fa3a483dd",
 	"to":"0xa7656df695f2e74b060e3c9a3c8e425cf2107c25",
 	"value":10,
    "height":2,
  	"pubkey":"0x01969b0aa2a95da2f17a7ddfdad63839cf07c811b6fa122080c3e12d7fde9eb4a40bab371f97a6ca932186a75d3a56c99ebaf6f7b994045f5122cc5bebcf7ea9ae",
    "publicKey_raw" : "0x0104969b0aa2a95da2f17a7ddfdad63839cf07c811b6fa122080c3e12d7fde9eb4a40bab371f97a6ca932186a75d3a56c99ebaf6f7b994045f5122cc5bebcf7ea9ae",
};
```
**Return**:
```
<Buffer 81 0c b7 39 ea 1e 5c c0 75 55 d7 8a 78 3f 8d ef 67 5b b3 6a c8 b7 e9 09 74 38 81 a7 9f 07 56 88>
to string hex:
810cb739ea1e5cc07555d78a783f8def675bb36ac8b7e909743881a79f075688
```
---
## **SIGN TRANSACTION**
**Method**:
```js
og.signRawTransaction(signTarget)
```
**Parameter**:  
| Parameter | Type | Required | Remark
| --- | --- | --- | ---
| signTarget | string | yes | generate by og.genRawTransaction()

**Example**:  
see example.js
**Return**:
```
<Buffer 32 d5 98 9c eb 13 52 03 0a cd b2 6d 96 d5 ab 45 8b 54 f5 df 56 5f 05 d9 d6 93 77 fc 3b 72 0a aa 6e d7 98 28 6f92 28 05 19 6b 6a 88 ec b3 ce c4 0f 0f ... >
to string hex:
32d5989ceb1352030acdb26d96d5ab458b54f5df565f05d9d69377fc3b720aaa6ed798286f922805196b6a88ecb3cec40f0fa937ed79070d79a23812355e8b5d
```
---
## **MAKE UP TRANSACTION**
**Method**:
```js
og.makeUpTransaction(txParams, signature)
```
**Parameter**:  
| Parameter | Type | Required | Remark
| --- | --- | --- | ---
| txParams | object | yes | same as og.genRawTransaction() parameter
| signature | string | yes | generate by og.signRawTransaction

**Example**:  
see example.js
**Return**:
```json
{
        "nonce" : 0,
        "from" : "0x96f4ac2f321...1f268f6f1d5406",
        "to" : "0x4a10e5baa3325...d92a011ef312",
        "value" : 10,
        "signature": "32d5989ceb1352030acdb26d96d5ab458b54f5df565f05d9d69377fc3b720aaa6ed798286f922805196b6a88ecb3cec40f0fa937ed79070d79a23812355e8b5d",
        "pubkey": "BKVH401d4INGypO...IoJGIkRt5Rk+eGR+I=" 
}
```
---
## **SEND TRANSACTION**
**Method**:
```js
og.sendTransaction(tx)
```
**Parameter**:  
| Parameter | Type | Required | Remark
| --- | --- | --- | ---
| tx | object | yes | generate by og.makeUpTransaction()

**Return**:
```json
{
    "data":"0xb4d525888e28119419f8ad1ccb837d899c17c1680f3bb4cb184471313439f570",
    "message":""
}
```
---
## **PUBLIC TO ADDRESS**
**Method**:
```js
og.publicToAddress(pubKey, [sanitize])
```
| Parameter | Type | Required | Remark
| --- | --- | --- | ---
| pubKey | string | yes | 
| sanitize | boolean | no

**Return**:
```
<Buffer 70 95 00 b3 73 d7 1d 15 39 09 4b 26 f8 45 85 41 79 04 75 c4>
to string hex
709500b373d71d1539094b26f8458541790475c4
```
---
## **to buffer**
**Method**:
```js
og.toBuffer(param)
```
| Parameter | Type | Required | Remark
| --- | --- | --- | ---
| param | Buffer\Array\String\Number | yes | 

**Return**:
```
<Buffer>
```
---
## **sha256**
**Method**:
```js
og.sha256(param)
```
| Parameter | Type | Required | Remark
| --- | --- | --- | ---
| param | Buffer\Array\String\Number | yes | 

**Return**:
```
<Buffer>
```
---
## **buffer to hex**
**Method**:
```js
og.buf2hex(buf)
```
| Parameter | Type | Required | Remark
| --- | --- | --- | ---
| buf | Buffer | yes |

**Return**:
```
<hex>
```
---