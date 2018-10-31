var OG = require('./index.js');

var og = new OG;

og.setProvider(new OG.providers.HttpProvider('http://localhost:8000'))

og.genesis().then(function(data){
    console.log('genesis',data);
});

og.net_info().then(function(data){
    console.log('net_info',data);
});

og.og_peers_info().then(function(data){
    console.log('og_peers_info',data);
});

og.peers_info().then(function(data){
    console.log('peers_info',data);
});

og.sequencer().then(function(data){
    console.log('sequencer',data);
});

og.status().then(function(data){
    console.log('status',data);
});

og.validators().then(function(data){
    console.log('validators',data);
});
