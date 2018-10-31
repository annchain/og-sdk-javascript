// var utils = require('../../utils/utils');
var Property = require('../property');

var Net = function (og) {
    this._requestManager = og._requestManager;
    var self = this;

    properties().forEach(function(p) { 
        p.attachToObject(self);
        p.setRequestManager(og._requestManager);
    });
};

var properties = function () {
    return [
        new Property({
            name: 'net_info',
            getter: 'net_info'
        })
    ];
};

module.exports = Net;