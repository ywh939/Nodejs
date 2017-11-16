var crypto = require('crypto');
var Config = require('../../config.js');

function getRandNum() {
    var nonce = parseInt( Math.random() * ((9999999999-1000000000)+1000000000));
    return nonce;
}

function getCurTimeSecStamp() {
    var ts = parseInt(Math.round(Date.now()/1000));
    return ts;
}

function decodeBase64(input) {
    var output = new Buffer(input, 'base64').toString();
    return output;
}

function genHashSign(signType, input, encodeType) {
    var signer = crypto.createHash(signType);
    signer.update(input);
    var output = signer.digest(encodeType);
    return output;
}

function genHmacSign(signType, key, input, encodeType) {
    var output = crypto.createHmac(signType, key).update(input).digest(encodeType);
    return output;
}

function genRSASign(signtype, input, key, encodetype) {
    var signer = crypto.createSign(signtype);
    signer.update(input);
    var safeSign = signer.sign(key, encodetype);
    return safeSign;
}

function checkVerifySign(verifyType, paramStr, key, sign, encodeType) {
    var verifier = crypto.createVerify(verifyType);
    verifier.update(paramStr);
    var result = verifier.verify(key, sign, encodeType);

    return result;
}

module.exports.getRandNum = getRandNum;
module.exports.getCurTimeSecStamp = getCurTimeSecStamp;
module.exports.decodeBase64 = decodeBase64;
module.exports.genHashSign = genHashSign;
module.exports.genHmacSign = genHmacSign;
module.exports.genRSASign = genRSASign;
module.exports.checkVerifySign = checkVerifySign;