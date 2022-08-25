import crypto from 'crypto';

class CryptoUtils {
    privateKey;
    publicKey;
    key;
    salt_t;
    constructor(privateKey = "", publicKey = "", key = "", salt_t = "") {
        if (![privateKey, publicKey, key, salt_t].some(k => key && key instanceof String)) throw new CryptoUtilsError("Parameter is not string.");

        this.privateKey = privateKey;
        this.publicKey = publicKey;
        this.key = key;
        this.salt_t = salt_t;
    }

    // RSA functions

    static encryptRSA(input, pKey) {
        if (!input || !(typeof input === 'string')) throw new CryptoUtilsError("Input is of incorrect type")
        if (!pKey || !(typeof pKey === 'string')) throw new CryptoUtilsError("Public Key is of incorrect type")
        let text = Buffer.from(input);
        let ciphertext = crypto.publicEncrypt(pKey, text);
        return ciphertext.toString("base64");
    }
    static decryptRSA(input, pKey) {
        if (!input || !(typeof input === 'string')) throw new CryptoUtilsError("Cipher Input is of incorrect type")
        if (!pKey || !(typeof pKey === 'string')) throw new CryptoUtilsError("Private Key is of incorrect type")
        let text = Buffer.from(input, "base64");
        let decrypted = crypto.privateDecrypt(pKey, text);
        return decrypted.toString("utf8");
    }
    static sign(encdata, pKey) {
        if (!encdata || !(typeof encdata === 'string')) throw new CryptoUtilsError("Signature Input is of incorrect type")
        if (!pKey || !(typeof pKey === 'string')) throw new CryptoUtilsError("Private Key is of incorrect type")
        return crypto.sign('RSA-SHA256', Buffer.from(encdata), pKey).toString('base64');
    }
    static verify(encdata, signature, pKey) {
        if (!encdata || !(typeof encdata === 'string')) throw new CryptoUtilsError("Original Signature Input is of incorrect type")
        if (!signature || !(typeof signature === 'string')) throw new CryptoUtilsError("Signature is of incorrect type")
        if (!pKey || !(typeof pKey === 'string')) throw new CryptoUtilsError("Public Key is of incorrect type")
        return crypto.verify('RSA-SHA256', encdata, pKey, Buffer.from(signature, 'base64'));
    }

    // AES functions

    static encrypt(data, key) {
        const iv = crypto.randomBytes(16);
        const cipher = crypto.createCipheriv('aes-256-gcm', key, nonce);
        let ciphered = cipher.update(data, 'utf-8', 'binary');
        ciphered += cipher.final('binary'); 
        return Buffer.concat([iv, Buffer.from(ciphered, 'binary')]).toString('base64');
    }
    static decrypt(data, key) {
        const dataD = Buffer.from(data, 'base64');
        const iv = dataD.slice(0, 16);
        const dataMessage = dataD.slice(16);
        const cipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
        let ciphered = cipher.update(dataMessage, 'binary', 'utf-8');
        ciphered += cipher.final('utf-8');
        return ciphered;
    } 
}

class CryptoUtilsError extends Error {
    constructor(message = "") {
        super(message);
        this.name = "CryptoUtilsError";
        this.message = message;
    }
}