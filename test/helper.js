'use strict'

const crypto = require('node:crypto')

function generateKeyPair () {
  const options = {
    modulusLength: 2048,
    publicExponent: 0x10001,
    publicKeyEncoding: {
      type: 'spki',
      format: 'pem'
    },
    privateKeyEncoding: {
      type: 'pkcs8',
      format: 'pem'
    }
  }
  return crypto.generateKeyPairSync('rsa', options)
}

function generateKeyPairProtected (passphrase) {
  const options = {
    modulusLength: 2048,
    publicExponent: 0x10001,
    publicKeyEncoding: {
      type: 'spki',
      format: 'pem'
    },
    privateKeyEncoding: {
      type: 'pkcs8',
      format: 'pem',
      cipher: 'aes-256-cbc',
      passphrase
    }
  }
  return crypto.generateKeyPairSync('rsa', options)
}

function withResolvers () {
  let promiseResolve, promiseReject
  const promise = new Promise((resolve, reject) => {
    promiseResolve = resolve
    promiseReject = reject
  })
  return { promise, resolve: promiseResolve, reject: promiseReject }
}

function generateKeyPairECDSA () {
  const options = {
    modulusLength: 2048,
    namedCurve: 'prime256v1',
    publicKeyEncoding: {
      type: 'spki',
      format: 'pem'
    },
    privateKeyEncoding: {
      type: 'pkcs8',
      format: 'pem'
    }
  }
  return crypto.generateKeyPairSync('ec', options)
}

function generateKeyPairECDSAProtected (passphrase) {
  const options = {
    modulusLength: 2048,
    namedCurve: 'prime256v1',
    publicKeyEncoding: {
      type: 'spki',
      format: 'pem'
    },
    privateKeyEncoding: {
      type: 'pkcs8',
      format: 'pem',
      cipher: 'aes-256-cbc',
      passphrase
    }
  }
  return crypto.generateKeyPairSync('ec', options)
}

module.exports = {
  generateKeyPair,
  generateKeyPairProtected,
  generateKeyPairECDSA,
  generateKeyPairECDSAProtected,
  withResolvers
}
