'use strict';

Object.defineProperty(exports, '__esModule', { value: true });

function _interopDefault (ex) { return (ex && (typeof ex === 'object') && 'default' in ex) ? ex['default'] : ex; }

var isBuffer = _interopDefault(require('is-buffer'));
var stripHexPrefix = _interopDefault(require('strip-hex-prefix'));
var assert = _interopDefault(require('assert'));
var ethUtil = _interopDefault(require('ethereumjs-util'));

var blockNumberLength = 4;
var txNumberLength = 4;
var txTypeLength = 1;
var signatureVlength = 1;
var signatureRlength = 32;
var signatureSlength = 32;
var merkleRootLength = 32;
var previousHashLength = 32;
var txOutputNumberLength = 1;
var txAmountLength = 32;
var txToAddressLength = 20;

/* Copyright 2017 Tierion
* Licensed under the Apache License, Version 2.0 (the "License")
* you may not use this file except in compliance with the License.
* You may obtain a copy of the License at
*     http://www.apache.org/licenses/LICENSE-2.0
* Unless required by applicable law or agreed to in writing, software
* distributed under the License is distributed on an "AS IS" BASIS,
* WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
* See the License for the specific language governing permissions and
* limitations under the License.
*/

var sha3512 = require('js-sha3').sha3_512;
var sha3384 = require('js-sha3').sha3_384;
var sha3256 = require('js-sha3').sha3_256;
var sha3224 = require('js-sha3').sha3_224;
var crypto = require('crypto');
var ethUtil$1 = require('ethereumjs-util');

var MerkleTools = function (treeOptions) {
  // in case 'new' was omitted
  if (!(this instanceof MerkleTools)) {
    return new MerkleTools(treeOptions)
  }

  var hashType = 'sha256';
  if (treeOptions) { // if tree options were supplied, then process them
    if (treeOptions.hashType !== undefined) { // set the hash function to the user's choice
      hashType = treeOptions.hashType;
    }
  }

  var hashFunction = function (value) {
    switch (hashType) {
      case 'SHA3-224':
        return new Buffer(sha3224.array(value))
      case 'SHA3-256':
        return new Buffer(sha3256.array(value))
      case 'SHA3-384':
        return new Buffer(sha3384.array(value))
      case 'SHA3-512':
        return new Buffer(sha3512.array(value))
      case 'sha3':
        return ethUtil$1.sha3(value, 256)  
      default:
        return crypto.createHash(hashType).update(value).digest()
    }
  };

  var tree = {};
  tree.leaves = [];
  tree.levels = [];
  tree.isReady = false;

  /// /////////////////////////////////////////
  // Public Primary functions
  /// /////////////////////////////////////////

  // Resets the current tree to empty
  this.resetTree = function () {
    tree = {};
    tree.leaves = [];
    tree.levels = [];
    tree.isReady = false;
  };

  // Add a leaf to the tree
  // Accepts hash value as a Buffer or hex string
  this.addLeaf = function (value, doHash) {
    tree.isReady = false;
    if (doHash) value = hashFunction(value);
    tree.leaves.push(_getBuffer(value));
  };

  // Add a leaves to the tree
  // Accepts hash values as an array of Buffers or hex strings
  this.addLeaves = function (valuesArray, doHash) {
    tree.isReady = false;
    valuesArray.forEach(function (value) {
      if (doHash) value = hashFunction(value);
      tree.leaves.push(_getBuffer(value));
    });
  };

  // Returns a leaf at the given index
  this.getLeaf = function (index) {
    if (index < 0 || index > tree.leaves.length - 1) return null // index is out of array bounds

    return tree.leaves[index]
  };

  // Returns the number of leaves added to the tree
  this.getLeafCount = function () {
    return tree.leaves.length
  };

  // Returns the ready state of the tree
  this.getTreeReadyState = function () {
    return tree.isReady
  };

  // Generates the merkle tree
  this.makeTree = function (doubleHash) {
    tree.isReady = false;
    var leafCount = tree.leaves.length;
    if (leafCount > 0) { // skip this whole process if there are no leaves added to the tree
      tree.levels = [];
      tree.levels.unshift(tree.leaves);
      while (tree.levels[0].length > 1) {
        tree.levels.unshift(_calculateNextLevel(doubleHash));
      }
    }
    tree.isReady = true;
  };

  // Generates the merkle tree Plasma style
  this.makePlasmaTree = function (paddingBuffer) {
    tree.isReady = false;
    var leafCount = tree.leaves.length;
    if (leafCount > 0) { // skip this whole process if there are no leaves added to the tree
      tree.levels = [];
      tree.levels.unshift(tree.leaves);
      while (tree.levels[0].length > 1) {
        tree.levels.unshift(_calculatePlasmaNextLevel(paddingBuffer));
      }
    }
    tree.isReady = true;
  };

  // Generates a Bitcoin style merkle tree
  this.makeBTCTree = function (doubleHash) {
    tree.isReady = false;
    var leafCount = tree.leaves.length;
    if (leafCount > 0) { // skip this whole process if there are no leaves added to the tree
      tree.levels = [];
      tree.levels.unshift(tree.leaves);
      while (tree.levels[0].length > 1) {
        tree.levels.unshift(_calculateBTCNextLevel(doubleHash));
      }
    }
    tree.isReady = true;
  };

  // Returns the merkle root value for the tree
  this.getMerkleRoot = function () {
    if (!tree.isReady || tree.levels.length === 0) return null
    return tree.levels[0][0]
  };

  // Returns the proof for a leaf at the given index as an array of merkle siblings in hex format
  this.getProof = function (index, asBinary) {
    if (!tree.isReady) return null
    var currentRowIndex = tree.levels.length - 1;
    if (index < 0 || index > tree.levels[currentRowIndex].length - 1) return null // the index it out of the bounds of the leaf array

    var proof = [];
    for (var x = currentRowIndex; x > 0; x--) {
      var currentLevelNodeCount = tree.levels[x].length;
            // skip if this is an odd end node
      if (index === currentLevelNodeCount - 1 && currentLevelNodeCount % 2 === 1) {
        index = Math.floor(index / 2);
        continue
      }

            // determine the sibling for the current index and get its value
      var isRightNode = index % 2;
      var siblingIndex = isRightNode ? (index - 1) : (index + 1);

      if (asBinary) {
        proof.push(new Buffer(isRightNode ? [0x00] : [0x01]));
        proof.push(tree.levels[x][siblingIndex]);
      } else {
        var sibling = {};
        var siblingPosition = isRightNode ? 'left' : 'right';
        var siblingValue = tree.levels[x][siblingIndex].toString('hex');
        sibling[siblingPosition] = siblingValue;

        proof.push(sibling);
      }

      index = Math.floor(index / 2); // set index to the parent index
    }

    return proof
  };

  // Takes a proof array, a target hash value, and a merkle root
  // Checks the validity of the proof and return true or false
  this.validateProof = function (proof, targetHash, merkleRoot) {
    targetHash = _getBuffer(targetHash);
    merkleRoot = _getBuffer(merkleRoot);
    if (proof.length === 0) return targetHash.toString('hex') === merkleRoot.toString('hex') // no siblings, single item tree, so the hash should also be the root

    var proofHash = targetHash;
    for (var x = 0; x < proof.length; x++) {
      if (proof[x].left) { // then the sibling is a left node
        proofHash = hashFunction(Buffer.concat([_getBuffer(proof[x].left), proofHash]));
      } else if (proof[x].right) { // then the sibling is a right node
        proofHash = hashFunction(Buffer.concat([proofHash, _getBuffer(proof[x].right)]));
      } else { // no left or right designation exists, proof is invalid
        return false
      }
    }

    return proofHash.toString('hex') === merkleRoot.toString('hex')
  };

  // Takes a proof buffer, a target hash value, and a merkle root
  // Checks the validity of the proof and return true or false
  this.validateBinaryProof = function (proof, targetHash, merkleRoot) {
    targetHash = _getBuffer(targetHash);
    merkleRoot = _getBuffer(merkleRoot);
    proof = _getBuffer(proof);
    if (proof.length === 0) return targetHash.toString('hex') === merkleRoot.toString('hex') // no siblings, single item tree, so the hash should also be the root

    var proofHash = targetHash;
    var elements = proof.length / 33;
    var zero = Buffer.alloc(1);
    var one = Buffer.from("01", 'hex');
    for (var x = 0; x < elements; x++) {
      var subProof = proof.slice(x*33, (x+1)*33);
      var leftOrRight = subProof.slice(0, 1);
      var element = subProof.slice(1, 33);
      if (leftOrRight.equals(zero)) { // then the sibling is a left node
        proofHash = hashFunction(Buffer.concat([element, proofHash]));
      } else if (leftOrRight.equals(one)) { // then the sibling is a right node
        proofHash = hashFunction(Buffer.concat([proofHash, element]));
      } else { // no left or right designation exists, proof is invalid
        return false
      }
    }

    return proofHash.toString('hex') === merkleRoot.toString('hex')
  };

  /// ///////////////////////////////////////
  // Private Utility functions
  /// ///////////////////////////////////////

  // Internally, trees are made of nodes containing Buffer values only
  // This helps ensure that leaves being added are Buffers, and will convert hex to Buffer if needed
  function _getBuffer (value) {
    if (value instanceof Buffer) { // we already have a buffer, so return it
      return value
    } else if (_isHex(value)) { // the value is a hex string, convert to buffer and return
      return new Buffer(value, 'hex')
    } else { // the value is neither buffer nor hex string, will not process this, throw error
      throw new Error("Bad hex value - '" + value + "'")
    }
  }

  function _isHex (value) {
    var hexRegex = /^[0-9A-Fa-f]{2,}$/;
    return hexRegex.test(value)
  }

  // Calculates the next level of node when building the merkle tree
  // These values are calcalated off of the current highest level, level 0 and will be prepended to the levels array
  function _calculateNextLevel (doubleHash) {
    var nodes = [];
    var topLevel = tree.levels[0];
    var topLevelCount = topLevel.length;
    for (var x = 0; x < topLevelCount; x += 2) {
      if (x + 1 <= topLevelCount - 1) { // concatenate and hash the pair, add to the next level array, doubleHash if requested
        if (doubleHash) {
          nodes.push(hashFunction(hashFunction(Buffer.concat([topLevel[x], topLevel[x + 1]]))));
        } else {
          nodes.push(hashFunction(Buffer.concat([topLevel[x], topLevel[x + 1]])));
        }
      } else { // this is an odd ending node, promote up to the next level by itself
        nodes.push(topLevel[x]);
      }
    }
    return nodes
  }

  // This version uses the BTC method of duplicating the odd ending nodes
  function _calculateBTCNextLevel (doubleHash) {
    var nodes = [];
    var topLevel = tree.levels[0];
    var topLevelCount = topLevel.length;
    if (topLevelCount % 2 === 1) { // there is an odd count, duplicate the last element
      topLevel.push(topLevel[topLevelCount - 1]);
    }
    for (var x = 0; x < topLevelCount; x += 2) {
      // concatenate and hash the pair, add to the next level array, doubleHash if requested
      if (doubleHash) {
        nodes.push(hashFunction(hashFunction(Buffer.concat([topLevel[x], topLevel[x + 1]]))));
      } else {
        nodes.push(hashFunction(Buffer.concat([topLevel[x], topLevel[x + 1]])));
      }
    }
    return nodes
  }

  function _calculatePlasmaNextLevel (paddingBuffer) {
    var nodes = [];
    var topLevel = tree.levels[0];
    var topLevelCount = topLevel.length;
    if (topLevelCount % 2 === 1) { // there is an odd count, duplicate the last element
      topLevel.push(hashFunction(paddingBuffer));
    }
    for (var x = 0; x < topLevelCount; x += 2) {
      // concatenate and hash the pair, add to the next level array, doubleHash if requested
        nodes.push(hashFunction(Buffer.concat([topLevel[x], topLevel[x + 1]])));
    }
    return nodes
  }
};

function defineProperties(self, fields, data_) {
  self._raw = [];
  self._fields = [];
  self._classes = [];
  self._isArray = [];

  /**
   * Computes a sha3-256 hash of the serialized object
   * @return {Buffer}
   */
  self.hash = function () { 
    const rlpEncoded = self.rlpEncode();
    return ethUtil.hashPersonalMessage(rlpEncoded)
  };

  // attach the `toJSON`
  self.toJSON = function (label) {
    if (label) {
      const obj = {};
      self._fields.forEach(function (field) {
        if (!self[field] || typeof self[field] === "undefined"){
          return
        }
        if (isBuffer(self[field])) {
          obj[field] = '0x' + self[field].toString('hex');
          return
        } else if (self[field].toJSON !== undefined) {
          obj[field] = '0x' + self[field].toJSON(label);
          return
        }
      });
      return obj
    }
    return ethUtil.baToJSON(self._raw)
  };

  self.serialize = function serialize () {
    return self.rlpEncode()
  };

  self.rlpEncode = function rlpEncode() {
    return ethUtil.rlp.encode(self.raw)
  };

  Object.defineProperty(self, 'raw', {
    enumerable: true,
    configurable: false,
    get: function() {
      const toReturn = [];
      self._raw.forEach(function (rawItem, i) {
        if (isBuffer(self._raw[i])) {
          toReturn.push(self._raw[i]);
        } else if (self._raw[i].constructor.name === "Array") {
          const items = [];
          self._raw[i].forEach(function(subitem, j) {
            if (subitem.raw !== undefined) {
              items.push(subitem.raw);
            } else {
              items.push(subitem);
            }
          });
          toReturn.push(items);
        } else if (self._raw[i].raw !== undefined) {
          toReturn.push(self._raw[i].raw);
        } else {
          throw Error("Error")
        }
      });
      return toReturn
    }
  });

  fields.forEach(function (field, i) {
    self._fields.push(field.name);
    self._classes.push(field.class);
    const isArray = field.array ? true: false;
    self._isArray.push(isArray);
    const envelope = field.envelope ? true : false; 

    function getter () {
        return self._raw[i]
    }
    function setter (v_) {
      let v = v_;
      if (envelope) {
        if (isArray) {
          assert(v.constructor.name === "Array", 'The field ' + field.name + ' must be an array');
        }
        self._raw[i] = v;
        return
      }

      let vBuffer = ethUtil.toBuffer(v);

      if (vBuffer.toString('hex') === '00' && !field.allowZero) {
        vBuffer  = Buffer.alloc(0);
      }

      if (field.allowLess && field.length !== undefined) {
        const strippedvBuffer = ethUtil.stripZeros(vBuffer);
        self._raw[i] = strippedvBuffer;
        assert(field.length >= v.length, 'The field ' + field.name + ' must not have more ' + field.length + ' bytes');
      } else if (!(field.allowZero && vBuffer.length === 0) && field.length !== undefined) {
        assert(field.length === vBuffer.length, 'The field ' + field.name + ' must have byte length of ' + field.length);
        self._raw[i] = vBuffer;
      }
    }

    Object.defineProperty(self, field.name, {
      enumerable: true,
      configurable: true,
      get: getter,
      set: setter
    });

    if (field.default) {
      self[field.name] = field.default;
    }

    // attach alias
    if (field.alias) {
      Object.defineProperty(self, field.alias, {
        enumerable: false,
        configurable: true,
        set: setter,
        get: getter
      });
    }
  });

  // if the constuctor is passed data
  if (data_ !== undefined) {
    let data = data_;
    if (typeof data === 'string' || isBuffer(data)) {
      data = ethUtil.rlp.decode(data);
    }

    if (Array.isArray(data)) {
      if (data.length > self._fields.length) {
        throw (new Error('wrong number of fields in data'))
      }

      // make sure all the items are buffers
      data.forEach(function (d, i) {
          if (typeof self._classes[i] !== "undefined") {
              if (self._isArray[i]) {
                  const decoded = d;
                  const fieldArray = [];
                  decoded.forEach(function(elem) {
                      let cl = self._classes[i];
                      fieldArray.push(new cl(elem));
                  });
                  self[self._fields[i]] = fieldArray;
              } else {
                  let cl = self._classes[i];
                  self[self._fields[i]] = new cl(d);
              }
          } else {
              self[self._fields[i]] = ethUtil.toBuffer(d);
          }
      });
    } else if (typeof data === 'object') {
      const keys = Object.keys(data);
      fields.forEach(function (field) {
        if (keys.indexOf(field.name) !== -1) self[field.name] = data[field.name];
        if (keys.indexOf(field.alias) !== -1) self[field.alias] = data[field.alias];
      });
    } else {
      throw new Error('invalid data')
    }
  }
}

const BN = ethUtil.BN;

// secp256k1n/2
const N_DIV_2 = new BN('7fffffffffffffffffffffffffffffff5d576e7357a4501ddfe92f46681b20a0', 16);

class TransactionInput {
  constructor (data) {
    data = data || {};
    // Define Properties
    const fields = [{
      name: 'blockNumber',
      alias: 'block',
      allowZero: true,
      length: blockNumberLength,
      allowLess: false,
      default: Buffer.alloc(blockNumberLength)
    }, {
      name: 'txNumberInBlock',
      allowZero: true,
      alias: 'txNum',
      length: txNumberLength,
      allowLess: false,
      default: Buffer.alloc(txNumberLength)
    }, {
      name: 'outputNumberInTransaction',
      allowZero: true,
      alias: 'outputNum',
      length: txOutputNumberLength,
      allowLess: false,
      default: Buffer.alloc(txOutputNumberLength)
    }, 
    // {
    //   name: 'assetID',
    //   allowZero: true,
    //   alias: 'asset',
    //   length: 4,
    //   allowLess: false,
    //   default: Buffer.alloc(4)
    // }, 
    {
      name: 'amountBuffer',
      allowZero: true,
      alias: 'valueBuffer',
      length: txAmountLength,
      allowLess: false,
      default: Buffer.alloc(txAmountLength)
    }];

     defineProperties(this, fields, data);

    /**
     * @property {BigNumber} from (read only) amount of this transaction, mathematically derived from other parameters.
     * @name from
     * @memberof Transaction
     */
    Object.defineProperty(this, 'value', {
        enumerable: true,
        configurable: true,
        get: (() => new BN(this.valueBuffer)) 
    });
  }

  getUTXOnumber() {
    const blockNumber = new BN(this.blockNumber);
    const txNumberInBlock = new BN(this.txNumberInBlock);
    const outputNumberInTransaction = new BN(this.outputNumberInTransaction);
    const utxoNum = blockNumber.ushln((txOutputNumberLength + txNumberLength)*8);
    utxoNum.iadd(txNumberInBlock.ushln(txOutputNumberLength*8));
    utxoNum.iadd(outputNumberInTransaction);
    return utxoNum
  }
  
  toFullJSON(labeled) {
    if (labeled) {
      const blockNumber = ethUtil.bufferToInt(this.blockNumber);
      const txNumberInBlock = ethUtil.bufferToInt(this.txNumberInBlock);
      const outputNumberInTransaction = ethUtil.bufferToInt(this.outputNumberInTransaction);
      const value = this.value.toString(10);
      const obj = {
        blockNumber,
        txNumberInBlock,
        outputNumberInTransaction,
        value
      };
      return obj
    } else {
      return ethUtil.baToJSON(this.raw)
    }
  }
}
  
const dummy = new TransactionInput();
const transactionInputLength = dummy.rlpEncode().length;

const BN$1 = ethUtil.BN;

// secp256k1n/2
const N_DIV_2$1 = new BN$1('7fffffffffffffffffffffffffffffff5d576e7357a4501ddfe92f46681b20a0', 16);

class TransactionOutput {
  constructor (data) {
    data = data || {};
    // Define Properties
    const fields = [
      // {
      // name: 'assetID',
      // allowZero: true,
      // alias: 'asset',
      // length: 4,
      // allowLess: false,
      // default: Buffer.alloc(4)
      // }, 
      {
      name: 'outputNumberInTransaction',
      allowZero: true,
      alias: 'outputNum',
      length: txOutputNumberLength,
      allowLess: false,
      default: Buffer.alloc(txOutputNumberLength)
      },
      {
      name: 'to',
      allowZero: true,
      alias: 'recipient',
      length: txToAddressLength,
      allowLess: false,
      default: Buffer.alloc(txToAddressLength)
      }, 
      {
      name: 'amountBuffer',
      allowZero: true,
      alias: 'valueBuffer',
      length: txAmountLength,
      allowLess: false,
      default: Buffer.alloc(txAmountLength)
    }];

    defineProperties(this, fields, data);

    /**
     * @property {BigNumber} from (read only) amount of this transaction, mathematically derived from other parameters.
     * @name from
     * @memberof Transaction
     */
    Object.defineProperty(this, 'value', {
      enumerable: true,
      configurable: true,
      get: (() => new BN$1(this.valueBuffer)) 
    });

    Object.defineProperty(this, 'length', {
      enumerable: true,
      configurable: true,
      get: (() =>  Buffer.concat(this.raw).length) 
    });
  }

  getKey() {
    if(this._key) {
      return this._key
    }
    this._key = Buffer.concat(this.raw.slice(0,2)).toString('hex');
    return this._key
  }

  toFullJSON(labeled) {
    if (labeled) {
      let to = ethUtil.bufferToHex(this.to);
      to = ethUtil.toChecksumAddress(to);
      const outputNumberInTransaction = ethUtil.bufferToInt(this.outputNumberInTransaction);
      const value = this.value.toString(10);
      const obj = {
        to,
        outputNumberInTransaction,
        value
      };
      return obj
    } else {
      return ethUtil.baToJSON(this.raw)
    }
  }
}

const dummy$1 = new TransactionOutput();
const transactionOutputLength = dummy$1.rlpEncode().length;

const BN$2 = ethUtil.BN;

const ZERO = new BN$2(0);
const ZEROADDRESS = Buffer.alloc(txToAddressLength);
const ZEROADDRESShex = ethUtil.bufferToHex(ZEROADDRESS);

const TxTypeNull = 0;
const TxTypeSplit = 1;
const TxTypeMerge = 2;
const TxTypeFund = 4;

// secp256k1n/2
const N_DIV_2$2 = new BN$2('7fffffffffffffffffffffffffffffff5d576e7357a4501ddfe92f46681b20a0', 16);

class PlasmaTransaction {
  constructor (data) {
    data = data || {};
    // Define Properties
    const fields = [{
      name: 'transactionType',
      alias: 'txType',
      length: txTypeLength,
      allowLess: false,
      allowZero: true,
      default: Buffer.alloc(txTypeLength)
    }, {
      name: 'inputs',
      envelope: true,
      array: true,
      class: TransactionInput
    }, {
      name: 'outputs',
      envelope: true,
      array: true,
      class: TransactionOutput
    }];

    defineProperties(this, fields, data);
  }

  // /**
  //  * If the tx's `to` is to the creation address
  //  * @return {Boolean}
  //  */
  // toWithdrawAddress () {
  //   return  this.outputs[0].to.toString('hex') === '' &&
  //           this.outputs[0].amoutBuffer.toString('hex') === '' &&
  //           this.transactionTypeUInt() == TxTypeWithdraw
  // }

  /**
   * If the tx's `from` is from the creation address
   * @return {Boolean}
   */
  fromFundingAddress () {
    return  this.inputs[0].blockNumber.toString('hex') === '' &&
            this.inputs[0].txNumberInBlock.toString('hex') === '' &&
            this.inputs[0].outputNumberInTransaction.toString('hex') === '' &&
            this.transactionTypeUInt() === TxTypeFund
  }

  getTransactionInput(inputNumber) {
      if (this.inputs[inputNumber]) {
        return this.inputs[inputNumber]
      }
      return null
  }

  getTransactionOutput(outputNumber) {
      if (this.outputs[outputNumber]) {
        return this.outputs[outputNumber]
      }
      return null
  }

  getKey() {
    if(this._key) {
      return this._key
    }
    this._key = "";
    for (let i of [0,1]) {
        let inp = this.getTransactionInput(i);
        if (inp && typeof inp !== "undefined") {
          this._key = this._key + inp.getKey();
        }
    }
    return this._key
  }

  transactionTypeUInt() {
    const txType = ethUtil.bufferToInt(this.transactionType);
    return txType
  }

  /**
   * validates the signature and checks internal consistency
   * @param {Boolean} [stringError=false] whether to return a string with a dscription of why the validation failed or return a Bloolean
   * @return {Boolean|String}
   */
  validate (stringError) {
    const errors = [];
    if (stringError === undefined || stringError === false) {
      return errors.length === 0
    } else {
      return errors.join(', ')
    }
  }

  isWellFormed() {
    const txType = this.transactionTypeUInt();
    const numInputs = this.inputs.length;
    const numOutputs = this.outputs.length;
    if (txType === TxTypeMerge) {
        if (numInputs !== 2 || numOutputs !== 1) {
            return false
        }
    } else if (txType === TxTypeSplit) {
        if (numInputs !== 1 || (numOutputs < 1 || numOutputs > 3)) {
            return false
        }
    } else if (txType === TxTypeFund) {
        if (numInputs !== 1 || numOutputs !== 1) {
            return false
        }
    } else {
      return false
    }

    if (txType !== TxTypeFund) {
      let inputsTotalValue = new BN$2(0);
      let outputsTotalValue = new BN$2(0);
      let outputCounter = 0;
        for (let input of this.inputs) {
            inputsTotalValue.iadd(input.value);
        }
        for (let output of this.outputs) {
            if (output.value.lte(0)) {
              return false
            }
            if (ethUtil.bufferToInt(output.outputNumberInTransaction) !== outputCounter) {
              return false
            }
            outputsTotalValue.iadd(output.value);
            const addr = ethUtil.bufferToHex(output.to);
            if (addr === undefined || addr === null) {
                return false
            }
            outputCounter++;
        }
        if (!outputsTotalValue.eq(inputsTotalValue)) {
          return false
        }
    }
    return true
  }

  toFullJSON(labeled) {
    if (labeled) {
      const rawObj = this.toJSON(labeled);
      const transactionType = this.transactionTypeUInt();
      const obj = {
        transactionType,
        inputs: [],
        outputs: []
      };
      for (let inp of this.inputs) {
        obj.inputs.push(inp.toFullJSON(labeled));
      }
      for (let out of this.outputs) {
        obj.outputs.push(out.toFullJSON(labeled));
      }
      return obj
    } else {
      return ethUtil.baToJSON(this.raw)
    }
  }
}

const numInputsForType = {};
numInputsForType[TxTypeFund] =  1;
numInputsForType[TxTypeMerge] = 2;
numInputsForType[TxTypeSplit] = 1;

const numOutputsForType = {};
numOutputsForType[TxTypeFund] = 1;
numOutputsForType[TxTypeMerge] = 1;
numOutputsForType[TxTypeSplit] = 3;

const EmptyTransaction = new PlasmaTransaction({
  transactionType: TxTypeNull,
  inputs: [], 
  outputs: []
});

const BN$3 = ethUtil.BN;

const ZERO$1 = new BN$3(0);
const ZEROADDRESS$1 = Buffer.alloc(txToAddressLength);
const ZEROADDRESShex$1 = ethUtil.bufferToHex(ZEROADDRESS$1);

// const secp256k1 = require("secp256k1")
// secp256k1n/2
const N_DIV_2$3 = new BN$3('7fffffffffffffffffffffffffffffff5d576e7357a4501ddfe92f46681b20a0', 16);
  
class PlasmaTransactionWithSignature {
  constructor (data) {
    data = data || {};
    // Define Properties
    const fields = [{
      name: 'transaction',
      envelope: true,
      array: false,
      class: PlasmaTransaction
    }, {
      name: 'v',
      allowZero: true,
      length: signatureVlength,
      allowLess: false,
      default: Buffer.alloc(signatureVlength)
    }, {
      name: 'r',
      length: signatureRlength,
      allowZero: true,
      allowLess: false,
      default: Buffer.alloc(signatureRlength)
    }, {
      name: 's',
      length: signatureSlength,
      allowZero: true,
      allowLess: false,
      default: Buffer.alloc(signatureSlength)
    }];

    this._from = null;
    this._senderPubKey = null;

    defineProperties(this, fields, data);
    /**
     * @property {Buffer} from (read only) sender address of this transaction, mathematically derived from other parameters.
     * @name from
     * @memberof Transaction
     */
    Object.defineProperty(this, 'from', {
      enumerable: true,
      configurable: true,
      get: this.getSenderAddress.bind(this)
    });
  }

  /**
   * returns the sender's address
   * @return {Buffer}
   */
  getSenderAddress () {
    if (this._from !== null) {
      return this._from
    }
    const pubkey = this.getSenderPublicKey();
    this._from = ethUtil.publicToAddress(pubkey);
    return this._from
  }

  /**
   * returns the public key of the sender
   * @return {Buffer}
   */
  getSenderPublicKey () {
    if (this._senderPubKey === null || this._senderPubKey.length === 0) {
      if (!this.verifySignature()) {
        return null
      }
    }
    return this._senderPubKey
  }
  
  /**
   * Determines if the signature is valid
   * @return {Boolean}
   */
  verifySignature () {
    const msgHash = this.transaction.hash();

    // check is haldled by secp256k1 itself

    // All transaction signatures whose s-value is greater than secp256k1n/2 are considered invalid.
    if (new BN$3(this.s).cmp(N_DIV_2$3) === 1) {
      return false
    }

    try {
      
      let v = ethUtil.bufferToInt(this.v);
      this._senderPubKey = ethUtil.ecrecover(msgHash, v, this.r, this.s);

      // let v = ethUtil.bufferToInt(this.v) - 27
      // const signature = Buffer.concat([this.r, this.s])
      // this._senderPubKey = secp256k1.recover(msgHash, signature, v, false).slice(1)
    } catch (e) {
      return false
    }

    return !!this._senderPubKey
  }

  /**
   * sign a transaction with a given a private key
   * @param {Buffer} privateKey
   */
  sign (privateKey) {
    const msgHash = this.transaction.hash();
    const sig = ethUtil.ecsign(msgHash, privateKey);
    if (sig.v < 27){
        sig.v += 27;
    }
    Object.assign(this, sig);
    this._from = null;
    this.verifySignature();
  }

  serializeSignature(signatureString) {
      const signature = stripHexPrefix(signatureString);
      let r = ethUtil.addHexPrefix(signature.substring(0,64));
      let s = ethUtil.addHexPrefix(signature.substring(64,128));
      let v = ethUtil.addHexPrefix(signature.substring(128,130));
      r = ethUtil.toBuffer(r);
      s = ethUtil.toBuffer(s);
      v = ethUtil.bufferToInt(ethUtil.toBuffer(v));
      if (v < 27) {
          v = v + 27;
      }
      v = ethUtil.toBuffer(v);
      // this.v = v
      // this.r = r
      // this.s = s
      Object.assign(this, {v, r, s});
      this._from = null;
      this.verifySignature();
    }

  /**
   * validates the signature and checks internal consistency
   * @param {Boolean} [stringError=false] whether to return a string with a dscription of why the validation failed or return a Bloolean
   * @return {Boolean|String}
   */
  validate (stringError) {
      const errors = [];
      if (!this.transaction.validate()) {
        errors.push("Malformed transaction");
      }
      if (!this.verifySignature()) {
        errors.push('Invalid Signature');
      }
      if (stringError === undefined || stringError === false) {
        return errors.length === 0
      } else {
        return errors.join(', ')
      }
    }
        
  isWellFormed() {
    if (!this.transaction.isWellFormed()){
      return false
    }
    if (this.from === null) {
      return false
    }
    return true
  }

  toFullJSON(labeled) {
    if (labeled) {
      const rawObj = this.transaction.toFullJSON(labeled);
      const obj = {
          transaction: rawObj,
          v: ethUtil.bufferToHex(this.v),
          r: ethUtil.bufferToHex(this.r),
          s: ethUtil.bufferToHex(this.s)
        };
      return obj
    } else {
      return ethUtil.baToJSON(this.raw)
    }
  }
}

const EmptyTransactionBuffer = (new PlasmaTransactionWithSignature({
  transaction: EmptyTransaction,
  v: Buffer.alloc(signatureVlength),
  r: Buffer.alloc(signatureRlength),
  s: Buffer.alloc(signatureSlength)
})).rlpEncode();

function defineProperties$1(self, fields, data) {
  self.raw = [];
  self._fields = [];

  // attach the `toJSON`
  self.toJSON = function (label) {
    if (label) {
      const obj = {};
      self._fields.forEach(function (field) {
        if (!self[field] || typeof self[field] === "undefined"){
          return
        }
        obj[field] = '0x' + self[field].toString('hex');
      });
      return obj
    }
    return ethUtil.baToJSON(this.raw)
  };

  self.serialize = function serialize () {
    return Buffer.concat(this.raw)
  };

  fields.forEach(function (field, i) {
    self._fields.push(field.name);
    function getter () {
      return self.raw[i]
    }
    function setter (v_) {
      let v = ethUtil.toBuffer(v_);

      if (v.toString('hex') === '00' && !field.allowZero) {
        v = Buffer.alloc(0);
      }

      if (field.allowLess && field.length) {
        v = ethUtil.stripZeros(v);
        assert(field.length >= v.length, 'The field ' + field.name + ' must not have more ' + field.length + ' bytes');
      } else if (!(field.allowZero && v.length === 0) && field.length) {
        assert(field.length === v.length, 'The field ' + field.name + ' must have byte length of ' + field.length);
      }

      self.raw[i] = v;
    }

    Object.defineProperty(self, field.name, {
      enumerable: true,
      configurable: true,
      get: getter,
      set: setter
    });

    if (field.default) {
      self[field.name] = field.default;
    }

    // attach alias
    if (field.alias) {
      Object.defineProperty(self, field.alias, {
        enumerable: false,
        configurable: true,
        set: setter,
        get: getter
      });
    }
  });

  // if the constuctor is passed data
  if (data) {
    if (typeof data === 'string') {
      data = Buffer.from(ethUtil.stripHexPrefix(data), 'hex');
    }

    if (Array.isArray(data)) {
      if (data.length > self._fields.length) {
        throw (new Error('wrong number of fields in data'))
      }

      // make sure all the items are buffers
      data.forEach(function (d, i) {
        self[self._fields[i]] = ethUtil.toBuffer(d);
      });
    } else if (typeof data === 'object') {
      const keys = Object.keys(data);
      fields.forEach(function (field) {
        if (keys.indexOf(field.name) !== -1) self[field.name] = data[field.name];
        if (keys.indexOf(field.alias) !== -1) self[field.alias] = data[field.alias];
      });
    } else {
      throw new Error('invalid data')
    }
  }
}

const BN$4 = ethUtil.BN;

// secp256k1n/2
const N_DIV_2$4 = new BN$4('7fffffffffffffffffffffffffffffff5d576e7357a4501ddfe92f46681b20a0', 16);

class BlockHeader {
  constructor (data) {
    data = data || {};
    // Define Properties
    const fields = [{
      name: 'blockNumber',
      alias: 'block',
      length: blockNumberLength,
      allowLess: false,
      default: Buffer.alloc(blockNumberLength)
    }, {
      name: 'numberOfTransactions',
      alias: 'numTX',
      length: txNumberLength,
      allowLess: false,
      default: Buffer.alloc(txNumberLength)
    }, {
      name: 'parentHash',
      allowZero: true,
      length: previousHashLength,
      allowLess: false,
      default: Buffer.alloc(previousHashLength)
    }, {
      name: 'merkleRootHash',
      allowZero: true,
      alias: 'merkle',
      length: merkleRootLength,
      allowLess: false,
      default: Buffer.alloc(merkleRootLength)
    }, {
      name: 'v',
      allowZero: true,
      length: signatureVlength,
      allowLess: false,
      default: Buffer.alloc(signatureVlength)
    }, {
      name: 'r',
      length: signatureRlength,
      allowZero: true,
      allowLess: false,
      default: Buffer.alloc(signatureRlength)
    }, {
      name: 's',
      length: signatureSlength,
      allowZero: true,
      allowLess: false,
      default: Buffer.alloc(signatureSlength)
    }];

 defineProperties$1(this, fields, data);
    /**
     * @property {Buffer} from (read only) sender address of this transaction, mathematically derived from other parameters.
     * @name from
     * @memberof Transaction
     */
    Object.defineProperty(this, 'from', {
      enumerable: true,
      configurable: true,
      get: this.getSenderAddress.bind(this)
    });

    Object.defineProperty(this, 'length', {
      enumerable: true,
      configurable: true,
      get: (() => Buffer.concat(this.raw).length) 
    });
  }
  
  /**
   * Computes a sha3-256 hash of the serialized tx
   * @param {Boolean} [includeSignature=true] whether or not to inculde the signature
   * @return {Buffer}
   */
  hash (includeSignature) {
    if (includeSignature === undefined) includeSignature = true;

    // EIP155 spec:
    // when computing the hash of a transaction for purposes of signing or recovering,
    // instead of hashing only the first six elements (ie. nonce, gasprice, startgas, to, value, data),
    // hash nine elements, with v replaced by CHAIN_ID, r = 0 and s = 0

    let items = this.clearRaw(includeSignature);
    // return ethUtil.sha3(Buffer.concat(items))
    return ethUtil.hashPersonalMessage(Buffer.concat(items))

  }

  serializeSignature(signatureString) {
    const signature = stripHexPrefix(signatureString);
    let r = ethUtil.addHexPrefix(signature.substring(0,64));
    let s = ethUtil.addHexPrefix(signature.substring(64,128));
    let v = ethUtil.addHexPrefix(signature.substring(128,130));
    r = ethUtil.toBuffer(r);
    s = ethUtil.toBuffer(s);
    v = ethUtil.bufferToInt(ethUtil.toBuffer(v));
    if (v < 27) {
        v = v + 27;
    }
    v = ethUtil.toBuffer(v);
    this.r = r;
    this.v = v;
    this.s = s;
  }

  /**
   * returns the sender's address
   * @return {Buffer}
   */
  getSenderAddress () {
    if (this._from) {
      return this._from
    }
    const pubkey = this.getSenderPublicKey();
    this._from = ethUtil.publicToAddress(pubkey);
    return this._from
  }

  /**
   * returns the public key of the sender
   * @return {Buffer}
   */
  getSenderPublicKey () {
    if (!this._senderPubKey || !this._senderPubKey.length) {
      if (!this.verifySignature()) throw new Error('Invalid Signature')
    }
    return this._senderPubKey
  }

  /**
   * Determines if the signature is valid
   *
   * @return {Boolean}
   */
  verifySignature () {
    const msgHash = this.hash(false);
    // All transaction signatures whose s-value is greater than secp256k1n/2 are considered invalid.
    if (new BN$4(this.s).cmp(N_DIV_2$4) === 1) {
      return false
    }
    try {
      let v = ethUtil.bufferToInt(this.v);
    //   if (this._chainId > 0) {
    //     v -= this._chainId * 2 + 8
    //   }
      this._senderPubKey = ethUtil.ecrecover(msgHash, v, this.r, this.s);
    } catch (e) {
      return false
    }

    return !!this._senderPubKey
  }

  /**
   * sign a transaction with a given a private key
   * @param {Buffer} privateKey
   */
  sign (privateKey) {
    const msgHash = this.hash(false);
    const sig = ethUtil.ecsign(msgHash, privateKey);
    if (sig.v < 27){
        sig.v += 27;
    }
 
    Object.assign(this, sig);
  }


  clearRaw(includeSignature) {
    let items;
    if (includeSignature) {
      items = this.raw;
    } else {
        items = this.raw.slice(0, this.raw.length-3);
    }
    return items
    // return Buffer.concat(items)
  }

  /**
   * validates the signature and checks to see if it has enough gas
   * @param {Boolean} [stringError=false] whether to return a string with a dscription of why the validation failed or return a Bloolean
   * @return {Boolean|String}
   */
  validate (stringError) {
    const errors = [];
    if (!this.verifySignature()) {
      errors.push('Invalid Signature');
    }
    if (stringError === undefined || stringError === false) {
      return errors.length === 0
    } else {
      return errors.join(' ')
    }
  }

  toFullJSON(labeled) {
    if (labeled) {
      const header = this.toJSON(labeled);
      const blockNumber = ethUtil.bufferToInt(this.blockNumber);
      const numberOfTransactions = ethUtil.bufferToInt(this.numberOfTransactions);
      header.blockNumber = blockNumber;
      header.numberOfTransactions = numberOfTransactions;
      return header
    } else {
      return ethUtil.baToJSON(this.raw)
    }
  }
}

const dummy$2 = new BlockHeader();
const blockHeaderLength = dummy$2.length;
const blockHeaderNumItems = dummy$2.raw.length;

const BN$5 = ethUtil.BN;

// secp256k1n/2
const N_DIV_2$5 = new BN$5('7fffffffffffffffffffffffffffffff5d576e7357a4501ddfe92f46681b20a0', 16);

class Block {
  constructor (data) {
    if (data instanceof Object && data.constructor === Object ){ 
      this.blockNumber = data.blockNumber || Buffer.alloc(blockNumberLength);
      this.parentHash = data.parentHash || Buffer.alloc(previousHashLength);
      this.transactions = data.transactions || [];
      this.numberOfTransactions = data.transactions.length || 0;
      const numberOfTransactionsBuffer = (new BN$5(this.numberOfTransactions)).toBuffer("be", txNumberLength);

      assert(this.transactions && Array.isArray(this.transactions), "TXs should be an array");
      const treeOptions = {
        hashType: 'sha3'
      };
      
      this.merkleTree = new MerkleTools(treeOptions);
      for (let i = 0; i < this.transactions.length; i++) {
        const tx = this.transactions[i];
        assert(tx.isWellFormed(), "Panic, block contains malformed transaction");
        const txHash = tx.hash();
        this.merkleTree.addLeaf(txHash);
      }  
      assert(this.merkleTree.getLeafCount() == this.numberOfTransactions);
      this.merkleTree.makePlasmaTree(EmptyTransactionBuffer);
      const rootValue = this.merkleTree.getMerkleRoot() || Buffer.alloc(merkleRootLength);
      // console.log("Merkle root of block is " + ethUtil.bufferToHex(rootValue))
      const headerParams = {
        blockNumber: this.blockNumber,
        parentHash: this.parentHash,
        merkleRootHash: rootValue,
        numberOfTransactions: numberOfTransactionsBuffer
      };
      this.header = new BlockHeader(headerParams);
    } else if (Buffer.isBuffer(data)) {
      this.transactions = [];
      const head = data.slice(0, blockHeaderLength);
      let i = 0;
      const headerArray = [];
      for (let sliceLen of [blockNumberLength, txNumberLength, previousHashLength, merkleRootLength, signatureVlength, signatureRlength, signatureSlength]) {
        headerArray.push(head.slice(i, i + sliceLen));
        i += sliceLen;
      }
      this.header = new BlockHeader(headerArray);
      const transactionsBuffer = data.slice(blockHeaderLength, data.length);
      const transactionsList = ethUtil.rlp.decode(transactionsBuffer);
      for (let rawTX of transactionsList) {
        const TX = new PlasmaTransactionWithSignature(rawTX);
        assert(TX.isWellFormed(), "Panic, block contains malformed transaction");
        this.transactions.push(TX);
      }
      assert(this.transactions.length === ethUtil.bufferToInt(this.header.numberOfTransactions));
      const treeOptions = {
        hashType: 'sha3'
        };
      this.merkleTree = new MerkleTools(treeOptions);
      for (let j = 0; j < this.transactions.length; j++) {
        const tx = this.transactions[j];
        const txHash = tx.hash();
        this.merkleTree.addLeaf(txHash);
      }  
      assert(this.merkleTree.getLeafCount() === this.transactions.length);
      this.merkleTree.makePlasmaTree(EmptyTransactionBuffer);
      const rootValue = this.merkleTree.getMerkleRoot();
      if (!this.header.merkleRootHash.equals(Buffer.alloc(merkleRootLength))) {
        assert(rootValue.equals(this.header.merkleRootHash), "Merkle root hash mismatch");
      }
      assert(this.header.validate(), "Header did not pass validation");
    }
    Object.defineProperty(this, 'from', {
      enumerable: true,
      configurable: true,
      get: this.getSenderAddress.bind(this)
    });

    Object.defineProperty(this, 'raw', {
      get: function () {
      return this.serialize()
      }
    }); 
  }

  serializeSignature(signatureString) {
    this.header.serializeSignature(signatureString);
  }
   
  serialize() {
    let txRaws = [];
    for (let i = 0; i < this.transactions.length; i++) {
      const tx = this.transactions[i];
      assert(tx.isWellFormed());
      txRaws.push(tx.rlpEncode());
    }
    return this.header.raw.concat(ethUtil.rlp.encode(txRaws))
  }  

  clearRaw(includeSignature) {
    return this.header.clearRaw(includeSignature)
  }

  /**
   * Computes a sha3-256 hash of the serialized tx
   * @param {Boolean} [includeSignature=true] whether or not to inculde the signature
   * @return {Buffer}
   */
  hash (includeSignature) {
    return this.header.hash(includeSignature)
  }

  /**
   * returns the sender's address
   * @return {Buffer}
   */
  getSenderAddress () {
    return this.header.getSenderAddress()
  }

  /**
   * returns the public key of the sender
   * @return {Buffer}
   */
  getSenderPublicKey () {
    return this.header._senderPubKey
  }

  getMerkleHash () {
    return this.header.merkleRootHash
  }

  /**
   * Determines if the signature is valid
   * @return {Boolean}
   */
  verifySignature () {
    return this.header.verifySignature()
  }

  /**
   * sign a transaction with a given a private key
   * @param {Buffer} privateKey
   */
  sign (privateKey) {
    this.header.sign(privateKey);
  }

  /**
   * validates the signature and checks to see if it has enough gas
   * @param {Boolean} [stringError=false] whether to return a string with a dscription of why the validation failed or return a Bloolean
   * @return {Boolean|String}
   */
  validate (stringError) {
    const errors = [];
    if (this.transactions.length !== ethUtil.bufferToInt(this.header.numberOfTransactions)) {
      errors.push("Invalid number of transactions");
    }
    if (!this.verifySignature()) {
      errors.push('Invalid Signature');
    }
    if (stringError === undefined || stringError === false) {
      return errors.length === 0
    } else {
      return errors.join(' ')
    }
  }
}

Block.prototype.getProofForTransactionSpendingUTXO = function (signedTX, forUTXOnumber) {
  let counter = 0;
  for (const tx of this.transactions) {
    const txNoNumberBuffer = tx.serialize();
    if (txNoNumberBuffer.equals(signedTX)) {
      const proof = Buffer.concat(this.merkleTree.getProof(counter, true));
      for (let i = 0; i < tx.transaction.inputs.length; i++) {
        const input = tx.transaction.inputs[i];
        if (input.getUTXOnumber().cmp(forUTXOnumber) === 0) {
          const inputNumber = new BN$5(i);
          return {tx, proof, inputNumber}
        }
        return null
      }
    }
    counter++;
  }
  return null
};

Block.prototype.getProofForTransactionByNumber = function (transactionNumber) {
  if (transactionNumber >= this.transactions.length) {
    return null
  }
  const tx = this.transactions[transactionNumber]; 
  const proof = Buffer.concat(this.merkleTree.getProof(transactionNumber, true));
  return {tx, proof};    
};

Block.prototype.getProofForTransaction = function (signedTX) {
  let counter = 0;
  for (const tx of this.transactions) {
    const txNoNumberBuffer = tx.serialize();
    if (txNoNumberBuffer.equals(signedTX)) {
      const proof = Buffer.concat(this.merkleTree.getProof(counter, true));
      return {tx, proof}
    }
    counter++;
  }
  return null
};

Block.prototype.toJSON = function (labeled) {
  if (labeled) {
    const obj = {
      header: this.header.toJSON(labeled),
      transactions: []
    };

    this.transactions.forEach(function (tx) {
      const txJSON = tx.toJSON(labeled);
      obj.transactions.push(txJSON);
    });

    return obj
  } else {
    return ethUtil.baToJSON(this.raw)
  }
};

Block.prototype.toFullJSON = function (labeled) {
  if (labeled) {
    const obj = {
      header: this.header.toFullJSON(labeled),
      transactions: []
    };
    this.transactions.forEach(function (tx) {
      const txJSON = tx.toFullJSON(labeled);
      obj.transactions.push(txJSON);
    });
    return obj
  } else {
    return ethUtil.baToJSON(this.raw)
  }
};

exports.blockNumberLength = blockNumberLength;
exports.txNumberLength = txNumberLength;
exports.txTypeLength = txTypeLength;
exports.signatureVlength = signatureVlength;
exports.signatureRlength = signatureRlength;
exports.signatureSlength = signatureSlength;
exports.merkleRootLength = merkleRootLength;
exports.previousHashLength = previousHashLength;
exports.txOutputNumberLength = txOutputNumberLength;
exports.txAmountLength = txAmountLength;
exports.txToAddressLength = txToAddressLength;
exports.transactionInputLength = transactionInputLength;
exports.transactionOutputLength = transactionOutputLength;
exports.numInputsForType = numInputsForType;
exports.numOutputsForType = numOutputsForType;
exports.blockHeaderLength = blockHeaderLength;
exports.blockHeaderNumItems = blockHeaderNumItems;
exports.MerkleTools = MerkleTools;
exports.TransactionInput = TransactionInput;
exports.TransactionOutput = TransactionOutput;
exports.PlasmaTransaction = PlasmaTransaction;
exports.TxTypeFund = TxTypeFund;
exports.TxTypeMerge = TxTypeMerge;
exports.TxTypeSplit = TxTypeSplit;
exports.EmptyTransaction = EmptyTransaction;
exports.PlasmaTransactionWithSignature = PlasmaTransactionWithSignature;
exports.EmptyTransactionBuffer = EmptyTransactionBuffer;
exports.BlockHeader = BlockHeader;
exports.Block = Block;
