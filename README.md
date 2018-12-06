<h3 align="center">
  <a href="https://thematter.io/">
    <img src="https://scontent-arn2-1.xx.fbcdn.net/v/t1.0-9/42614873_308414336637874_8225471638720741376_n.png?_nc_cat=106&_nc_ht=scontent-arn2-1.xx&oh=36eec27649e6cb3079108415d8bb77b7&oe=5CB0FBF8" width="100" />
    <br />
    The Matter Plasma Implementation
  </a>
</h3>
<p align="center">
  <a href="https://github.com/matterinc/PlasmaContract">Contract</a> &bull;
  <b>TX & Block RLP</b> &bull;
  <a href="https://github.com/matterinc/PlasmaManager">JS Lib</a> &bull;
  <a href="https://github.com/matterinc/PlasmaSwiftLib">Swift Lib</a> &bull;
  <a href="https://github.com/matterinc/PlasmaWebExplorer">Block Explorer</a> &bull;
  <a href="https://github.com/matterinc/PlasmaWebUI">Web App</a> &bull;
  <a href="https://github.com/matterinc/DiveLane">iOS App</a>
</p>

# Plasma TX & Block RLP &middot; 
[![npm version](https://img.shields.io/npm/v/@thematter_io/plasma.js.svg)](https://www.npmjs.com/package/@thematter_io/plasma.js)

JavaScript library describes TX & Block RLP structure for More Viable Plasma by The Matter.

Use it to serialize and sign raw transactions for Plasma.

<!-- toc -->

- [Installation](#installation)
- [Usage](#usage)
- [RLP structures](#rlp-structures)
  * [Transaction structure](#transaction-structure)
  * [Block structure](#block-structure)
- [Credits](#credits)
- [Donations](#donations)
- [License](#license)

<!-- tocstop -->

## Installation

```bash
npm install @thematter_io/plasma.js
```

## Usage

```javascript
const plasma = require('@thematter_io/plasma.js')
console.log(plasma)
```

## RLP structures

### Transaction structure

The transaction structure, that is used in The Matter Plasma Implementation is the UTXO model with explicit enumeration of UTXOs in the inputs.

#### Input
An RLP encoded set with the following items:
- Block number, 4 bytes
- Transaction number in block, 4 bytes
- Output number in transaction, 1 byte
- "Amount" field, 32 bytes, that is more a data field, usually used for an amount of the output referenced by previous field, but has special meaning for "Deposit" transactions

#### Output
An RLP encoded set with the following items:
- Output number in transaction, 1 byte
- Receiver's Ethereum address, 20 bytes
- "Amount" field, 32 bytes

#### Transaction 
An RLP encoded set with the following items:
- Transaction type, 1 byte
- An array (list) of Inputs, maximum 2 items
- An array (list) of Outputs, maximum 3 items. One of the outputs is an explicit output to an address of Plasma operator.

#### Signed transaction 
An RLP encoded set with the following items:
- Transaction, as described above
- Recoverable EC of the transaction sender:
   1) V value, 1 byte, expected values 27, 28
   2) R value, 32 bytes
   3) S value, 32 bytes

From this signature Plasma operator deduces a sender, checks that the sender is an owner of UTXOs referenced by inputs. Signature is based on EthereumPersonalHash(RLPEncode(Transaction)). Transaction should be well-formed, sum of inputs equal to sum of the outputs, etc.

### Block structure

#### Block header
- Block number, 4 bytes, used in the main chain to double check proper ordering
- Number of transactions in block, 4 bytes, purely informational
- Parent hash, 32 bytes, hash of the previous block, hashes the full header
- Merkle root of the transactions tree, 32 bytes
- V value, 1 byte, expected values 27, 28
- R value, 32 bytes
- S value, 32 bytes

Signature is based on EthereumPersonalHash(block number || number of transactions || previous hash || merkle root), where || means concatenation. Values V, R, S are then concatenated to the header.

#### Block
- Block header, as described above, 137 bytes
- RLP encoded array (list) of signed transactions, as described above

While some fields can be excessive, such block header can be submitted by anyone to the main Ethereum chain when block is available, but for some reason not sent to the smart contract. Transaction numbering is done by the operator, it should be monotonically increasing without spaces and number of transactions in header should (although this is not necessary for the functionality) match the number of transactions in the Merkle tree and the full block.

## Credits

Denis Khoruzhiy, [@DirectX](https://github.com/DirectX)

## Donations

[The Matters](https://github.com/orgs/matterinc/people) are charged with open-sorсe and do not require money for using their `PlasmaSwiftLib`.
We want to continue to do everything we can to move the needle forward.
If you use any of our libraries for work, see if your employers would be interested in donating. Any amount you can donate today to help us reach our goal would be greatly appreciated.

Our Ether wallet address: 0xe22b8979739d724343bd002f9f432f5990879901

![Donate](http://qrcoder.ru/code/?0xe22b8979739d724343bd002f9f432f5990879901&4&0)

## License

PlasmaSwiftLib is available under the Apache License 2.0 license. See the [LICENSE](https://github.com/matterinc/plasma.js/blob/master/LICENSE) for details.
