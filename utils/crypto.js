const crypto = require('crypto');
const {Web3} = require('web3'); // Import Web3.js
const web3 = new Web3(new Web3.providers.HttpProvider(process.env.WEB3_PROVIDER_URL));
const { signTransactionScript } = require("../scripts/signTx.js");

function encrypt(text, encryptionKey) {
  const cipher = crypto.createCipher('aes-256-cbc', encryptionKey);
  let encryptedText = cipher.update(text, 'utf8', 'hex');
  encryptedText += cipher.final('hex');
  return encryptedText;
}

function decrypt(encryptedText, encryptionKey) {
  const decipher = crypto.createDecipher('aes-256-cbc', encryptionKey);
  let decryptedText = decipher.update(encryptedText, 'hex', 'utf8');
  decryptedText += decipher.final('utf8');
  return decryptedText;
}

// Function to generate a new wallet
function generateWallet() {
  const wallet = web3.eth.accounts.create();
  return wallet;
}

// Function to get the balance of a wallet
async function getWalletBalance(walletAddress) {
  try {
    const balance = await web3.eth.getBalance(walletAddress);
    return web3.utils.fromWei(balance, 'ether');
  } catch (error) {
    throw new Error('Failed to get wallet balance');
  }
}

// Function to sign a transaction using the user's private key
async function signTransaction( encodedABIData, nonce, privateKey) {
    try {
      let signatureData =await signTransactionScript( encodedABIData, nonce, privateKey,web3)
      
      return {signatureData};
    } catch (error) {
        console.log(error)
      throw new Error('Failed to sign the transaction');

    }
}


module.exports = { encrypt, decrypt, generateWallet, getWalletBalance,signTransaction };
