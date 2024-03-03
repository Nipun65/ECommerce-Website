const fs = require('fs');
const path = require('path');

const pathDir = require('../utils/path');
const cartFile = path.join(pathDir, 'data', 'cart.json');

const getCartProductFromFile = (callBack) => {
  fs.readFile(cartFile, (error, fileContent) => {
    let cart = { products: [], totalPrice: 0 };
    if (error) {
      return callBack(cart);
    } else {
      return callBack(JSON.parse(fileContent));
    }
  });
};

module.exports = class Cart {
  static addInCartItems(prodId, productPrice) {
    getCartProductFromFile((cartProducts) => {
      let productIsInCart = false;
      cartProducts.products.map((value) => {
        if (value.prodId === prodId) {
          value.qty += 1;
          cartProducts.totalPrice += parseInt(productPrice.split('$')[1]);
          productIsInCart = true;
        }
      });
      if (!productIsInCart) {
        cartProducts.products.push({ prodId, qty: 1 });
        cartProducts.totalPrice += parseInt(productPrice.split('$')[1]);
      }
      fs.writeFile(cartFile, JSON.stringify(cartProducts), (err) => {
        console.log(err);
      });
    });
  }

  static deleteProduct(id, productPrice) {
    fs.readFile(cartFile, (err, fileContent) => {
      if (err) {
        return;
      } else {
        const updatedCart = { ...JSON.parse(fileContent) };
        const deleteCartProduct = updatedCart.products.find(
          (p) => p.prodId === id
        );
        if (!deleteCartProduct) {
          return;
        }
        const productQty = deleteCartProduct?.qty;
        const contentInCartIndex = updatedCart.products.findIndex(
          (p) => p.prodId == id
        );
        updatedCart.products.splice(contentInCartIndex, 1);
        updatedCart.totalPrice -= productPrice.split('$')[1] * productQty;
        fs.writeFile(cartFile, JSON.stringify(updatedCart), (err) => {
          console.log(err);
        });
      }
    });
  }

  static getCardData(callBack) {
    fs.readFile(cartFile, (err, fileContent) => {
      if (err) {
        callBack([]);
        // return err;
      } else {
        callBack(JSON.parse(fileContent));
      }
    });
  }
};
