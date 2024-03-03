const mongoose = require('mongoose');
const Schema = mongoose.Schema;

const userSchema = new Schema({
  email: {
    type: String,
    required: true,
  },
  password: {
    type: String,
    required: true,
  },
  resetToken: String,
  resetTokenExpiration: Date,
  cart: {
    items: [
      {
        productId: {
          type: Schema.Types.ObjectId,
          ref: 'Product',
          required: true,
        },
        quantity: { type: Number, required: true },
      },
    ],
  },
});

userSchema.methods.addToCart = function (product) {
  const cartProductIndex = this.cart.items.findIndex((cp) => {
    return cp.productId.toString() === product._id.toString();
  });
  let newQuantity = 1;

  const updatedCartItems = [...this.cart.items];
  if (cartProductIndex >= 0) {
    newQuantity = this.cart.items[cartProductIndex].quantity + 1;
    updatedCartItems[cartProductIndex].quantity = newQuantity;
  } else {
    updatedCartItems.push({
      productId: product._id,
      quantity: newQuantity,
    });
  }

  const updatedCart = {
    items: updatedCartItems,
  };

  this.cart = updatedCart;
  return this.save();
};

userSchema.methods.cartProductdeleteById = function (cartProductId) {
  const updatedCartItems = this.cart.items.filter(
    (cp) => cp.productId.toString() !== cartProductId.toString()
  );
  this.cart = {
    items: updatedCartItems,
  };
  return this.save();
};

userSchema.methods.clearCart = function () {
  this.cart = {
    items: [],
  };
  return this.save();
};

module.exports = mongoose.model('users', userSchema);

// const { ObjectId } = require('mongodb');
// const { getDb } = require('../utils/database');
// const { deleteById } = require('./product');

// class User {
//   constructor(username, email, cart, id) {
//     this.username = username;
//     this.email = email;
//     this.cart = cart;
//     this._id = id;
//   }
//   save() {
//     const db = getDb();
//     return db.collection('users').insertOne(this);
//   }

//   addToCart(product) {
//     const db = getDb();

//     const cartProductIndex = this.cart.items.findIndex((cp) => {
//       return cp.productId.toString() === product._id.toString();
//     });
//     let newQuantity = 1;

//     const updatedCartItems = [...this.cart.items];
//     if (cartProductIndex >= 0) {
//       newQuantity = this.cart.items[cartProductIndex].quantity + 1;
//       updatedCartItems[cartProductIndex].quantity = newQuantity;
//     } else {
//       updatedCartItems.push({
//         productId: new ObjectId(product._id),
//         quantity: newQuantity,
//       });
//     }
//     const updatedCart = {
//       items: updatedCartItems,
//     };
//     return db
//       .collection('users')
//       .updateOne(
//         { _id: new ObjectId(this._id) },
//         { $set: { cart: updatedCart } }
//       );
//   }
//   getCart() {
//     const db = getDb();
//     const cartProductIds = this.cart.items.map((cp) => cp.productId);
//     return db
//       .collection('products')
//       .find({ _id: { $in: cartProductIds } })
//       .toArray()
//       .then((products) => {
//         return products.map((p) => {
//           console.log(p);
//           return {
//             productData: p,
//             qty: this.cart.items.find((i) => {
//               return i.productId.toString() === p._id.toString();
//             }).quantity,
//           };
//         });
//       });
//   }

//   cartProductdeleteById(cartProductId) {
//     const db = getDb();
//     const updatedCartItems = this.cart.items.filter(
//       (cp) => cp.productId.toString() !== cartProductId.toString()
//     );
//     const updatedCart = {
//       items: updatedCartItems,
//     };
//     console.log('delete updated Cart');
//     console.log(updatedCart);
//     return db
//       .collection('users')
//       .updateOne(
//         { _id: new ObjectId(this._id) },
//         { $set: { cart: updatedCart } }
//       );
//   }

//   addOrder() {
//     const db = getDb();
//     return this.getCart().then((products) => {
//       console.log(products);
//       const order = {
//         items: products,
//         user: { _id: this._id, name: this.username, email: this.email },
//       };
//       return db
//         .collection('orders')
//         .insertOne(order)
//         .then((result) => {
//           this.cart = { items: [] };
//           console.log(result);
//           return db
//             .collection('users')
//             .updateOne(
//               { _id: new ObjectId(this._id) },
//               { $set: { cart: { items: [] } } }
//             );
//         });
//     });
//   }
//   getOrdersFromDB(userId) {
//     const db = getDb();
//     console.log(userId);
//     return db
//       .collection('orders')
//       .find({ 'user._id': new ObjectId(userId) })
//       .toArray()
//       .then((orders) => {
//         return orders;
//       });
//   }

//   static findById(userId) {
//     const db = getDb();
//     return db
//       .collection('users')
//       .findOne({ _id: new ObjectId(userId) })
//       .then((user) => {
//         return user;
//       })
//       .catch((err) => {
//         console.log(err);
//       });
//   }
// }

// module.exports = User;
