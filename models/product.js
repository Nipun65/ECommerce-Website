const mongoose = require('mongoose');

const Schema = mongoose.Schema;

const productSchema = new Schema({
  title: {
    type: String,
    required: true,
  },
  imageUrl: {
    type: String,
    required: true,
  },
  price: {
    type: String,
    required: true,
  },
  description: {
    type: String,
    required: true,
  },
  userId: {
    type: Schema.Types.ObjectId,
    ref: 'users',
  },
});

module.exports = mongoose.model('Product', productSchema);

/*const { getDb } = require('../utils/database');
const mongoDB = require('mongodb');

class Product {
  constructor(title, imageUrl, price, description, id, userId) {
    this.title = title;
    this.imageUrl = imageUrl;
    this.price = price;
    this.description = description;
    this._id = id;
    this.userId = userId;
  }

  save() {
    const db = getDb();
    let dbOp;
    if (this._id) {
      dbOp = db
        .collection('products')
        .updateOne({ _id: this._id }, { $set: this });
    } else {
      dbOp = db.collection('products').insertOne(this);
    }
    return dbOp
      .then((result) => {
        return result;
      })
      .catch((err) => {
        console.log(err);
      });
  }
  static fetchAll() {
    const db = getDb();
    return db
      .collection('products')
      .find()
      .toArray()
      .then((result) => {
        return result;
      })
      .catch((err) => {
        console.log(err);
      });
  }

  static findById(prodId) {
    const db = getDb();
    return db
      .collection('products')
      .find({ _id: new mongoDB.ObjectId(prodId) })
      .next()
      .then((product) => {
        console.log(product);
        return product;
      })
      .catch((err) => {
        console.log(err);
      });
  }

  static deleteById(id) {
    const db = getDb();
    return db
      .collection('products')
      .deleteOne({ _id: new mongoDB.ObjectId(id) })
      .then((result) => {
        console.log('deleted');
        console.log(result);
      })
      .catch((err) => {
        console.log(err);
      });
  }
}*/

// const fs = require('fs');
// const path = require('path');

// const pathDir = require('../utils/path');
// const p = path.join(pathDir, 'data', 'products.json');
// const Cart = require('./cart');

// const getProductFromFile = (callBack) => {
//   fs.readFile(p, (error, fileContent) => {
//     console.log(fileContent);
//     if (error) {
//       return callBack([]);
//     } else {
//       return callBack(JSON.parse(fileContent));
//     }
//   });
// };

// module.exports = class Product {
//   constructor(id, title, imageUrl, price, description) {
//     this.id = id;
//     this.title = title;
//     this.imageUrl = imageUrl;
//     this.price = price;
//     this.description = description;
//   }
//   save() {
//     getProductFromFile((products) => {
//       if (this.id !== 'null' && this.id) {
//         const existingProductIndex = products.findIndex(
//           (p) => p.id === this.id
//         );
//         const updatedProducts = [...products];
//         updatedProducts[existingProductIndex] = this;
//         fs.writeFile(p, JSON.stringify(updatedProducts), (err) => {
//           console.log(err);
//         });
//       } else {
//         this.id = Math.random().toString();
//         products.push(this);
//         fs.writeFile(p, JSON.stringify(products), (err) => {
//           console.log(err);
//         });
//       }
//     });
//   }

//   updateProducts(product) {
//     getProductFromFile((products) => {
//       products.find((p) => {
//         if (product.id === p.id) {
//           p = product;
//         }
//       });
//       fs.writeFile(p, JSON.stringify(products), (err) => {
//         console.log(err);
//       });
//     });
//   }

//   static fetchAll(callBack) {
//     getProductFromFile(callBack);
//   }

//   static findById(id, callBack) {
//     getProductFromFile((products) => {
//       const product = products.find((p) => p.id === id);
//       callBack(product);
//     });
//   }

//   static deleteById(id) {
//     getProductFromFile((products) => {
//       const product = products.find((p) => p.id === id);
//       const updateProducts = products.filter((p) => p.id !== id);
//       Cart.deleteProduct(id, product.price);
//       fs.writeFile(p, JSON.stringify(updateProducts), (err) => {
//         if (!err) {
//           console.log(err);
//         }
//       });
//     });
//   }
// };

// module.exports = Product;
