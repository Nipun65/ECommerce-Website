const mongoose = require('mongoose');

const Schema = mongoose.Schema;

const orderSchema = new Schema({
  products: [
    {
      product: {
        type: Object,
        required: true,
      },
      quantity: {
        type: Number,
        required: true,
      },
    },
  ],
  user: {
    email: { type: String, required: true },
    userId: { type: Schema.Types.ObjectId, required: true, ref: 'users' },
  },
});

// orderSchema.methods.addOrder = function () {
//   return this.getCart().then((products) => {
//     console.log(products);
//     const order = {
//       items: products,
//       user: { _id: this._id, name: this.username, email: this.email },
//     };
//     return db
//       .collection('orders')
//       .insertOne(order)
//       .then((result) => {
//         this.cart = { items: [] };
//         console.log(result);
//         return db
//           .collection('users')
//           .updateOne(
//             { _id: new ObjectId(this._id) },
//             { $set: { cart: { items: [] } } }
//           );
//       });
//   });
// };

module.exports = mongoose.model('Order', orderSchema);
