const express = require('express');
const router = express.Router();
const isAuth = require('../middleware/is-auth');

const {
  getProducts,
  getCartList,
  getCheckoutList,
  getIndex,
  getProductDetails,
  addProductToCart,
  postCartDeleteItem,
  postOrders,
  getOrders,
  getInvoice,
  getCheckout,
} = require('../controllers/shop');

router.get('/', getProducts);
router.get('/products', getIndex);
router.get('/products/:productId', getProductDetails);
router.get('/cart', isAuth, getCartList);
router.post('/add-to-cart', isAuth, addProductToCart);
router.get('/checkout', isAuth, getCheckout);
router.get('/checkout/success', isAuth, postOrders);
router.get('/checkout/cancel', isAuth, getCheckout);
router.post('/cart-delete-item', isAuth, postCartDeleteItem);
router.post('/create-order', isAuth, postOrders);
router.get('/orders', isAuth, getOrders);
router.get('/orders/:orderId', isAuth, getInvoice);

module.exports = router;
