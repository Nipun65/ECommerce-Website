const express = require('express');
const isAuth = require('../middleware/is-auth');
const { body } = require('express-validator');

const {
  getAddProduct,
  postAddProduct,
  getAdminProduct,
  getEditProduct,
  deleteProduct,
  postEditProduct,
} = require('../controllers/admin');
const router = express.Router();

router.get('/add-product', isAuth, getAddProduct);
router.post(
  '/add-product',
  [
    body('title').isString().isLength({ min: 3 }).trim(),
    body('description').isLength({ min: 5, max: 400 }).trim(),
  ],
  isAuth,
  postAddProduct
);
router.get('/products', isAuth, getAdminProduct);
router.get('/edit-product/:productId', isAuth, getEditProduct);
router.post('/edit-product', isAuth, postEditProduct);
// router.get('/delete-product/:productId', isAuth, postDeleteProduct);
router.delete('/product/:productId', isAuth, deleteProduct);

module.exports = router;
