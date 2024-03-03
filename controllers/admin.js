const Product = require("../models/product");
const mongoDb = require("mongodb");
const { validationResult } = require("express-validator");
const ObjectId = mongoDb.ObjectId;
const fileHelper = require("../utils/file");

exports.getAddProduct = (req, res) => {
  res.render("admin/add-edit-product", {
    pageTitle: "Add Products",
    path: "/admin/add-product",
    editMode: false,
    isAuthenticated: req.session.isLoggedIn,
  });
};

exports.postAddProduct = (req, res, next) => {
  const product = new Product({
    // _id: new mongoose.Types.ObjectId('6419faedf2a0d3997fc53a29'),
    title: req.body.title,
    imageUrl: req.file.path,
    price: req.body.price,
    description: req.body.description,
    _id: req?.body?._id,
    userId: req?.session?.user,
  });

  if (!req.file) {
    return res.status(422).render("admin/add-edit-product", {
      pageTitle: "Add Product",
      path: "/admin/add-product",
      editing: false,
      hasError: true,
      product: {
        title: req.body.title,
        price: req.body.price,
        description: req.body.description,
      },
      errorMessage: "Attached file is not an image.",
      validationErrors: [],
    });
  }

  const errors = validationResult(req);

  if (!errors.isEmpty()) {
    return res.status(422).render("admin/edit-product", {
      pageTitle: "Add Product",
      path: "/admin/add-product",
      editing: false,
      hasError: true,
      product: {
        title: req.body.title,
        price: req.body.price,
        imageUrl: req.file.path,
        description: req.body.description,
      },
      errorMessage: errors.array()[0].msg,
      validationErrors: errors.array(),
    });
  }

  product
    .save()
    .then((result) => {
      res.redirect("/");
      res.redirect("/admin/products");
    })
    .catch((err) => {
      // const error = new Error('Creating product failed');
      // error.httpStatusCode = 500;
      // return next(error);
    });
};

exports.postEditProduct = (req, res, next) => {
  Product.findById(req.body?.id)
    .then((product) => {
      if (product.userId.toString() !== req.user._id.toString()) {
        return res.redirect("/");
      }
      const image = req.file;
      product.title = req.body.title;
      if (image) {
        fileHelper.deleteFile(product.imageUrl);
        product.imageUrl = image.path;
      }
      product.price = req.body.price;
      product.description = req.body.description;
      product._id = new ObjectId(req.body?.id);
      product.userId = req.user;
      return product.save().then((result) => {
        res.redirect("/admin/products");
      });
    })
    .catch((err) => {
      const error = new Error("Creating product failed");
      error.httpStatusCode = 500;

      return next(error);
    });
};

exports.getEditProduct = (req, res, next) => {
  const prodId = req.params.productId;

  Product.findById(prodId)
    .then((product) => {
      if (!product) {
        return res.redirect("/");
      }
      res.render("admin/add-edit-product", {
        pageTitle: "Edit Product",
        path: "/admin/edit-product",
        editMode: true,
        product: product,
        isAuthenticated: req.session.isLoggedIn,
      });
    })
    .catch((err) => {
      const error = new Error("Creating product failed");
      error.httpStatusCode = 500;

      return next(error);
    });
};

exports.getAdminProduct = (req, res, next) => {
  Product.find({ userId: req.user._id })
    .then((products) => {
      res.render("admin/products", {
        prods: products,
        pageTitle: "Admin Products",
        path: "/admin/products",
        isAuthenticated: req.session.isLoggedIn,
      });
    })
    .catch((err) => {
      const error = new Error("Creating product failed");
      error.httpStatusCode = 500;

      return next(error);
    });
};

exports.deleteProduct = (req, res, next) => {
  const productId = req.params.productId;

  Product.findById(productId)
    .then((prod) => {
      fileHelper.deleteFile(prod.imageUrl);
    })
    .catch((err) => console.log(err));

  Product.deleteOne({
    _id: req.params.productId,
    userId: req.user._id.toString(),
  })
    .then((result) => {
      res.status(200).json({ message: "Success!" });

      // res.redirect('/admin/products');
    })
    .catch((err) => {
      res.status(500).json({ message: "Deleting Product failed!" });
      // const error = new Error('Creating product failed');
      // error.httpStatusCode = 500;
      // console.log(err);
      // return next(error);
    });
};
