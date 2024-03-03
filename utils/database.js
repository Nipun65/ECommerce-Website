const mongodb = require("mongodb");

const mongoClient = mongodb.MongoClient;
let _db;

const mongoConnect = (callBack) => {
  mongoClient
    .connect(process.env.CONNECTION_STRING)
    .then((result) => {
      _db = result.db();

      callBack(result);
    })
    .catch((err) => {
      console.log(err);
      throw err;
    });
};

const getDb = () => {
  if (_db) {
    return _db;
  }
  throw "No database found";
};

exports.mongoConnect = mongoConnect;
exports.getDb = getDb;
