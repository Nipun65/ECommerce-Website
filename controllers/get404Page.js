exports.get404Page = (req, res, next) => {
  res.status(404).render('404', { pageTitle: 'Page not found' });
};

exports.get500Page = (req, res, next) => {
  res.status(500).render('500', { pageTitle: 'Error', path: '/500' });
};
