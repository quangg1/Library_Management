const bcrypt = require('bcrypt');
bcrypt.hash('123', 10, (err, hash) => console.log(hash));