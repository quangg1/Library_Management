
const mysql = require("mysql2");
require('dotenv').config(); 
// Kết nối đến cơ sở dữ liệu
const connection = mysql.createConnection({
    host: process.env.MYSQLHOST,  
    user: process.env.MYSQLUSER,  
    password: process.env.MYSQL_ROOT_PASSWORD,  
    database: process.env.MYSQL_DATABASE,  
    port: process.env.MYSQLPORT 
});

// Hàm lấy dữ liệu sách
function getBooks(callback) {
    const query = "SELECT * FROM all_book";
    connection.query(query, (err, results) => {
        if (err) {
            callback(err, null);
        } else {
            callback(null, results);
        }
    });
}

module.exports = { getBooks };