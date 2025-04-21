
const mysql = require("mysql2");
require('dotenv').config(); 
// Kết nối đến cơ sở dữ liệu
const connection = mysql.createConnection({
    host: process.env.DB_HOST,  
    user: process.env.DB_USER,  
    password: process.env.DB_PASSWORD,  
    database: process.env.DB_NAME,  
    port: process.env.DB_PORT 
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