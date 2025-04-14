
const mysql = require("mysql2");

// Kết nối đến cơ sở dữ liệu
const connection = mysql.createConnection({
    host: "localhost",
    user: "root",
    password: "01012004",
    database: "librabry_management"
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