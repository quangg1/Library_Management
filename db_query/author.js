const mysql = require("mysql2");

// Kết nối đến cơ sở dữ liệu
const connection = mysql.createConnection({
    host: "localhost",
    user: "root",
    password: "01012004",
    database: "librabry_management"
});

// Hàm lấy dữ liệu sách
function getAuthorByBook(bookId, callback) {
    const query = `
        SELECT a.* FROM all_authors a
        JOIN all_book b ON a.author_id = b.author_id
        WHERE b.book_id = ?
    `;

    connection.query(query, [bookId], (err, results) => {
        if (err) {
            callback(err, null);
        } else {
            callback(null, results);
        }
    });
}



module.exports = { getAuthorByBook};

