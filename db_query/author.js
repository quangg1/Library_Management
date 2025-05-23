require('dotenv').config(); 
const mysql = require("mysql2");

// Tạo pool kết nối MySQL
const pool = mysql.createPool({
    host: process.env.MYSQLHOST,  
    user: process.env.MYSQLUSER,  
    password: process.env.MYSQL_ROOT_PASSWORD,  
    database: process.env.MYSQL_DATABASE,  
    port: process.env.MYSQLPORT 
});

// Sử dụng Promise API
const db = pool.promise(); 

// Hàm lấy dữ liệu tác giả theo bookId
async function getAuthorByBook(bookId) {
    const query = `
        SELECT a.* FROM all_authors a
        JOIN all_book b ON a.author_id = b.author_id
        WHERE b.book_id = ?
    `;
    
    try {
        const [results] = await db.query(query, [bookId]);  // Query trả về kết quả dưới dạng mảng
        return results;
    } catch (err) {
        console.error("Lỗi khi truy vấn:", err);
        throw err;
    }
}

module.exports = { getAuthorByBook };
