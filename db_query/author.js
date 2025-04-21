require('dotenv').config(); 
const mysql = require("mysql2");

// Tạo pool kết nối MySQL
const pool = mysql.createPool({
    host: process.env.DB_HOST,  
    user: process.env.DB_USER,  
    password: process.env.DB_PASSWORD,  
    database: process.env.DB_NAME,  
    port: process.env.DB_PORT  
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
