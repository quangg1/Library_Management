const mysql = require("mysql2");
require('dotenv').config(); 
// Tạo Pool kết nối
const pool = mysql.createPool({
    host: process.env.DB_HOST,  
    user: process.env.DB_USER,  
    password: process.env.DB_PASSWORD,  
    database: process.env.DB_NAME,  
    port: process.env.DB_PORT 
});

// Kiểm tra kết nối
pool.getConnection((err, connection) => {
    if (err) {
        console.error("Lỗi kết nối MySQL:", err);
    } else {
        console.log("Đã kết nối MySQL");
        connection.release();  // Giải phóng kết nối sau khi kiểm tra
    }
});

module.exports = pool;
