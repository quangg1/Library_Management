const mysql = require("mysql2");
require('dotenv').config(); 

// Cấu hình kết nối MySQL (sử dụng pool để quản lý kết nối)
const pool = mysql.createPool({
    host: process.env.DB_HOST,  
    user: process.env.DB_USER,  
    password: process.env.DB_PASSWORD,  
    database: process.env.DB_NAME,  
    port: process.env.DB_PORT
});

// Sử dụng Promise API
const db = pool.promise();  // Đảm bảo db trả về một promise

// Kiểm tra kết nối
async function testConnection() {
    try {
        const [rows, fields] = await db.query("SELECT 1");  // Chỉ cần thực hiện một query đơn giản để kiểm tra kết nối
        console.log("Đã kết nối MySQL");
    } catch (err) {
        console.error("Lỗi kết nối MySQL:", err);
    }
}

testConnection();

module.exports = db;
