const mysql = require("mysql2");
require('dotenv').config(); 
// Tạo Pool kết nối
const pool = mysql.createPool({
    host: process.env.MYSQLHOST,  
    user: process.env.MYSQLUSER,  
    password: process.env.MYSQL_ROOT_PASSWORD,  
    database: process.env.MYSQL_DATABASE,  
    port: process.env.MYSQLPORT  
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
