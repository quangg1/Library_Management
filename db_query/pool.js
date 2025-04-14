const mysql = require("mysql2");

// Tạo Pool kết nối
const pool = mysql.createPool({
    connectionLimit: 10,  // Số kết nối tối đa trong pool
    host: "localhost",    
    user: "root",         
    password: "01012004",  
    database: "Librabry_Management"  
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
