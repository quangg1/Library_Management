const mysql = require("mysql2");


// Cấu hình kết nối MySQL
const pool = mysql.createConnection({
    host: "localhost",      // Địa chỉ MySQL
    user: "root",           // Username MySQL
    password: "01012004",           // Mật khẩu MySQL
    database: "Librabry_Management"        // Tên database
});

// Kết nối MySQL
const db = pool.promise();
db.connect((err) => {
    if (err) {
        console.error("Lỗi kết nối MySQL:", err);
    } else {
        console.log("Đã kết nối MySQL");
    }
});
module.exports = db;