const mysql = require("mysql2");
require('dotenv').config(); 
const pool = mysql.createConnection({
    host: process.env.MYSQLHOST,  
    user: process.env.MYSQLUSER,  
    password: process.env.MYSQL_ROOT_PASSWORD,  
    database: process.env.MYSQL_DATABASE,  
    port: process.env.MYSQLPORT 
});

function getBookSeriesByAuthor(bookSeriesId, callback) {
    const query = `CALL GetBookSeriesByAuthor(?)`;

    console.log("📌 Query SQL chạy với bookSeriesId:", bookSeriesId);

    pool.query(query, [bookSeriesId], (err, results) => {
        if (err) {
            console.error("❌ Lỗi SQL:", err);
            return callback(err, null);
        }

        // ✅ Kết quả truy vấn nằm trong results[0]
        const data = results[0];

        console.log("✅ Kết quả SQL:", data);

        if (data.length > 0) {
            console.log("✅ book_series lấy được:", data[0]["book series"]);
            callback(null, data[0]["book series"]);
        } else {
            console.log("⚠️ Không có dữ liệu phù hợp");
            callback(null, "Không có thông tin");
        }
    });
}


module.exports = { getBookSeriesByAuthor };
