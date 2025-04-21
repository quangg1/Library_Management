const mysql = require("mysql2");
const pool = mysql.createConnection({
    host: process.env.DB_HOST,  
    user: process.env.DB_USER,  
    password: process.env.DB_PASSWORD,  
    database: process.env.DB_NAME,  
    port: process.env.DB_PORT 
});

function getBookSeriesByAuthor(bookSeriesId, callback) {
    const query = `
        SELECT a.\`book series\`
        FROM all_book_series a
        LEFT JOIN all_authors b ON a.book_series_id = b.\`books in series\`
        WHERE b.\`books in series\` = ?
        LIMIT 1;
    `;

    console.log("📌 Query SQL chạy với bookSeriesId:", bookSeriesId);

    // Sửa connection.query() thành pool.query()
    pool.query(query, [bookSeriesId], (err, results) => {
        if (err) {
            console.error("❌ Lỗi SQL:", err);
            return callback(err, null);
        }

        console.log("✅ Kết quả SQL:", results);

        if (results.length > 0) {
            console.log("✅ book_series lấy được:", results[0]["book series"]);
            callback(null, results[0]["book series"]);
        } else {
            console.log("⚠️ Không có dữ liệu phù hợp");
            callback(null, "Không có thông tin");
        }
    });
}

module.exports = { getBookSeriesByAuthor };
