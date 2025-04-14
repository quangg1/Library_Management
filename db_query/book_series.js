const mysql = require("mysql2");
const connection = mysql.createConnection({
    host: "localhost",
    user: "root",
    password: "01012004",
    database: "librabry_management"
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

    // ⚠️ Sửa db.query() thành connection.query()
    connection.query(query, [bookSeriesId], (err, results) => {
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
