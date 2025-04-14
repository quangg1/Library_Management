const db = require("./db");
const bcrypt = require("bcryptjs");

const authenticateUser = (username, password, callback) => {
    const sql = "SELECT * FROM users WHERE username = ?";

    db.query(sql, [username], async (err, results) => {
        if (err) return callback(err, null);
        if (results.length === 0) return callback(null, false);

        // Kiểm tra mật khẩu đã mã hóa
        const user = results[0];
        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) return callback(null, false);

        return callback(null, user);
    });
};

module.exports = { authenticateUser };