const express = require("express");
const bodyParser = require("body-parser");
const path = require("path");
const mysql = require('mysql2'); 
const { authenticateUser } = require(__dirname + "/db_query/auth.js");
const { getBooks } = require(__dirname + "/db_query/books.js"); 
const db = require(__dirname + "/db_query/db.js"); 
const pool = require(__dirname + "/db_query/pool.js"); 
const app = express();
const bcrypt = require("bcryptjs"); 
const { getAuthorByBook } = require(__dirname + "/db_query/author.js");
const { getBookSeriesByAuthor } = require(__dirname + "/db_query/book_series.js");
const session = require('express-session');
// Middleware
app.use(session({
    secret: 'mysecretkey',
    resave: false,
    saveUninitialized: false,
    cookie: {
        secure: false, // Đặt thành true nếu dùng HTTPS
        httpOnly: true, 
        maxAge: 24 * 60 * 60 * 1000,
        sameSite: 'lax'
    }
}));
app.use((req, res, next) => {
    console.log('Session data:', req.session); // Log session mỗi request
    next();
});
app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, "static")));
app.use(express.json());
function checkAuth(req, res, next) {
    if (!req.session.user_id) {
        console.log('Unauthorized access - No session user_id'); // Debug
        return res.status(401).json({ success: false, message: "Bạn cần đăng nhập." });
    }
    next();
}
// Trang login
app.get("/", (req, res) => {
    res.sendFile(path.join(__dirname, "templates", "login.html"));
});
app.get("/api/session", (req, res) => {
    res.json({
        user_id: req.session.user_id || null,
    });
});
// Route để lấy dữ liệu sách
app.get("/books", (req, res) => {
    getBooks((err, books) => {
        if (err) {
            res.status(500).json({ error: "Lỗi khi lấy dữ liệu sách" });
        } else {
            res.json(books);
        }
    });
});

// Trang chính
app.get("/index.html",checkAuth, (req, res) => {
    res.sendFile(path.join(__dirname, "templates", "index.html"));
    
});
// API trả về JSON
app.get("/book/:id", checkAuth, async(req, res) => {
    console.log("Route /book/:id được gọi với ID:", req.params.id); // ✅ Thêm log này

    const bookId = req.params.id;
    const query = "SELECT * FROM all_book WHERE book_id = ?";

    try {
        const [results] = await db.execute(query, [bookId]);

        if (results.length > 0) {
            return res.json(results[0]); // ✅ Trả về dữ liệu tác giả đúng
        } else {
            return res.status(404).json({ error: "Không tìm thấy tác giả" });
        }
    } catch (err) {
        return res.status(500).json({ error: "Lỗi khi truy vấn dữ liệu tác giả" });
    }
});

// Route hiển thị file HTML
app.get("/book-detail.html",checkAuth, (req, res) => {
    res.sendFile(path.join(__dirname, "templates", "book-detail.html"));
});
// Tác giả
app.get("/author.html",checkAuth, (req, res) => {
    res.sendFile(path.join(__dirname, "templates", "author.html"));
});

app.get("/author/:id", checkAuth, async (req, res) => {
    const authorId = req.params.id;
    const query = "SELECT * FROM all_authors WHERE author_id = ?";

    try {
        // Sử dụng db.execute() hoặc db.query() với promise
        const [results] = await db.execute(query, [authorId]);

        if (results.length > 0) {
            return res.json(results[0]); // ✅ Trả về dữ liệu tác giả đúng
        } else {
            return res.status(404).json({ error: "Không tìm thấy tác giả" });
        }
    } catch (err) {
        return res.status(500).json({ error: "Lỗi khi truy vấn dữ liệu tác giả" });
    }
});
app.get("/check-author", async (req, res) => {
    const {name} = req.query;
    const [rows] = await db.query('SELECT Author_ID, author FROM all_authors WHERE author LIKE ?', [`%${name}%`]);
    res.json(rows);
})
// Chủ đề 
app.get("/subject.html",checkAuth, (req, res) => {
    res.sendFile(path.join(__dirname, "templates", "subject.html"));
});
app.get("/subject/:id",checkAuth, async(req, res) => {
    const subjectId = req.params.id;

    const query = "SELECT * FROM all_book_subjects WHERE subject_id = ?"; 

    try {
        // Sử dụng db.execute() hoặc db.query() với promise
        const [results] = await db.execute(query, [subjectId]);

        if (results.length > 0) {
            return res.json(results[0]); // ✅ Trả về dữ liệu tác giả đúng
        } else {
            return res.status(404).json({ error: "Không tìm thấy tác giả" });
        }
    } catch (err) {
        return res.status(500).json({ error: "Lỗi khi truy vấn dữ liệu tác giả" });
    }
});
app.get("/check-subject", async (req, res) => {
    const {name} = req.query;
    const [rows] = await db.query('SELECT subject_id, \`book subject\` FROM all_book_subjects WHERE \`book subject\` LIKE ?', [`%${name}%`]);
    res.json(rows);
})
// Nhà xuất bản
app.get("/book_publisher.html",checkAuth, (req, res) => {
    res.sendFile(path.join(__dirname, "templates", "book_publisher.html"));
});
app.get("/book_publisher/:id",checkAuth, async(req, res) => {
    const publisherId = req.params.id;

    const query = "SELECT * FROM all_book_publishers WHERE publisher_id = ?"; 

    try {
        // Sử dụng db.execute() hoặc db.query() với promise
        const [results] = await db.execute(query, [publisherId]);

        if (results.length > 0) {
            return res.json(results[0]); // ✅ Trả về dữ liệu tác giả đúng
        } else {
            return res.status(404).json({ error: "Không tìm thấy tác giả" });
        }
    } catch (err) {
        return res.status(500).json({ error: "Lỗi khi truy vấn dữ liệu tác giả" });
    }
});
app.get('/check-publisher', async (req, res) => {
    const { name } = req.query;
    const [rows] = await db.query('SELECT publisher_id, book_publisher FROM all_book_publishers WHERE book_publisher LIKE ?', [`%${name}%`]);
    res.json(rows);
  });
// Series
app.get("/book-series/:bookSeriesId",checkAuth, (req, res) => {
    const bookSeriesId = req.params.bookSeriesId;
    console.log("📌 bookSeriesId nhận được:", bookSeriesId); // Kiểm tra ID

    getBookSeriesByAuthor(bookSeriesId, (err, bookSeries) => {
        if (err) {
            console.error("❌ Lỗi truy vấn:", err);
            return res.status(500).json({ error: "Lỗi lấy loạt sách" });
        }
        console.log("✅ Dữ liệu trả về:", bookSeries);
        res.json({ book_series: bookSeries });
    });
});
app.get("/book-series-detail/:id",checkAuth, async(req, res) => {
    const authorId = req.params.id;

    const query = "SELECT * FROM all_book_series WHERE book_series_id = ?"; // 🔥 Truy vấn theo author_id

    try {
        // Sử dụng db.execute() hoặc db.query() với promise
        const [results] = await db.execute(query, [authorId]);

        if (results.length > 0) {
            return res.json(results[0]); // ✅ Trả về dữ liệu tác giả đúng
        } else {
            return res.status(404).json({ error: "Không tìm thấy tác giả" });
        }
    } catch (err) {
        return res.status(500).json({ error: "Lỗi khi truy vấn dữ liệu tác giả" });
    }
});
app.get("/book_series.html",checkAuth, (req, res) => {
    res.sendFile(path.join(__dirname, "templates", "book_series.html"));
});
// Phần login user
app.post('/login',(req, res) => {
    const { email, password } = req.body;

    if (!email || !password) {
        return res.status(400).json({ success: false, message: "Email và mật khẩu không được để trống!" });
    }

    pool.getConnection((err, connection) => {
        if (err) {
            console.error("Lỗi kết nối database:", err);
            return res.status(500).json({ success: false, message: "Lỗi máy chủ!" });
        }

        const query = `
            SELECT role, User_ID AS id, Full_Name AS name, Email, Sinh_vien, Giao_vien, Password 
            FROM user WHERE Email = ?
            UNION
            SELECT role, EmployeeID AS id, Full_Name AS name, Email, Null as Sinh_vien, Null as Giao_vien, Password 
            FROM employee WHERE Email = ?
        `;

        connection.query(query, [email, email], (err, results) => {
            connection.release();

            if (err) {
                console.error("Lỗi truy vấn:", err);
                return res.status(500).json({ success: false, message: "Lỗi máy chủ!" });
            }

            if (results.length === 0) {
                return res.status(404).json({ success: false, message: "Email không tồn tại trong hệ thống!" });
            }

            const user = results[0];

            bcrypt.compare(password, user.Password, (err, isMatch) => {
                if (err) {
                    console.error("Lỗi kiểm tra mật khẩu:", err);
                    return res.status(500).json({ success: false, message: "Lỗi máy chủ!" });
                }

                if (!isMatch) {
                    return res.status(401).json({ success: false, message: "Mật khẩu không chính xác!" });
                }

                // Thiết lập session cho người dùng
                req.session.user_id = user.id;
                req.session.role = user.role;
                req.session.email = user.email;
                // Xác định nếu là Sinh viên hay Giáo viên
                let userType = 'user'; // Mặc định là user
                if (user.Sinh_vien === 1) {
                    userType = 'sinhvien';
                } else if (user.Giao_vien === 1) {
                    userType = 'giaovien';
                } else {
                    // Chỉ có trong bảng employee
                    if (user.role === 'admin') {
                        userType = 'admin';
                    } else if (user.role === 'employee') {
                        userType = 'employee';
                    }
                }
                req.session.save(err => {
                    if (err) {
                      console.error('Lỗi lưu session:', err);
                      return res.status(500).json({ success: false, message: "Lỗi server" });
                    }
                    res.json({
                        success: true,
                        message: "Đăng nhập thành công!",
                        role: user.role,
                        userId: user.id,
                        email: user.email,
                        fullName: user.name,
                        userType: userType 
                    });
                });
            });
        });
    });
});


app.post('/check-unique', (req, res) => {
    const { email, phone } = req.body;

    pool.getConnection((err, connection) => {
        if (err) {
            console.error('Error getting connection:', err.message);
            return res.status(500).json({ success: false, message: 'Lỗi server: ' + err.message });
        }

        // Kiểm tra email
        connection.query('SELECT * FROM user WHERE Email = ?', [email], (err, emailRows) => {
            if (err) {
                connection.release();
                console.error('Error checking email:', err.message);
                return res.status(500).json({ success: false, message: 'Lỗi server: ' + err.message });
            }

            if (emailRows.length > 0) {
                connection.release();
                return res.json({ success: false, message: 'email_exists' });
            }

            // Kiểm tra phone
            connection.query('SELECT * FROM user WHERE Phone_number = ?', [phone], (err, phoneRows) => {
                if (err) {
                    connection.release();
                    console.error('Error checking phone:', err.message);
                    return res.status(500).json({ success: false, message: 'Lỗi server: ' + err.message });
                }

                if (phoneRows.length > 0) {
                    connection.release();
                    return res.json({ success: false, message: 'phone_exists' });
                }

                connection.release();
                res.json({ success: true });
            });
        });
    });
});

// API để xử lý đăng ký
app.post('/register', (req, res) => {
    const { userID, fullName, email, password, phone, sinhvien, giaovien } = req.body;
    console.log(req.body);

    if (!password) {
        return res.status(400).json({ success: false, message: "Mật khẩu không được để trống!" });
    }

    pool.getConnection((err, connection) => {
        if (err) {
            console.error("Error getting connection:", err.message);
            return res.status(500).json({ success: false, message: "Lỗi server: " + err.message });
        }

        // Kiểm tra User_ID có bị trùng không
        connection.query('SELECT * FROM user WHERE User_ID = ?', [userID], (err, userIdRows) => {
            if (err) {
                connection.release();
                console.error("Error checking UserID:", err.message);
                return res.status(500).json({ success: false, message: "Lỗi server: " + err.message });
            }

            if (userIdRows.length > 0) {
                connection.release();
                return res.json({ success: false, message: "MSSV/MSGV đã tồn tại!" });
            }

            if (sinhvien === 1 && giaovien === 1) {
                connection.release();
                return res.json({ success: false, message: "Chỉ được chọn một vai trò: Sinh viên hoặc Giáo viên!" });
            }
            if (sinhvien === 0 && giaovien === 0) {
                connection.release();
                return res.json({ success: false, message: "Phải chọn một vai trò: Sinh viên hoặc Giáo viên!" });
            }

            // Mã hóa mật khẩu
            const saltRounds = 10;
            bcrypt.hash(password, saltRounds, (err, hashedPassword) => {
                if (err || !hashedPassword) {
                    connection.release();
                    console.error("Lỗi khi mã hóa mật khẩu:", err ? err.message : "Mật khẩu không hợp lệ");
                    return res.status(500).json({ success: false, message: "Lỗi khi mã hóa mật khẩu!" });
                }

                // Thêm người dùng mới vào database
                const insertQuery = `
                    INSERT INTO user (User_ID, Full_Name, Email, Password, Phone_number, Sinh_vien, Giao_vien)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                `;

                const values = [userID, fullName, email, hashedPassword, phone, sinhvien, giaovien];

                connection.query(insertQuery, values, (err, result) => {
                    connection.release();
                    if (err) {
                        console.error("Lỗi khi chèn người dùng:", err.message);
                        return res.status(500).json({ success: false, message: "Đăng ký thất bại!" });
                    }

                    return res.json({ success: true, message: "Đăng ký thành công!" });
                });
            });
        });
    });
});

// Lấy thông tin người dùng
app.get("/current-user", checkAuth, async (req, res) => {
    const userId = req.session.user_id;

    if (!userId) {
        return res.status(401).json({ error: "Chưa đăng nhập" });
    }

    try {
        // Ưu tiên lấy từ bảng employee
        const employeeQuery = "SELECT Full_Name, email, Phone_number, role FROM employee WHERE EmployeeID = ?";
        const [empResults] = await db.query(employeeQuery, [userId]);

        if (empResults.length > 0) {
            return res.json(empResults[0]);  // Trả về dữ liệu từ bảng employee nếu có
        } else {
            // Nếu không có trong employee thì lấy từ user
            const userQuery = "SELECT Full_Name, email, Phone_number, role FROM user WHERE User_ID = ?";
            const [userResults] = await db.query(userQuery, [userId]);

            if (userResults.length > 0) {
                return res.json(userResults[0]);
            } else {
                return res.status(404).json({ error: "Không tìm thấy người dùng" });
            }
        }
    } catch (err) {
        console.error("Lỗi khi truy vấn dữ liệu người dùng:", err);
        return res.status(500).json({ error: "Lỗi máy chủ" });
    }
});

app.get("/login", (req, res) => {
    res.sendFile(__dirname + "/templates/login.html");
});
app.get("/user_profile",checkAuth, (req, res) => {
    if (!req.session.user_id) {
        return res.redirect("/login"); // chuyển hướng nếu chưa đăng nhập
    }

    res.sendFile(__dirname + "/templates/user_profile.html");
});
app.put("/update-user",checkAuth, async (req, res) => {
    const { Full_Name, email, Phone_number } = req.body;
    const userId = req.session.user_id;

    if (!userId) {
        return res.status(401).json({ error: "Chưa đăng nhập" });
    }

    const query = `UPDATE user SET Full_Name = ?, Email = ?, Phone_number = ? WHERE User_ID = ?`;

    try {
        // Thực thi câu lệnh UPDATE
        const [result] = await db.query(query, [Full_Name, email, Phone_number, userId]);

        // Kiểm tra kết quả cập nhật
        if (result.affectedRows === 0) {
            return res.status(404).json({ error: "Không tìm thấy người dùng để cập nhật" });
        }

        return res.json({ message: "Cập nhật thành công" });
    } catch (err) {
        console.error("Lỗi khi cập nhật:", err);
        return res.status(500).json({ error: "Lỗi máy chủ" });
    }
});

// Thay đổi mật khẩu
app.put('/change-password', async (req, res) => {
    const userId = req.session.user_id;
    const { current_password, new_password } = req.body;

    if (!userId) {
        return res.status(401).json({ success: false, error: "Bạn chưa đăng nhập." });
    }

    if (!current_password || !new_password) {
        return res.status(400).json({ success: false, error: "Thiếu thông tin." });
    }

    try {
        // Lấy hash password từ DB
        const sqlGet = "SELECT password FROM user WHERE User_ID = ?";
        const [results] = await db.query(sqlGet, [userId]);

        if (results.length === 0) {
            return res.status(404).json({ success: false, error: "Không tìm thấy người dùng." });
        }

        const hashedPassword = results[0].password;

        // So sánh password nhập với hash
        const match = await bcrypt.compare(current_password, hashedPassword);
        if (!match) {
            return res.status(403).json({ success: false, error: "Mật khẩu hiện tại không đúng." });
        }

        // Hash mật khẩu mới
        const newHashedPassword = await bcrypt.hash(new_password, 10);

        // Cập nhật mật khẩu
        const sqlUpdate = "UPDATE user SET password = ? WHERE User_ID = ?";
        await db.query(sqlUpdate, [newHashedPassword, userId]);

        return res.json({ success: true, message: "Đổi mật khẩu thành công!" });
    } catch (err) {
        console.error("Lỗi khi xử lý yêu cầu đổi mật khẩu:", err);
        return res.status(500).json({ success: false, error: "Lỗi máy chủ khi đổi mật khẩu." });
    }
});

app.get('/change_password.html',checkAuth, (req, res) => {
    res.sendFile(__dirname + "/templates/change_password.html");
  });
// Mượn sách
app.post("/borrow", async (req, res) => {
    const userId = req.session.user_id;
    const { bookId } = req.body;

    if (!userId) {
        return res.status(401).json({ error: "Bạn cần đăng nhập để mượn sách." });
    }

    if (!bookId) {
        return res.status(400).json({ error: "Thiếu mã sách." });
    }

    const borrowDate = new Date();
    const returnDate = new Date(); // giả sử trả sau 14 ngày
    returnDate.setDate(returnDate.getDate() + 14);

    const query = `
        INSERT INTO borrow (User_ID, Book_ID, Borrow_Date, Return_Date, Status)
        VALUES (?, ?, ?, ?, 'Đang mượn')
    `;

    try {
        await db.query(query, [userId, bookId, borrowDate, returnDate]);
        res.json({ success: true, message: "Mượn sách thành công!" });
    } catch (err) {
        console.error("Lỗi khi mượn sách:", err);
        res.status(500).json({ error: "Không thể mượn sách." });
    }
});

// Lấy danh sách sách đã mượn
app.get('/borrowed-books', async (req, res) => {
    const userId = req.session.user_id;
    if (!userId) return res.status(401).json({ message: "Chưa đăng nhập" });

    const query = `
      SELECT 
      b.Borrow_ID, b.Borrow_Date, b.Return_Date, b.Status,
      ab.book, ab.author
      FROM borrow b
      JOIN all_book ab ON b.Book_ID = ab.book_id
      WHERE b.User_ID = ?
    `;
  
    try {
        const results = await db.query(query, [userId]);
        res.json(results);
    } catch (err) {
        return res.status(500).json({ message: "Lỗi server", error: err });
    }
});
// Tra sach
app.delete("/return-book/:id", async (req, res) => {
    const borrowId = req.params.id;
    const sql = `
      UPDATE borrow
      SET Status = 'Đã trả', Actual_Return_Date = CURDATE()
      WHERE Borrow_ID = ?
    `;

    try {
        await db.query(sql, [borrowId]);
        res.json({ message: "Trả sách thành công!" });
    } catch (err) {
        console.error("Lỗi khi trả sách:", err);
        return res.status(500).json({ error: "Lỗi server khi trả sách" });
    }
});

// Thêm sách
app.post('/add-book', async (req, res) => {
    const {
      book, author, book_subject, book_publisher_name,
      image, pub_date, earliest_pub_date, language, isbn
    } = req.body;

    if (!author || !book_subject || !book_publisher_name) {
      return res.status(400).send('Thiếu thông tin tác giả, chủ đề hoặc nhà xuất bản');
    }

    const trimLower = str => str ? str.trim().toLowerCase() : '';

    const insertOrGetId = async (table, column, value) => {
      const querySelect = `SELECT ${table}_id AS id FROM ${table} WHERE ${column} = ?`;
      const results = await db.query(querySelect, [value]);

      if (results.length > 0) {
        return results[0].id;
      }

      const queryInsert = `INSERT INTO ${table} (${column}) VALUES (?)`;
      const result = await db.query(queryInsert, [value]);
      return result.insertId;
    };

    try {
      const author_id = await insertOrGetId('all_authors', 'author', trimLower(author));
      const subject_id = await insertOrGetId('all_book_subjects', 'book_subject', trimLower(book_subject));
      const publisher_id = await insertOrGetId('all_book_publishers', 'book_publisher', trimLower(book_publisher_name));

      const insertBookQuery = `
        INSERT INTO all_book (
          book, author_id, subject_id, image, \`publication date\`,
          \`earliest publication date\`, language, isbn, publisher_id
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
      `;

      await db.query(insertBookQuery, [
        book, author_id, subject_id, image,
        pub_date, earliest_pub_date, language, isbn, publisher_id
      ]);

      res.redirect('/add-book.html');
    } catch (err) {
      console.error('Lỗi thêm sách:', err);
      return res.status(500).send('Thêm sách thất bại');
    }
});


  
// Sửa sách
app.post('/edit-book', async (req, res) => {
    const { book, author, book_subject, book_publisher, image, pub_date, language, earliest_pub_date, ISBN, book_id } = req.body;

    const query = `
      UPDATE all_book
      SET book = ?, author = ?, \`book subject\` = ?, \`book publisher\` = ?, image = ?, \`publication date\` = ?, language = ?, \`earliest publication date\` = ?, ISBN = ?
      WHERE book_id = ?
    `;

    try {
        await db.query(query, [book, author, book_subject, book_publisher, image, pub_date, language, earliest_pub_date, ISBN, book_id]);
        res.redirect('/edit-book.html');
    } catch (err) {
        console.error('Lỗi khi cập nhật sách:', err);
        return res.status(500).send('Cập nhật sách thất bại.');
    }
});

app.delete('/delete-book/:id', async (req, res) => {
    const bookId = req.params.id;

    try {
        await db.query('DELETE FROM books WHERE book_id = ?', [bookId]);
        res.json({ success: true });
    } catch (err) {
        return res.status(500).json({ error: err.message });
    }
})
app.get('/employee_home.html',checkAuth,(req, res) => {
    res.sendFile(path.join(__dirname, 'templates', 'employee_home.html'));
  });
  app.get('/add-book.html',checkAuth, (req, res) => {
    res.sendFile(path.join(__dirname, 'templates', 'add-book.html'));
});

app.get('/edit-book.html',checkAuth, (req, res) => {
    res.sendFile(path.join(__dirname, 'templates', 'edit-book.html'));
});
// Chạy server
app.listen(3000, () => {
    console.log("Server chạy tại http://localhost:3000");
});
