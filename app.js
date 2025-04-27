const express = require("express")
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
const multer = require('multer');
const upload = multer();
require('dotenv').config();
const PORT = process.env.PORT || 3000;
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
app.get("/book/:id", checkAuth, async (req, res) => {
    console.log("Route /book/:id được gọi với ID:", req.params.id);

    const bookId = req.params.id;
    const query = "CALL GetBookById(?)";

    try {
        const [results] = await db.execute(query, [bookId]);

        // Kết quả trả về từ thủ tục sẽ nằm trong mảng [0]
        if (results[0].length > 0) {
            return res.json(results[0][0]);
        } else {
            return res.status(404).json({ error: "Không tìm thấy tác giả" });
        }
    } catch (err) {
        console.error("Lỗi khi gọi thủ tục:", err);
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
    const query = "Call GetAuthor(?)";

    try {
        // Sử dụng db.execute() hoặc db.query() với promise
        const [results] = await db.execute(query, [authorId]);
        const data = results[0];

        if (data.length > 0) {
            return res.json(data[0]); // ✅ Trả về dữ liệu tác giả đúng
        } else {
            return res.status(404).json({ error: "Không tìm thấy tác giả" });
        }
    } catch (err) {
        return res.status(500).json({ error: "Lỗi khi truy vấn dữ liệu tác giả" });
    }
});
app.get("/check-author", async (req, res) => {
    const { name } = req.query;
    const query = "CALL SearchAuthorBeLike(?)";

    try {
        const [rows] = await db.execute(query, [name]);
        res.json(rows[0]); // rows[0] chứa dữ liệu chính
    } catch (err) {
        console.error("Lỗi khi gọi thủ tục SearchAuthorByName:", err);
        res.status(500).json({ error: "Lỗi khi truy vấn tác giả" });
    }
});
// Chủ đề 
app.get("/subject.html",checkAuth, (req, res) => {
    res.sendFile(path.join(__dirname, "templates", "subject.html"));
});
app.get("/subject/:id",checkAuth, async(req, res) => {
    const subjectId = req.params.id;

    const query = "Call GetSubject (?)"; 

    try {
        // Sử dụng db.execute() hoặc db.query() với promise
        const [results] = await db.execute(query, [subjectId]);
        const data = results[0];

        if (data.length > 0) {
            return res.json(data[0]); // ✅ Trả về dữ liệu tác giả đúng
        } else {
            return res.status(404).json({ error: "Không tìm thấy tác giả" });
        }
    } catch (err) {
        return res.status(500).json({ error: "Lỗi khi truy vấn dữ liệu tác giả" });
    }
});
app.get("/check-subject", async (req, res) => {
    const {name} = req.query;
    const [rows] = await db.query('Call SearchSubjectBeLike(?)', name);
    res.json(rows[0]);
})
// Nhà xuất bản
app.get("/book_publisher.html",checkAuth, (req, res) => {
    res.sendFile(path.join(__dirname, "templates", "book_publisher.html"));
});
////// Code mẫu gọi thủ tục hàm//////
app.get("/book_publisher/:id", checkAuth, async (req, res) => {
    const publisherId = req.params.id;

    try {
        const [results] = await db.query("CALL GetPublisherById(?)", [publisherId]);

        if (results[0].length > 0) {
            return res.json(results[0][0]); // ✅ Trả về 1 record
        } else {
            return res.status(404).json({ error: "Không tìm thấy nhà xuất bản" });
        }
    } catch (err) {
        console.error(err);
        return res.status(500).json({ error: "Lỗi khi gọi stored procedure" });
    }
});
app.get('/check-publisher', async (req, res) => {
    const { name } = req.query;
    const [rows] = await db.query('Call SearchBookPublishertBeLike (?)', name);
    res.json(rows[0]);
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
app.get("/book-series-detail/:id", checkAuth, async (req, res) => {
    const authorId = req.params.id;

    try {
        const [results] = await db.query("CALL GetBookSeriesDetail(?)", [authorId]);

        if (results[0].length > 0) {
            return res.json(results[0][0]);
        } else {
            return res.status(404).json({ error: "Không tìm thấy tác giả" });
        }
    } catch (err) {
        console.error(err);
        return res.status(500).json({ error: "Lỗi khi gọi thủ tục trong database" });
    }
});
app.get("/book_series.html",checkAuth, (req, res) => {
    res.sendFile(path.join(__dirname, "templates", "book_series.html"));
});
// Phần login user, va phan biet userType
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
                let userType;

if (user.role === 'Admin') {
    userType = 'admin';
} else if (user.role === 'Employee') {
    userType = 'employee';
} else if (user.Sinh_vien === 1) {
    userType = 'sinhvien';
} else if (user.Giao_vien === 1) {
    userType = 'giaovien';
} else {
    userType = 'user'; // fallback nếu không khớp cái nào
}
                req.session.userType = userType;
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
app.get('/user_type', (req, res) => {
    const userType = req.session.userType; 
    const userId=req.session.user_id ;
    const role=req.session.role;
    res.json({ userType, userId,role });
});
// Kiem tra tinh dach cua email va phone
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
        const employeeQuery = "CALL GetUserInfo(?)";
        const [empResults] = await db.query(employeeQuery, [userId]);

        if (empResults.length > 0) {
            return res.json(empResults[0]);
        } else {
            return res.status(404).json({ error: "Không tìm thấy người dùng" });
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
app.put("/update-user", checkAuth, async (req, res) => {
    const { Full_Name, email, Phone_number } = req.body;
    const userId = req.session.user_id;

    if (!userId) {
        return res.status(401).json({ error: "Chưa đăng nhập" });
    }

    const query = `CALL update_user_info(?, ?, ?, ?)`;

    try {
        // Gọi thủ tục hàm để cập nhật thông tin người dùng
        const [result] = await db.query(query, [userId, Full_Name, email, Phone_number]);

        // Kiểm tra kết quả
        if (result.length > 0) {
            return res.json({ message: "Cập nhật thành công" });
        } else {
            return res.status(404).json({ error: "Không tìm thấy người dùng để cập nhật" });
        }
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
app.get('/borrowed-books',checkAuth, async (req, res) => {
    const userId = req.query.user_id;
  
    if (!userId) {
      return res.status(400).json({ error: "Thiếu user_id" });
    }
  
    const query = "CALL GetBorrowedBooksByUser(?)";
  
    try {
      const [results] = await db.query(query, [userId]);
      res.json([results[0]]); // CALL trả mảng 2 chiều
    } catch (err) {
      console.error("Lỗi gọi stored procedure:", err);
      res.status(500).json({ error: 'Lỗi máy chủ' });
    }
  });
  
  
  app.post("/borrow", async (req, res) => {
    const userId = req.session.user_id;
    const userType = req.session.userType;
    const { bookId } = req.body;

    if (!userId) {
        return res.status(401).json({ error: "Bạn cần đăng nhập để mượn sách." });
    }

    if (!bookId) {
        return res.status(400).json({ error: "Thiếu mã sách." });
    }

    try {
        await db.query("CALL borrow_book(?, ?, ?)", [userId, userType, bookId]);
        res.json({ success: true, message: "Mượn sách thành công!" });
    } catch (err) {
        console.error("Lỗi khi mượn sách:", err);
        res.status(500).json({ error: "Không thể mượn sách." });
    }
});

// Lấy danh sách sách đã mượn
app.post('/add-book', upload.none(), async (req, res) => {
    const {
      book, author, book_subject, book_publisher_name,
      image, pub_date, earliest_pub_date, language, isbn,
      permission_level   // ✅ Lấy thêm permission_level từ form
    } = req.body;
  
    try {
      await db.query('CALL add_book(?, ?, ?, ?, ?, ?, ?, ?, ?, ?)', [
        book,
        author,
        book_subject,
        book_publisher_name,
        image,
        pub_date,
        earliest_pub_date,
        language,
        isbn,
        permission_level    // ✅ Thêm vào tham số cuối cùng
      ]);
      res.json({ message: 'Thêm sách thành công' });
    } catch (err) {
      console.error(err);
      res.status(500).json({ message: 'Thêm sách thất bại hoặc dữ liệu không hợp lệ' });
    }
  });
// Trả sách
app.patch('/update-return-date/:borrowId', async (req, res) => {
    const borrowId = req.params.borrowId;
    const { Actual_Return_Date } = req.body;
  
    try {
      // Kiểm tra định dạng ngày trả có hợp lệ không (ví dụ: dd/mm/yyyy)
      const [month, day, year] = Actual_Return_Date.split('/');
      if (month < 1 || month > 12 || day < 1 || day > 31) {
        return res.status(400).json({ message: 'Ngày trả không hợp lệ' });
      }
  
      // Chuyển đổi ngày từ chuỗi sang định dạng Date (yyyy-mm-dd)
      const dateObj = new Date(year, month - 1, day);
      const formattedDate = dateObj.toLocaleDateString('en-CA'); // 'yyyy-mm-dd'
  
      // Gọi thủ tục đã tạo để cập nhật ngày trả sách
      await db.query('CALL update_actual_return_date(?, ?)', [borrowId, formattedDate]);
  
      res.json({ message: 'Cập nhật ngày trả sách thành công' });
    } catch (error) {
      console.error(error);
      res.status(500).json({ message: 'Lỗi khi cập nhật ngày trả sách' });
    }
  });

  
// Sửa sách
app.post('/edit-book', async (req, res) => {
    const { book, author, book_subject, book_publisher, image, pub_date, language, earliest_pub_date, ISBN, book_id } = req.body;
  
    try {
      // Gọi thủ tục để cập nhật thông tin sách
      await db.query('CALL update_book_info(?, ?, ?, ?, ?, ?, ?, ?, ?, ?)', [
        book, author, book_subject, book_publisher, image, pub_date, language, earliest_pub_date, ISBN, book_id
      ]);
      res.redirect('/edit-book.html');
    } catch (err) {
      console.error('Lỗi khi cập nhật sách:', err);
      return res.status(500).send('Cập nhật sách thất bại.');
    }
  });

  app.delete('/delete-book/:id', async (req, res) => {
    const bookId = req.params.id;

    try {
        // Gọi thủ tục để xóa sách
        await db.query('CALL delete_book(?)', [bookId]);
        res.json({ success: true });
    } catch (err) {
        console.error('Lỗi khi xóa sách:', err);
        return res.status(500).json({ error: err.message });
    }
});

app.get('/employee_home.html',checkAuth,(req, res) => {
    res.sendFile(path.join(__dirname, 'templates', 'employee_home.html'));
  });
  app.get('/add-book.html',checkAuth, (req, res) => {
    res.sendFile(path.join(__dirname, 'templates', 'add-book.html'));
});

app.get('/edit-book.html',checkAuth, (req, res) => {
    res.sendFile(path.join(__dirname, 'templates', 'edit-book.html'));
});

//// Quản lí nhân viên và người dùng ////
app.get('/management', checkAuth, (req, res) => {
    res.sendFile(path.join(__dirname, 'templates', 'management.html'));
});
// Lấy danh sách người dùng
app.get("/users", async (req, res) => {
    try {
        const [rows] = await db.query("CALL get_users()");
        res.json(rows[0]); // chỉ trả về mảng dữ liệu chính, không nested
    } catch (err) {
        console.error("Lỗi khi lấy users:", err);
        res.status(500).json({ error: "Lỗi server khi lấy danh sách người dùng" });
    }
});

// Lấy danh sách nhân viên
app.get("/employees", async (req, res) => {
    try {
        const result = await db.query("CALL get_employees()"); // Gọi thủ tục get_employees
        res.json(result[0]); // Kết quả từ thủ tục sẽ là mảng dữ liệu
    } catch (err) {
        console.error("Lỗi khi lấy employees:", err);
        res.status(500).json({ error: "Lỗi server khi lấy danh sách nhân viên" });
    }
});
// Xóa nhân viên và người dùng
// Xóa người dùng
app.delete("/delete-user/:id", async (req, res) => {
    const { id } = req.params;
    try {
        // Gọi thủ tục xóa người dùng
        await db.query("CALL delete_user(?)", [id]);
        res.sendStatus(200);
    } catch (err) {
        console.error("Lỗi xóa user:", err);
        res.status(500).json({ error: "Lỗi khi xóa người dùng" });
    }
});

// Xóa nhân viên
app.delete("/delete-employee/:id", async (req, res) => {
    const { id } = req.params;
    try {
        // Gọi thủ tục xóa nhân viên
        await db.query("CALL delete_employee(?)", [id]);
        res.sendStatus(200);
    } catch (err) {
        console.error("Lỗi xóa employee:", err);
        res.status(500).json({ error: "Lỗi khi xóa nhân viên" });
    }
});
//// Thông tin phạt ////
app.get('/fine-detail/:borrowId', async (req, res) => {
    const { borrowId } = req.params;
    const role = req.session.user?.role || "user"; // fallback nếu chưa đăng nhập
  
    try {
      const result = await db.query("CALL GetFineDetail(?)", [borrowId]);
      res.json({ fine: result[0][0], userRole: role });
    } catch (err) {
      console.error(err);
      res.status(500).json({ error: "Lỗi khi lấy thông tin phạt." });
    }
  });
app.get('/fine_detail.html',checkAuth, (req, res) => {
    res.sendFile(path.join(__dirname, 'templates', 'fine_detail.html'));
});
app.get('/get-fines/:borrowId', checkAuth, async (req, res) => {
    const { borrowId } = req.params; // Lấy Borrow_ID từ URL
    const role = req.session.user?.role || "user";

    // Kiểm tra borrowId hợp lệ
    if (isNaN(borrowId) || borrowId === 'null') {
        return res.status(400).json({ message: 'Borrow_ID không hợp lệ.' });
    }

    try {
        // Gọi stored procedure để lấy thông tin phiếu phạt theo Borrow_ID
        const [fines] = await db.query('CALL GetFineByFineId(?)', [borrowId]);

        res.json({ fines, userRole: role });
    } catch (error) {
        console.error(error);
        res.status(500).json({ message: 'Lỗi khi lấy dữ liệu phiếu phạt.' });
    }
});
// Update phiếu phat
app.post('/update-fine', checkAuth, upload.none(), async (req, res) => {
    try {
        // Kiểm tra dữ liệu nhận được từ req.body
        console.log("Received data:", req.body);

        const { Fine_ID, User_ID, Book_ID, Mat_sach, Hu_hong, Fine_amount, Da_thanh_toan, so_ngay_tre_han } = req.body;

        // Gọi thủ tục UpdateFine
        const query = `CALL UpdateFine(?, ?, ?, ?, ?, ?, ?)`;
        const [rows, fields] = await db.query(query, [Fine_ID, User_ID, Book_ID, Mat_sach, Hu_hong,Da_thanh_toan, so_ngay_tre_han]);

        console.log("Result from CALL:", rows);

        res.json({ message: 'Cập nhật phiếu phạt thành công' });

    } catch (error) {
        console.error(error);
        res.status(500).json({ message: 'Lỗi không xác định khi cập nhật phiếu phạt.' });
    }
});
// Gia hạn ngày mượn
app.patch('/extend-loan/:borrowId', async (req, res) => {
    const { borrowId } = req.params;
    let { newReturnDate } = req.body;

    // Chuyển đổi ngày từ M/D/YYYY sang YYYY-MM-DD
    const [month, day, year] = newReturnDate.split('/');
    const formattedDate = `${year}-${month.padStart(2, '0')}-${day.padStart(2, '0')}`;

    try {
        const [rows] = await db.query('CALL UpdateReturnDate(?, ?)', [borrowId, formattedDate]);

        // Kiểm tra kết quả, nếu thành công sẽ có kết quả trả về
        res.json({ message: 'Đã gia hạn sách thành công' });
    } catch (err) {
        console.error(err);
        res.status(500).json({ message: 'Cập nhật thất bại' });
    }
});
// Lấy số lần gia hạn
app.get('/get-renew/:borrowId', async (req, res) => {
    const borrowId = req.params.borrowId;
    try {
        // Gọi stored procedure để lấy thông tin mượn sách
        const [rows] = await db.query('CALL GetBorrowById(?)', [borrowId]);

        // Kiểm tra nếu không tìm thấy bản ghi
        if (rows.length === 0) {
            return res.status(404).json({ message: 'Không tìm thấy thông tin mượn sách' });
        }

        // Trả về toàn bộ thông tin của bản ghi (bao gồm tất cả các cột từ bảng borrow)
        res.json(rows[0]); // rows[0] chứa bản ghi đầu tiên
    } catch (err) {
        console.error(err);
        res.status(500).json({ message: 'Lỗi khi lấy thông tin mượn sách' });
    }
});
// Chạy server
app.listen(PORT, '0.0.0.0', () => {
    console.log(`Server chạy tại http://localhost:${PORT}`);
});
// Nhân viên
app.get("/add-employee.html", checkAuth, (req, res) => {
    res.sendFile(path.join(__dirname, "templates", "add-employee.html"));
});
// Người dùng
app.get("/add-user.html", checkAuth, (req, res) => {
    res.sendFile(path.join(__dirname, "templates", "add-user.html"));
});
// Tác giả
app.get("/add-author.html",checkAuth, (req, res) => {
    res.sendFile(path.join(__dirname, "templates", "add-author.html"));
});
// Nhà xuất bản
app.get("/add-publisher.html", checkAuth, (req, res) => {
    res.sendFile(path.join(__dirname, "templates", "add-publisher.html"));
});
// Thêm nhân viên 
app.post('/add-employee', upload.none(), checkAuth, async (req, res) => {
    const { fullName, email, password, phone, role } = req.body;
    console.log("Received data:", req.body);

    if (!fullName || !email || !password || !role) {
        return res.status(400).json({ success: false, message: "Tất cả các trường bắt buộc phải được điền!" });
    }

    try {
        // Lấy Admin_ID từ session (giả sử admin đang đăng nhập)
        const adminId = req.session.user_id || null; // Nếu không có admin, để NULL

        // Kiểm tra email có bị trùng không (đã có trong thủ tục, nhưng có thể kiểm tra trước để tối ưu)
        const [emailRows] = await db.query('SELECT * FROM employee WHERE Email = ?', [email]);
        if (emailRows.length > 0) {
            return res.status(400).json({ success: false, message: "Email đã tồn tại!" });
        }

        // Kiểm tra số điện thoại có bị trùng không (nếu cần)
        if (phone) {
            const [phoneRows] = await db.query('SELECT * FROM employee WHERE Phone_number = ?', [phone]);
            if (phoneRows.length > 0) {
                return res.status(400).json({ success: false, message: "Số điện thoại đã tồn tại!" });
            }
        }

        // Mã hóa mật khẩu
        const hashedPassword = await bcrypt.hash(password, 10);

        // Thêm nhân viên vào database
        await db.query('CALL add_employee(?, ?, ?, ?, ?, ?)', [
            adminId,      // Admin_ID từ session
            fullName,     // Full_Name
            email,        // Email
            phone || null, // Phone_number (cho phép NULL)
            role,         // Role (Employee hoặc Admin)
            hashedPassword // Password đã mã hóa
        ]);

        res.json({ success: true, message: "Thêm nhân viên thành công!" });
    } catch (err) {
        console.error("Lỗi khi thêm nhân viên:", err);
        res.status(500).json({ success: false, message: err.sqlMessage || "Lỗi máy chủ!" });
    }
});
// Thêm người dùng
app.post('/add-user', upload.none(), checkAuth, async (req, res) => {
    const { userId, fullName, email, password, phone, role } = req.body;
    console.log("Received data:", req.body);

    if (!userId || !fullName || !email || !password || !phone || !role) {
        return res.status(400).json({ success: false, message: "Tất cả các trường đều bắt buộc!" });
    }

    try {
        // Kiểm tra User_ID có bị trùng không
        const [userIdRows] = await db.query('SELECT * FROM user WHERE User_ID = ?', [userId]);
        if (userIdRows.length > 0) {
            return res.status(400).json({ success: false, message: "Mã người dùng đã tồn tại!" });
        }

        // Kiểm tra email có bị trùng không
        const [emailRows] = await db.query('SELECT * FROM user WHERE Email = ?', [email]);
        if (emailRows.length > 0) {
            return res.status(400).json({ success: false, message: "Email đã tồn tại!" });
        }

        // Kiểm tra số điện thoại có bị trùng không
        const [phoneRows] = await db.query('SELECT * FROM user WHERE Phone_number = ?', [phone]);
        if (phoneRows.length > 0) {
            return res.status(400).json({ success: false, message: "Số điện thoại đã tồn tại!" });
        }

        // Ánh xạ vai trò
        const sinhvien = role === 'sinhvien' ? 1 : 0;
        const giaovien = role === 'giaovien' ? 1 : 0;

        // Mã hóa mật khẩu
        const hashedPassword = await bcrypt.hash(password, 10);

        // Thêm người dùng vào database
        await db.query('CALL add_user(?, ?, ?, ?, ?, ?, ?)', [
            userId,
            fullName,
            email,
            hashedPassword,
            phone,
            sinhvien,
            giaovien
        ]);

        res.json({ success: true, message: "Thêm người dùng thành công!" });
    } catch (err) {
        console.error("Lỗi khi thêm người dùng:", err);
        res.status(500).json({ success: false, message: err.sqlMessage || "Lỗi máy chủ!" });
    }
});
// Thêm tác giả
app.post('/add-author', upload.none(), checkAuth, async (req, res) => {
    const { authorId, author, birthDate, deathDate, numberOfBooks, firstPublicationDate, lastPublicationDate, booksInSeries } = req.body;
    console.log("Received data:", req.body);

    if (!authorId || !author) {
        return res.status(400).json({ success: false, message: "Mã tác giả và tên tác giả là bắt buộc!" });
    }

    try {
        // Kiểm tra Author_ID có bị trùng không
        const [authorIdRows] = await db.query('SELECT * FROM all_authors WHERE Author_ID = ?', [authorId]);
        if (authorIdRows.length > 0) {
            return res.status(400).json({ success: false, message: "Mã tác giả đã tồn tại!" });
        }

        // Thêm tác giả vào database
        await db.query('CALL add_author(?, ?, ?, ?, ?, ?, ?, ?)', [
            authorId,
            author,
            birthDate || null,
            deathDate || null,
            numberOfBooks || null,
            firstPublicationDate || null,
            lastPublicationDate || null,
            booksInSeries || null
        ]);

        res.json({ success: true, message: "Thêm tác giả thành công!" });
    } catch (err) {
        console.error("Lỗi khi thêm tác giả:", err);
        res.status(500).json({ success: false, message: err.sqlMessage || "Lỗi máy chủ!" });
    }
});
app.post('/check-author-id', async (req, res) => {
    const { authorId } = req.body;

    try {
        const [rows] = await db.query('SELECT * FROM all_authors WHERE Author_ID = ?', [authorId]);
        if (rows.length > 0) {
            return res.json({ success: false, message: 'author_id_exists' });
        }
        res.json({ success: true });
    } catch (err) {
        console.error("Lỗi khi kiểm tra Author_ID:", err);
        res.status(500).json({ success: false, message: "Lỗi máy chủ!" });
    }
});
// Thêm nhà xuất bản
app.post('/add-publisher', upload.none(), checkAuth, async (req, res) => {
    const { book_publisher, number_of_books_published, earliest_publication_date, latest_publication_date } = req.body;
    console.log(req.body); 
    if (!book_publisher || !number_of_books_published || !earliest_publication_date || !latest_publication_date) {
        return res.status(400).json({ success: false, message: "Tất cả các trường đều bắt buộc!" });
    }

    try {
        await db.query('CALL add_publisher(?, ?, ?, ?)', [
            book_publisher,
            number_of_books_published,
            earliest_publication_date,
            latest_publication_date
        ]);

        res.json({ success: true, message: "Thêm nhà xuất bản thành công!" });
    } catch (err) {
        console.error("Lỗi khi thêm nhà xuất bản:", err);
        res.status(500).json({ success: false, message: err.sqlMessage || "Lỗi máy chủ!" });
    }
});
// Thêm subject
// Hiển thị form thêm môn học
app.get("/add-subject.html", checkAuth, (req, res) => {
    res.sendFile(path.join(__dirname, "templates", "add-subject.html"));
});

// Thêm chủ đề
app.post('/add-subject', upload.none(), checkAuth, async (req, res) => {
    const { bookSubject, numberOfAuthors, numberOfBooks } = req.body;
    console.log("Received data:", req.body);

    if (!bookSubject || !numberOfAuthors || !numberOfBooks) {
        return res.status(400).json({ success: false, message: "Tất cả các trường đều bắt buộc!" });
    }

    try {
        // Thêm môn học vào database
        await db.query('CALL add_subject(?, ?, ?)', [
            bookSubject,
            parseInt(numberOfAuthors), // Chuyển sang số nguyên
            parseInt(numberOfBooks)    // Chuyển sang số nguyên
        ]);

        res.json({ success: true, message: "Thêm chủ đề thành công!" });
    } catch (err) {
        console.error("Lỗi khi thêm chủ đề:", err);
        res.status(500).json({ success: false, message: err.sqlMessage || "Lỗi máy chủ!" });
    }
});

// API endpoint đăng ký người dùng - Cách 2: Sử dụng stored procedure từ file SQL
app.post("/register-user-procedure", async (req, res) => {
    const { userID, fullName, email, password, phone, sinhvien, giaovien } = req.body;

    try {
        // Băm password
        const hashedPassword = await bcrypt.hash(password, 10);

        // Kết nối database
        const connection = await mysql.createConnection(dbConfig);

        // Xác định loại tài khoản dựa vào thông tin đăng ký
        let accountType = 'user'; // Mặc định là user
        if (giaovien) {
            accountType = 'employee';
        }

        // Gọi procedure register_new_account từ file SQL
        await connection.query('CALL register_new_account(?, ?, ?, ?, ?)', [
            userID, // p_username 
            password, // p_password (procedure sẽ tự hash password)
            fullName, // p_full_name
            email, // p_email
            accountType // p_account_type
        ]);

        await connection.end();

        res.status(201).json({ message: 'Đăng ký người dùng thành công! Vui lòng chờ phê duyệt.' });
    } catch (error) {
        console.error('Lỗi đăng ký user:', error.message);
        res.status(400).json({ message: 'Đăng ký người dùng thất bại!', error: error.message });
    }
});

// API để admin phê duyệt tài khoản
app.post("/admin/approve-account", async (req, res) => {
    const { registrationId, adminUsername } = req.body;

    try {
        const connection = await mysql.createConnection(dbConfig);

        await connection.query('CALL approve_account(?, ?)', [
            registrationId,
            adminUsername
        ]);

        await connection.end();

        res.status(200).json({ message: 'Tài khoản đã được phê duyệt thành công' });
    } catch (error) {
        console.error('Lỗi phê duyệt tài khoản:', error.message);
        res.status(400).json({ message: 'Phê duyệt tài khoản thất bại', error: error.message });
    }
});

// API để employee phê duyệt tài khoản user
app.post("/employee/approve-user", async (req, res) => {
    const { registrationId, employeeUsername } = req.body;

    try {
        const connection = await mysql.createConnection(dbConfig);

        await connection.query('CALL employee_approve_user(?, ?)', [
            registrationId,
            employeeUsername
        ]);

        await connection.end();

        res.status(200).json({ message: 'Tài khoản user đã được phê duyệt thành công' });
    } catch (error) {
        console.error('Lỗi phê duyệt tài khoản:', error.message);
        res.status(400).json({ message: 'Phê duyệt tài khoản thất bại', error: error.message });
    }
});

// API để xem danh sách yêu cầu đăng ký (dành cho admin)
app.get("/admin/registration-requests", async (req, res) => {
    try {
        const connection = await mysql.createConnection(dbConfig);

        const [rows] = await connection.query('CALL view_registration_requests()');

        await connection.end();

        res.status(200).json(rows[0]);
    } catch (error) {
        console.error('Lỗi lấy danh sách đăng ký:', error.message);
        res.status(400).json({ message: 'Không thể lấy danh sách đăng ký', error: error.message });
    }
});

// API để xem danh sách yêu cầu đăng ký user (dành cho employee)
app.get("/employee/user-registration-requests", async (req, res) => {
    try {
        const connection = await mysql.createConnection(dbConfig);

        const [rows] = await connection.query('CALL view_user_registration_requests()');

        await connection.end();

        res.status(200).json(rows[0]);
    } catch (error) {
        console.error('Lỗi lấy danh sách đăng ký user:', error.message);
        res.status(400).json({ message: 'Không thể lấy danh sách đăng ký user', error: error.message });
    }
});

// API để admin thêm nhân viên mới
app.post("/admin/add-employee", async (req, res) => {
    try {
        const { adminId, fullName, email, phone, role, password } = req.body;

        // Kiểm tra xem người dùng có quyền admin không
        // Code kiểm tra quyền admin có thể thêm vào đây

        // Mã hóa mật khẩu
        const hashedPassword = await bcrypt.hash(password, 10);

        // Kết nối database
        const connection = await mysql.createConnection(dbConfig);

        // Gọi procedure add_employee
        await connection.query('CALL add_employee(?, ?, ?, ?, ?, ?)', [
            adminId,        // Admin_ID từ session
            fullName,       // Full_Name
            email,          // Email
            phone || null,  // Phone_number (cho phép NULL)
            role,           // Role (Employee hoặc Admin)
            hashedPassword  // Password đã mã hóa
        ]);

        await connection.end();

        res.status(201).json({ success: true, message: 'Thêm nhân viên mới thành công!' });
    } catch (err) {
        console.error("Lỗi khi thêm nhân viên:", err);
        res.status(500).json({ success: false, message: err.sqlMessage || 'Lỗi máy chủ!' });
    }
});

// API để lấy danh sách tất cả nhân viên
app.get("/admin/employees", async (req, res) => {
    try {
        const connection = await mysql.createConnection(dbConfig);

        // Truy vấn danh sách nhân viên
        const [rows] = await connection.query('SELECT * FROM employee');

        await connection.end();

        res.status(200).json({ success: true, data: rows });
    } catch (err) {
        console.error("Lỗi khi lấy danh sách nhân viên:", err);
        res.status(500).json({ success: false, message: err.sqlMessage || 'Lỗi máy chủ!' });
    }
});

// API để lấy thông tin một nhân viên cụ thể
app.get("/admin/employees/:employeeId", async (req, res) => {
    try {
        const { employeeId } = req.params;
        const connection = await mysql.createConnection(dbConfig);

        // Truy vấn thông tin nhân viên
        const [rows] = await connection.query('SELECT * FROM employee WHERE Employee_ID = ?', [employeeId]);

        await connection.end();

        if (rows.length === 0) {
            return res.status(404).json({ success: false, message: 'Không tìm thấy nhân viên' });
        }

        res.status(200).json({ success: true, data: rows[0] });
    } catch (err) {
        console.error("Lỗi khi lấy thông tin nhân viên:", err);
        res.status(500).json({ success: false, message: err.sqlMessage || 'Lỗi máy chủ!' });
    }
});

// API để cập nhật thông tin nhân viên
app.put("/admin/employees/:employeeId", async (req, res) => {
    try {
        const { employeeId } = req.params;
        const { fullName, email, phone, role } = req.body;

        const connection = await mysql.createConnection(dbConfig);

        // Cập nhật thông tin nhân viên
        await connection.query(
            'UPDATE employee SET Full_Name = ?, Email = ?, Phone_number = ?, Role = ? WHERE Employee_ID = ?',
            [fullName, email, phone || null, role, employeeId]
        );

        await connection.end();

        res.status(200).json({ success: true, message: 'Cập nhật thông tin nhân viên thành công' });
    } catch (err) {
        console.error("Lỗi khi cập nhật thông tin nhân viên:", err);
        res.status(500).json({ success: false, message: err.sqlMessage || 'Lỗi máy chủ!' });
    }
});

// API để đổi mật khẩu nhân viên
app.patch("/admin/employees/:employeeId/change-password", async (req, res) => {
    try {
        const { employeeId } = req.params;
        const { newPassword } = req.body;

        // Mã hóa mật khẩu mới
        const hashedPassword = await bcrypt.hash(newPassword, 10);

        const connection = await mysql.createConnection(dbConfig);

        // Cập nhật mật khẩu
        await connection.query(
            'UPDATE employee SET Password = ? WHERE Employee_ID = ?',
            [hashedPassword, employeeId]
        );

        await connection.end();

        res.status(200).json({ success: true, message: 'Đổi mật khẩu thành công' });
    } catch (err) {
        console.error("Lỗi khi đổi mật khẩu nhân viên:", err);
        res.status(500).json({ success: false, message: err.sqlMessage || 'Lỗi máy chủ!' });
    }
});

// API để xóa nhân viên
app.delete("/admin/employees/:employeeId", async (req, res) => {
    try {
        const { employeeId } = req.params;
        const connection = await mysql.createConnection(dbConfig);

        // Xóa nhân viên
        await connection.query('DELETE FROM employee WHERE Employee_ID = ?', [employeeId]);

        await connection.end();

        res.status(200).json({ success: true, message: 'Xóa nhân viên thành công' });
    } catch (err) {
        console.error("Lỗi khi xóa nhân viên:", err);
        res.status(500).json({ success: false, message: err.sqlMessage || 'Lỗi máy chủ!' });
    }
});

// API để nhân viên lấy thông tin cá nhân
app.get("/employee/profile", async (req, res) => {
    try {
        const employeeId = req.employee.id; // Giả sử có middleware xác thực jwt đã gán thông tin nhân viên

        const connection = await mysql.createConnection(dbConfig);

        // Lấy thông tin nhân viên từ ID trong token xác thực
        const [rows] = await connection.query(
            'SELECT Employee_ID, Full_Name, Email, Phone_number, Role FROM employee WHERE Employee_ID = ?',
            [employeeId]
        );

        await connection.end();

        if (rows.length === 0) {
            return res.status(404).json({ success: false, message: 'Không tìm thấy thông tin nhân viên' });
        }

        res.status(200).json({ success: true, data: rows[0] });
    } catch (err) {
        console.error("Lỗi khi lấy thông tin cá nhân:", err);
        res.status(500).json({ success: false, message: err.sqlMessage || 'Lỗi máy chủ!' });
    }
});

// API để nhân viên cập nhật thông tin cá nhân
app.put("/employee/profile", async (req, res) => {
    try {
        const employeeId = req.employee.id; // Giả sử có middleware xác thực jwt đã gán thông tin nhân viên
        const { fullName, phone } = req.body; // Chỉ cho phép cập nhật một số thông tin

        const connection = await mysql.createConnection(dbConfig);

        // Cập nhật thông tin cá nhân
        await connection.query(
            'UPDATE employee SET Full_Name = ?, Phone_number = ? WHERE Employee_ID = ?',
            [fullName, phone || null, employeeId]
        );

        await connection.end();

        res.status(200).json({ success: true, message: 'Cập nhật thông tin cá nhân thành công' });
    } catch (err) {
        console.error("Lỗi khi cập nhật thông tin cá nhân:", err);
        res.status(500).json({ success: false, message: err.sqlMessage || 'Lỗi máy chủ!' });
    }
});

// API để nhân viên đổi mật khẩu
app.patch("/employee/change-password", async (req, res) => {
    try {
        const employeeId = req.employee.id; // Giả sử có middleware xác thực jwt đã gán thông tin nhân viên
        const { currentPassword, newPassword } = req.body;

        const connection = await mysql.createConnection(dbConfig);

        // Kiểm tra mật khẩu hiện tại
        const [rows] = await connection.query('SELECT Password FROM employee WHERE Employee_ID = ?', [employeeId]);

        if (rows.length === 0) {
            await connection.end();
            return res.status(404).json({ success: false, message: 'Không tìm thấy thông tin nhân viên' });
        }

        const passwordMatch = await bcrypt.compare(currentPassword, rows[0].Password);

        if (!passwordMatch) {
            await connection.end();
            return res.status(400).json({ success: false, message: 'Mật khẩu hiện tại không đúng' });
        }

        // Mã hóa mật khẩu mới
        const hashedPassword = await bcrypt.hash(newPassword, 10);

        // Cập nhật mật khẩu mới
        await connection.query(
            'UPDATE employee SET Password = ? WHERE Employee_ID = ?',
            [hashedPassword, employeeId]
        );

        await connection.end();

        res.status(200).json({ success: true, message: 'Đổi mật khẩu thành công' });
    } catch (err) {
        console.error("Lỗi khi đổi mật khẩu:", err);
        res.status(500).json({ success: false, message: err.sqlMessage || 'Lỗi máy chủ!' });
    }
});