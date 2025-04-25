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
app.get('/borrowed-books', async (req, res) => {
    const userId = req.session.user_id;
  
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
app.post('/add-book', async (req, res) => {
    const {
      book, author, book_subject, book_publisher_name,
      image, pub_date, earliest_pub_date, language, isbn
    } = req.body;
  
    try {
      await db.query('CALL add_book(?, ?, ?, ?, ?, ?, ?, ?, ?)', [
        book,
        author,
        book_subject,
        book_publisher_name,
        image,
        pub_date,
        earliest_pub_date,
        language,
        isbn
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
        const result = await db.query("CALL get_users()"); // Gọi thủ tục get_users
        res.json(result[0]); // Kết quả từ thủ tục sẽ là mảng dữ liệu
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
// Chạy server
app.listen(PORT, '0.0.0.0', () => {
    console.log(`Server chạy tại http://localhost:${PORT}`);
});
