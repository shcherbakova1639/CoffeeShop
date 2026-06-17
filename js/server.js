const express = require("express");
const { Sequelize, DataTypes } = require("sequelize");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");

const rateLimit = require("express-rate-limit");

// === НАЛАШТУВАННЯ ОБМЕЖЕННЯ СПРОБ ВХОДУ (RATE LIMIT) ===
const loginLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // Вікно блокування: 15 хвилин
    max: 5, // Максимальна кількість спроб з однієї IP за цей час
    message: { 
        message: "Забагато спроб входу з цієї IP-адреси. Спробуйте знову через 15 хвилин." 
    },
    standardHeaders: true, // Повертає стандартну інформацію про ліміти у заголовках RateLimit-*
    legacyHeaders: false, // Вимикає застарілі заголовки X-RateLimit-*
});

const app = express();
app.use(express.json()); // Вмикаємо підтримку JSON у тілі запитів

// Розділяємо ключі для Access та Refresh токенів
const ACCESS_SECRET = "kpi_access_secret_key"; 
const REFRESH_SECRET = "kpi_refresh_secret_key"; 

// === ФУНКЦІЯ СТРУКТУРОВАНОГО ЛОГУВАННЯ ПОМИЛОК ===
const logError = (method, path, error) => {
    const timestamp = new Date().toISOString();
    // Виводимо в консоль красивий структурований лог (можна також налаштувати запис у файл)
    console.error(`[ERROR] [${timestamp}] [${method}] ${path} -> ${error.message || error}`);
};

// === ПІДКЛЮЧЕННЯ ДО MICROSOFT SQL SERVER ===
const sequelize = new Sequelize("web_backend_lab", "sa", "1111", {
    host: "localhost",
    port: 1433,
    dialect: "mssql",
    dialectOptions: {
        options: {
            encrypt: true,
            trustServerCertificate: true // Ігноруємо сертифікати для локального запуску
        }
    },
    logging: false 
});

// === ОПИС МОДЕЛІ КОРИСТУВАЧА ===
const User = sequelize.define("User", {
    id: { 
        type: DataTypes.INTEGER, 
        primaryKey: true, 
        autoIncrement: true 
    },
    email: { 
        type: DataTypes.STRING, 
        allowNull: false, 
        unique: true 
    },
    passwordHash: { 
        type: DataTypes.STRING, 
        allowNull: false, 
        field: "password_hash" // Мапінг на правильну колонку в базі даних
    },
    role: { 
        type: DataTypes.STRING, 
        defaultValue: "user" 
    },
    refreshToken: {
        type: DataTypes.STRING(500),
        allowNull: true,
        field: "refresh_token"
    },
    resetToken: {
        type: DataTypes.STRING(100),
        allowNull: true,
        field: "reset_token"
    },
    resetTokenExpires: {
        type: DataTypes.DATE,
        allowNull: true,
        field: "reset_token_expires"
    },
    isVerified: {
        type: DataTypes.BOOLEAN,
        defaultValue: false,
        field: "is_verified"
    },
    verificationToken: {
        type: DataTypes.STRING(100),
        allowNull: true,
        field: "verification_token"
    }
}, { 
    timestamps: false, 
    tableName: "users" 
});

// === МІДЛВАРІ ЗАХИСТУ ===
const authMiddleware = (req, res, next) => {
    const authHeader = req.headers["authorization"];
    const token = authHeader && authHeader.split(" ")[1];

    if (!token) {
        return res.status(401).json({ message: "Доступ заборонено. Токен відсутній." });
    }

    try {
        // Верифікація за допомогою ACCESS ключа
        const decoded = jwt.verify(token, ACCESS_SECRET);
        req.user = decoded;
        next();
    } catch (error) {
        return res.status(403).json({ message: "Невалідний або прострочений access токен." });
    }
};

const adminMiddleware = (req, res, next) => {
    if (!req.user || req.user.role !== "admin") {
        return res.status(403).json({ message: "Доступ заборонено. Потрібні права адміністратора." });
    }
    next();
};

// === МАРШРУТИ ===

app.get("/", (req, res) => {
    res.send("Сервер автентифікації працює успішно!");
});

// 1. РЕЄСТРАЦІЯ КОРИСТУВАЧА
app.post("/api/auth/register", async (req, res) => {
    try {
        const { email, password, confirmPassword } = req.body;

        if (!email || !password || !confirmPassword) {
            return res.status(400).json({ message: "Будь ласка, заповніть всі поля." });
        }

        if (password !== confirmPassword) {
            return res.status(400).json({ message: "Пароль та підтвердження пароля не збігаються." });
        }

        if (password.length < 6) {
            return res.status(400).json({ message: "Пароль має бути не менше 6 символів." });
        }

        const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
        if (!emailRegex.test(email)) {
            return res.status(400).json({ message: "Некоректний формат email." });
        }

        const userExists = await User.findOne({ where: { email } });
        if (userExists) {
            return res.status(400).json({ message: "Користувач з таким email вже існує." });
        }

        // ОГОЛОШЕННЯ ХЕШУ (Тільки один раз!)
        const hashedPassword = await bcrypt.hash(password, 10);
        
        const crypto = require("crypto");
        const vToken = crypto.randomBytes(20).toString("hex");

        const newUser = await User.create({
            email,
            passwordHash: hashedPassword,
            isVerified: false,
            verificationToken: vToken
        });

        res.status(201).json({ 
            message: "Користувача успішно зареєстровано! Будь ласка, підтвердіть ваш email.", 
            userId: newUser.id,
            verificationToken: vToken 
        });

    } catch (error) {
        logError("POST", "/api/auth/register", error);
        res.status(500).json({ message: "Помилка сервера при реєстрації.", error: error.message });
    }
});

// 2. АВТОРИЗАЦІЯ (ВХІД) – Оновлено для генерації двох токенів
app.post("/api/auth/login", loginLimiter, async (req, res) => {
    try {
        const { email, password } = req.body;

        if (!email || !password) {
            return res.status(400).json({ message: "Будь ласка, вкажіть email та пароль." });
        }

        const user = await User.findOne({ where: { email } });
        if (!user || !(await bcrypt.compare(password, user.passwordHash))) {
            return res.status(400).json({ message: "Невірний email або пароль." });
        }

        // Порівнюємо надісланий пароль із хешем у базі
        const isMatch = await bcrypt.compare(password, user.passwordHash);
        if (!isMatch) {
            return res.status(400).json({ message: "Невірний email або пароль." });
        }

        // НОВА ПЕРЕВІРКА БЕЗПЕКИ: Чи підтверджено email
        if (!user.isVerified) {
            return res.status(403).json({ message: "Доступ заборонено. Будь ласка, підтвердіть ваш email перед входом." });
        }
        // Короткостроковий Access маркер (наприклад, на 15 хвилин)
        const accessToken = jwt.sign(
            { id: user.id, email: user.email, role: user.role },
            ACCESS_SECRET,
            { expiresIn: "15m" }
        );

        // Довгостроковий Refresh маркер (наприклад, на 7 днів)
        const refreshToken = jwt.sign(
            { id: user.id },
            REFRESH_SECRET,
            { expiresIn: "7d" }
        );

        // Зберігаємо refresh токен у базу даних SQL Server
        await user.update({ refreshToken });

        res.json({ 
            message: "Вхід успішний!", 
            accessToken,
            refreshToken
        });

    } catch (error) {
    logError("POST", "/api/auth/login", error);
    res.status(500).json({ message: "Помилка сервера при вході.", error: error.message });
    }
});

// 3. ОНОВЛЕННЯ ACCESS ТОКЕНА (Refresh маршрут)
app.post("/api/auth/refresh", async (req, res) => {
    try {
        const { token } = req.body;
        if (!token) return res.status(401).json({ message: "Refresh токен відсутній." });

        const user = await User.findOne({ where: { refreshToken: token } });
        if (!user) return res.status(403).json({ message: "Невалідний refresh токен." });

        jwt.verify(token, REFRESH_SECRET, (err, decoded) => {
            if (err) return res.status(403).json({ message: "Токен прострочений або пошкоджений." });

            const newAccessToken = jwt.sign(
                { id: user.id, email: user.email, role: user.role },
                ACCESS_SECRET,
                { expiresIn: "15m" }
            );
            res.json({ accessToken: newAccessToken });
        });
    } catch (error) {
        logError("POST", "/api/auth/refresh", error);
        res.status(500).json({ message: "Помилка сервера при оновленні токена." });    }
});

// 4. ПРОФІЛЬ КОРИСТУВАЧА
app.get("/api/profile", authMiddleware, async (req, res) => {
    try {
        const user = await User.findByPk(req.user.id, {
            attributes: ["id", "email", "role"]
        });
        if (!user) return res.status(404).json({ message: "Користувача не знайдено." });
        
        res.json({
            message: "Успішний доступ до захищеного маршруту!",
            profile: user
        });
    } catch (error) {
    logError("GET", "/api/profile", error);
    res.status(500).json({ message: "Помилка сервера при отриманні профілю." });
    }
});

// 5. ОНОВЛЕННЯ ДАНИХ ПРОФІЛЮ
app.put("/api/profile/update", authMiddleware, async (req, res) => {
    try {
        const { email } = req.body;
        const userId = req.user.id;

        if (email) {
            const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
            if (!emailRegex.test(email)) {
                return res.status(400).json({ message: "Некоректний формат email." });
            }

            const emailExists = await User.findOne({ where: { email } });
            if (emailExists && emailExists.id !== userId) {
                return res.status(400).json({ message: "Цей email вже зайнятий іншим користувачем." });
            }
        }

        const user = await User.findByPk(userId);
        if (!user) {
            return res.status(404).json({ message: "Користувача не знайдено." });
        }

        if (email) user.email = email;
        await user.save();

        res.json({ 
            message: "Профіль успішно оновлено!",
            profile: { id: user.id, email: user.email, role: user.role }
        });
    } catch (error) {
        logError("PUT", "/api/profile/update", error);
        res.status(500).json({ message: "Помилка сервера при оновленні профілю." });
    }
});

// 6. АДМІН-ПАНЕЛЬ
app.get("/api/admin/dashboard", authMiddleware, adminMiddleware, (req, res) => {
    res.json({
        message: "Успішно! Вітаємо в адмін-панелі сервера.",
        secretAdminData: "Ці дані бачить лише адмін."
    });
});

// 7. ВИХІД ІЗ СИСТЕМИ (LOGOUT)
app.post("/api/auth/logout", authMiddleware, async (req, res) => {
    try {
        const user = await User.findByPk(req.user.id);
        if (!user) {
            return res.status(404).json({ message: "Користувача не знайдено." });
        }

        await user.update({ refreshToken: null });
        res.json({ message: "Успішний вихід із системи. Токен анульовано в базі даних." });
    } catch (error) {
        logError("POST", "/api/auth/logout", error);
        res.status(500).json({ message: "Внутрішня помилка сервера при спробі виходу." });
    }
});

// === МАРШРУТ: ЗМІНА ПАРОЛЯ (PUT) ===
app.put("/api/profile/change-password", authMiddleware, async (req, res) => {
    try {
        const { oldPassword, newPassword } = req.body;
        const userId = req.user.id; // Надійно отримуємо ID користувача з токена

        // 1. ВАЛІДАЦІЯ: Перевірка пустих полів
        if (!oldPassword || !newPassword) {
            return res.status(400).json({ message: "Будь ласка, вкажіть старий та новий паролі." });
        }

        // 2. ВАЛІДАЦІЯ: Перевірка довжини нового пароля
        if (newPassword.length < 6) {
            return res.status(400).json({ message: "Новий пароль має бути не менше 6 символів." });
        }

        // 3. Шукаємо користувача в базі даних SQL Server
        const user = await User.findByPk(userId);
        if (!user) {
            return res.status(404).json({ message: "Користувача не знайдено." });
        }

        // 4. ПЕРЕВІРКА: Чи збігається старий пароль із хешем у базі
        const isMatch = await bcrypt.compare(oldPassword, user.passwordHash);
        if (!isMatch) {
            return res.status(400).json({ message: "Поточний (старий) пароль вказано невірно." });
        }

        // 5. БЕЗПЕКА: Перевірка, щоб новий пароль не збігався зі старим
        if (oldPassword === newPassword) {
            return res.status(400).json({ message: "Новий пароль не може збігатися зі старим." });
        }

        // 6. ХЕШУВАННЯ ТА ЗБЕРЕЖЕННЯ
        user.passwordHash = await bcrypt.hash(newPassword, 10);
        await user.save(); // Оновлюємо рядок в базі даних

        res.json({ 
            message: "Пароль успішно змінено!" 
        });

    } catch (error) {
        logError("PUT", "/api/profile/change-password", error);
        res.status(500).json({ message: "Помилка сервера при зміні пароля." });
    }
});

app.delete("/api/profile/delete", authMiddleware, async (req, res) => {
    try {
        const { password } = req.body;
        const userId = req.user.id; // Безпечно витягуємо ID з токена

        // 1. ВАЛІДАЦІЯ: Перевірка, чи передано пароль
        if (!password) {
            return res.status(400).json({ message: "Будь ласка, вкажіть ваш пароль для підтвердження видалення." });
        }

        // 2. Пошук користувача в базі даних
        const user = await User.findByPk(userId);
        if (!user) {
            return res.status(404).json({ message: "Користувача не знайдено." });
        }

        // 3. ПЕРЕВІРКА: Чи збігається пароль із хешем у базі
        const isMatch = await bcrypt.compare(password, user.passwordHash);
        if (!isMatch) {
            return res.status(400).json({ message: "Невірний пароль. Видалення скасовано." });
        }

        // 4. ВИДАЛЕННЯ З БАЗИ ДАНИХ
        await user.destroy(); // Метод Sequelize для виконання SQL-запиту DELETE

        res.json({ 
            message: "Ваш обліковий запис було успішно видалено з бази даних." 
        });

    } catch (error) {
        // Використовуємо уніфіковане логування помилок
        logError("DELETE", "/api/profile/delete", error);
        res.status(500).json({ message: "Помилка сервера при спробі видалення акаунта." });
    }
});

app.post("/api/auth/forgot-password", async (req, res) => {
    try {
        const { email } = req.body;
        if (!email) return res.status(400).json({ message: "Будь ласка, вкажіть ваш email." });

        const user = await User.findOne({ where: { email } });
        if (!user) return res.status(404).json({ message: "Користувача з таким email не знайдено." });

        // Генеруємо випадковий унікальний токен (скидання сесії) за допомогою вбудованого модуля crypto або jwt
        const crypto = require("crypto");
        const token = crypto.randomBytes(20).toString("hex");

        // Встановлюємо термін дії токена: поточний час + 1 година
        const expires = new Date();
        expires.setHours(expires.getHours() + 1);

        // Записуємо дані в базу
        await user.update({
            resetToken: token,
            resetTokenExpires: expires
        });

        // Повертаємо токен у відповіді (імітація відправки на email)
        res.json({
            message: "Токен для відновлення пароля успішно згенеровано.",
            resetToken: token,
            info: "У реальній системі цей токен було б надіслано на вказану електронну пошту."
        });

    } catch (error) {
        logError("POST", "/api/auth/forgot-password", error);
        res.status(500).json({ message: "Помилка сервера при запиті відновлення пароля." });
    }
});

// === МАРШРУТ 2: СКИДАННЯ ПАРОЛЯ (Застосування нового пароля за токеном) ===
app.post("/api/auth/reset-password", async (req, res) => {
    try {
        const { token, newPassword } = req.body;

        if (!token || !newPassword) {
            return res.status(400).json({ message: "Необхідно надати токен та новий пароль." });
        }

        if (newPassword.length < 6) {
            return res.status(400).json({ message: "Новий пароль має бути не менше 6 символів." });
        }

        // Шукаємо користувача, у якого збігається токен І термін дії токена більший за поточний час
        const { Op } = require("sequelize");
        const user = await User.findOne({
            where: {
                resetToken: token,
                resetTokenExpires: { [Op.gt]: new Date() } // Op.gt означає "більше ніж" (Greater Than)
            }
        });

        if (!user) {
            return res.status(400).json({ message: "Токен відновлення невалідний або його термін дії закінчився." });
        }

        // Хешуємо новий пароль
        const hashedPassword = await bcrypt.hash(newPassword, 10);

        // Оновлюємо пароль та очищаємо поля токена скидання, щоб його не можна було використати вдруге
        await user.update({
            passwordHash: hashedPassword,
            resetToken: null,
            resetTokenExpires: null
        });

        res.json({ message: "Пароль успішно оновлено! Тепер ви можете увійти з новим паролем." });

    } catch (error) {
        logError("POST", "/api/auth/reset-password", error);
        res.status(500).json({ message: "Помилка сервера при скиданні пароля." });
    }
});

// === МАРШРУТ: ВЕРИФІКАЦІЯ EMAIL (GET) ===
app.get("/api/auth/verify-email", async (req, res) => {
    try {
        const { token } = req.query; // Отримуємо токен з параметрів URL (?token=...)

        if (!token) {
            return res.status(400).json({ message: "Токен верифікації відсутній." });
        }

        // Шукаємо користувача з таким токеном
        const user = await User.findOne({ where: { verificationToken: token } });
        if (!user) {
            return res.status(400).json({ message: "Невалідний або вже використаний токен підтвердження." });
        }

        // Оновлюємо статус акаунта
        await user.update({
            isVerified: true,
            verificationToken: null // Очищаємо токен
        });

        res.json({ message: "Email успішно підтверджено! Тепер ви можете увійти в систему." });

    } catch (error) {
        logError("GET", "/api/auth/verify-email", error);
        res.status(500).json({ message: "Помилка сервера при підтвердженні email." });
    }
});

const { OAuth2Client } = require("google-auth-library");
// Для лабораторної можна використати будь-який набір символів як GOOGLE_CLIENT_ID, 
// але у реальному додатку цей ID береться з Google Cloud Console
const GOOGLE_CLIENT_ID = "your-google-client-id.apps.googleusercontent.com";
const googleClient = new OAuth2Client(GOOGLE_CLIENT_ID);

// === МАРШРУТ: АВТЕНТИФІКАЦІЯ ЧЕРЕЗ OAUTH 2.0 (GOOGLE LOGIN) ===
app.post("/api/auth/google", async (req, res) => {
    try {
        const { idToken } = req.body;

        if (!idToken) {
            return res.status(400).json({ message: "id_token від Google відсутній у запиті." });
        }

        const ticket = await googleClient.verifyIdToken({
            idToken: idToken,
            audience: GOOGLE_CLIENT_ID,
        });

        const payload = ticket.getPayload();
        const googleEmail = payload.email;

        let user = await User.findOne({ where: { email: googleEmail } });

        if (!user) {
            const crypto = require("crypto");
            const randomPassword = crypto.randomBytes(16).toString("hex");
            
            // ВИПРАВЛЕНО: Використовуємо унікальне ім'я googleHashedPassword
            const googleHashedPassword = await bcrypt.hash(randomPassword, 10);

            user = await User.create({
                email: googleEmail,
                passwordHash: googleHashedPassword,
                isVerified: true, 
                role: "user"
            });
        }

        const accessToken = jwt.sign(
            { id: user.id, email: user.email, role: user.role },
            ACCESS_SECRET,
            { expiresIn: "15m" }
        );

        const refreshToken = jwt.sign(
            { id: user.id },
            REFRESH_SECRET,
            { expiresIn: "7d" }
        );

        await user.update({ refreshToken });

        res.json({
            message: "Вхід через Google успішний!",
            user: { id: user.id, email: user.email, role: user.role },
            accessToken,
            refreshToken
        });

    } catch (error) {
        logError("POST", "/api/auth/google", error);
        res.status(400).json({ message: "Невалідний id_token від Google. Авторизацію відхилено." });
    }
});
// === СИНХРОНІЗАЦІЯ МОДЕЛЕЙ ТА ЗАПУСК ===
// Додаємо { alter: true }, щоб Sequelize автоматично створив стовпчик refresh_token у базі, якщо його там ще немає
sequelize.sync({ force: true }).then(() => {
    console.log("Моделі успішно синхронізовано з SQL Server (структуру оновлено)");
    app.listen(3000, () => {
        console.log("Сервер безпеки запущено на порту 3000");
    });
}).catch(err => {
    console.error("Критична помилка старту бази даних:", err.message);
});