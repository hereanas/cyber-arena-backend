const express = require('express');
const { Pool } = require('pg');
const cors = require('cors'); // استدعاء مكتبة الجسر
require('dotenv').config(); // تحميل المتغيرات من ملف .env
const app = express();
const port = 3000;

const bcrypt = require('bcrypt');
const jsonwebtoken = require('jsonwebtoken');

// مفتاح سري جداً لتوقيع تصاريح الدخول (المفروض بالشركات يكون مخفي في ملف .env)
const JWT_SECRET = 'Super_Secret_CTF_Key_2026_!@#';

// السماح للواجهة حقتنا (React) إنها تتصل بالسيرفر بدون ما يكرشها المتصفح
app.use(cors());

// مهم جداً: هذا السطر يخلي السيرفر يفهم البيانات اللي تجي بصيغة JSON من واجهة React
app.use(express.json()); 
app.use(express.urlencoded({ extended: true }));


const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});

// 1. API جلب التحديات
app.get('/api/challenges', async (req, res) => {
    try {
        const result = await pool.query('SELECT id, title, description, points FROM challenges');
        res.json(result.rows);
    } catch (err) {
        res.status(500).json({ error: 'Server error' });
    }
}); 

// 2. API جلب لوحة الصدارة
app.get('/api/leaderboard', async (req, res) => {
    try {
        const result = await pool.query('SELECT username, score FROM users ORDER BY score DESC LIMIT 10');
        res.json(result.rows);
    } catch (err) {
        res.status(500).json({ error: 'Server error' });
    }
});

// 3. API التحقق من الـ Flag (الحين يرجع JSON بدل واجهات HTML)
app.post('/api/submit', async (req, res) => {
    const { flag: userFlag, username } = req.body;

    try {
        const challengeQuery = 'SELECT * FROM challenges WHERE flag = $1';
        const challengeResult = await pool.query(challengeQuery, [userFlag]);

        if (challengeResult.rows.length === 0) {
            return res.status(400).json({ status: 'error', message: '❌ الـ Flag غلط! حاول مرة ثانية.' });
        }

        const challenge = challengeResult.rows[0]; 

        let userQuery = 'SELECT id, score FROM users WHERE username = $1';
        let userResult = await pool.query(userQuery, [username]);
        
        if (userResult.rows.length === 0) {
            const insertUser = 'INSERT INTO users (username, score) VALUES ($1, 0) RETURNING id, score';
            userResult = await pool.query(insertUser, [username]);
        }
        
        const user = userResult.rows[0]; 

        const checkSubmission = 'SELECT * FROM submissions WHERE user_id = $1 AND challenge_id = $2';
        const submissionResult = await pool.query(checkSubmission, [user.id, challenge.id]);

        if (submissionResult.rows.length > 0) {
            return res.status(400).json({ status: 'warning', message: '⚠️ حليت هذا التحدي مسبقاً! لا تحاول تخدع النظام.' });
        }

        await pool.query('INSERT INTO submissions (user_id, challenge_id) VALUES ($1, $2)', [user.id, challenge.id]);
        const updateScore = 'UPDATE users SET score = score + $1 WHERE id = $2 RETURNING score';
        const finalUserResult = await pool.query(updateScore, [challenge.points, user.id]);
        
        res.json({ 
            status: 'success', 
            message: `✅ كفو! الـ Flag صحيح لتحدي ${challenge.title}`, 
            points: challenge.points,
            newScore: finalUserResult.rows[0].score
        });

    } catch (err) {
        res.status(500).json({ status: 'error', message: 'حصل خطأ في السيرفر!' });
    }
});

// 🟢 مسار تسجيل حساب جديد
app.post('/api/register', async (req, res) => {
  const { username, password } = req.body;
  try {
    // 1. التشفير: نخلط الباسورد بـ 10 طبقات حماية (Salt) عشان الهاكرز ما يقدرون يقرونه
    const hashedPassword = await bcrypt.hash(password, 10);

    // 2. الحفظ في قاعدة البيانات
    const result = await pool.query(
      'INSERT INTO users (username, password, score) VALUES ($1, $2, 0) RETURNING id, username',
      [username, hashedPassword]
    );

    // 3. إصدار تصريح الدخول (Token)
    const token = jsonwebtoken.sign({ id: result.rows[0].id, username }, JWT_SECRET, { expiresIn: '24h' });

    res.json({ status: 'success', message: 'تم تسجيل الحساب بنجاح!', token });
  } catch (err) {
    if (err.code === '23505') { // كود الخطأ في PostgreSQL لو الاسم موجود مسبقاً
      res.status(400).json({ status: 'warning', message: 'هذا الهاكر مسجل عندنا من قبل، اختر اسم ثاني أو سجل دخول!' });
    } else {
      console.error(err);
      res.status(500).json({ status: 'error', message: 'خطأ داخلي في السيرفر' });
    }
  }
});

// 🔵 مسار تسجيل الدخول
app.post('/api/login', async (req, res) => {
  const { username, password } = req.body;
  try {
    // 1. نبحث عن الهاكر في قاعدة البيانات
    const result = await pool.query('SELECT * FROM users WHERE username = $1', [username]);
    const user = result.rows[0];

    // إذا الاسم مو موجود
    if (!user) {
      return res.status(400).json({ status: 'error', message: 'بيانات الدخول غير صحيحة! ACCESS DENIED' });
    }

    // 2. نقارن الباسورد اللي دخله بالـ (الطلاسم) المشفرة في الداتا بيس
    const validPassword = await bcrypt.compare(password, user.password);
    if (!validPassword) {
      return res.status(400).json({ status: 'error', message: 'بيانات الدخول غير صحيحة! ACCESS DENIED' });
    }

    // 3. إصدار تصريح الدخول (Token) بعد نجاح التحقق
    const token = jsonwebtoken.sign({ id: user.id, username: user.username }, JWT_SECRET, { expiresIn: '24h' });

    res.json({ status: 'success', message: 'Welcome back, Operative.', token });
  } catch (err) {
    console.error(err);
    res.status(500).json({ status: 'error', message: 'خطأ داخلي في السيرفر' });
  }
});


app.listen(port, () => {
    console.log(`🚀 API السيرفر جاهز ومستعد لاستقبال الطلبات على: http://localhost:${port}`);
});