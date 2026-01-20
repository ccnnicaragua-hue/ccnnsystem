
import express from 'express';
import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';
import sql from 'mssql';

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'secret_prueba';

const dbConfig = {
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  server: process.env.DB_SERVER,
  database: process.env.DB_NAME,
  options: { encrypt: true, trustServerCertificate: true }
};

app.use(express.json());

function auth(req, res, next) {
  const token = req.headers['authorization'];
  if (!token) return res.sendStatus(401);
  try {
    req.user = jwt.verify(token.replace('Bearer ', ''), JWT_SECRET);
    next();
  } catch {
    res.sendStatus(401);
  }
}

app.post('/api/login', async (req, res) => {
  const { username, password } = req.body;
  const pool = await sql.connect(dbConfig);
  const r = await pool.request()
    .input('username', sql.VarChar, username)
    .query('SELECT * FROM Users WHERE username=@username');
  if (!r.recordset.length) return res.sendStatus(401);
  const user = r.recordset[0];
  if (!await bcrypt.compare(password, user.password)) return res.sendStatus(401);
  const token = jwt.sign({ id: user.id }, JWT_SECRET, { expiresIn: '2h' });
  res.json({ token });
});

app.post('/api/students', auth, async (req, res) => {
  const { nombre, curso, carrera } = req.body;
  const pool = await sql.connect(dbConfig);
  await pool.request()
    .input('nombre', sql.VarChar, nombre)
    .input('curso', sql.VarChar, curso)
    .input('carrera', sql.VarChar, carrera)
    .query('INSERT INTO Students VALUES (@nombre,@curso,@carrera)');
  res.json({ message: 'OK' });
});

app.listen(PORT, () => console.log('Running'));
