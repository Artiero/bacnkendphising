const express = require('express');
const cors = require('cors');
const path = require('path');
const { exec } = require('child_process');

const app = express();
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, '..', 'public')));

app.get('/', (req, res) => {
  res.send('API deteksi phishing aktif. Gunakan POST ke /api/check-url');
});

app.post('/api/check-url', (req, res) => {
  const url = req.body.url;
  if (!url || typeof url !== 'string') {
    return res.status(400).json({ error: 'URL tidak valid.' });
  }

  const scriptPath = path.join(__dirname, 'python', 'predict.py');
  const scriptDir = path.dirname(scriptPath);

  exec(
    `python3 "${scriptPath}" "${url}"`,
    { cwd: scriptDir, maxBuffer: 10 * 1024 * 1024 },
    (err, stdout, stderr) => {
      if (err) {
        console.error('Exec error:', err);
        return res.status(500).json({ error: 'Gagal menjalankan script Python.' });
      }
      if (stderr) console.warn('Python stderr:', stderr);

      try {
        const output = JSON.parse(stdout);
        res.json({
          prediction: output.result,
          probability: output.proba,
          whitelisted: !!output.note,
          features: output.features || {}
        });
      } catch (parseError) {
        console.error('JSON parse error:', parseError, stdout);
        res.status(500).json({ error: 'Output Python bukan JSON valid.' });
      }
    }
  );
});

const PORT = process.env.PORT || 5000;
const HOST = '0.0.0.0';
app.listen(PORT, HOST, () =>
  console.log(`Server aktif di http://${HOST}:${PORT}`)
);
