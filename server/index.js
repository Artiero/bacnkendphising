const express = require('express');
const cors = require('cors');
const path = require('path');
const { exec } = require('child_process');

const app = express();
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, '..', 'public'))); // Static files

// === API untuk deteksi URL ===
app.post('/api/check-url', (req, res) => {
    const url = req.body.url;
    console.log('Request body:', req.body);

    if (typeof url !== 'string' || url.trim() === '') {
        return res.status(400).json({ error: 'URL tidak valid atau kosong.' });
    }

    const scriptPath = path.join(__dirname, 'python', 'predict.py');
    console.log(`Menjalankan script: python ${scriptPath} "${url}"`);

    exec(`python "${scriptPath}" "${url}"`, (err, stdout, stderr) => {
        if (err) {
            console.error('Exec error:', err);
            return res.status(500).json({ error: 'Gagal menjalankan script Python.' });
        }

        if (stderr) {
            console.warn('Python stderr:', stderr);
        }

        try {
            const output = JSON.parse(stdout);

            if (!output || typeof output !== 'object') {
                return res.status(500).json({ error: 'Output Python tidak valid atau tidak lengkap.' });
            }

            const result = {
                url: url,
                status: output.status,
                probability_phishing: output.probability_phishing,
                whitelisted: !!output.note,
                features: output.features || {}
            };

            res.json(result);
        } catch (parseError) {
            console.error('Gagal mengurai output dari Python:', parseError);
            return res.status(500).json({ error: 'Gagal mengurai output dari Python.' });
        }
    });
});

const PORT = 5000;
app.listen(PORT, () => console.log(`Server aktif di http://localhost:${PORT}`));
