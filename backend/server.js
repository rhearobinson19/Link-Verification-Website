require('dotenv').config();
const express = require('express');
const cors = require('cors');
const axios = require('axios');

const app = express();
const PORT = process.env.PORT || 5000;

// Middleware
app.use(cors());
app.use(express.json());

// Route to check URL safety
app.post('/check-url', async (req, res) => {
    const { url } = req.body;

    if (!url) {
        return res.status(400).json({ error: 'URL is required' });
    }

    try {
        // Encode the URL for VirusTotal API
        const encodedUrl = Buffer.from(url).toString('base64');
        const API_KEY = process.env.VIRUSTOTAL_API_KEY;
        const endpoint = `https://www.virustotal.com/api/v3/urls/${encodedUrl}`;

        // Make the request to VirusTotal API
        const response = await axios.get(endpoint, {
            headers: {
                'x-apikey': API_KEY,
            },
        });

        const { last_analysis_stats } = response.data.data.attributes;

        res.status(200).json({
            url,
            analysis: last_analysis_stats,
        });
    } catch (error) {
        console.error('Error fetching data from VirusTotal:', error.message);

        if (error.response) {
            res.status(error.response.status).json({ error: error.response.data });
        } else {
            res.status(500).json({ error: 'Internal server error' });
        }
    }
});

app.listen(PORT, () => {
    console.log(`Server is running on http://localhost:${PORT}`);
});
