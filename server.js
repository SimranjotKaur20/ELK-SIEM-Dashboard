const express = require('express');
const path = require('path');
const app = express();
const PORT = process.env.PORT || 3000;

// Serve static assets from the current root directory
app.use(express.static(__dirname));

// Direct any routing back to index.html
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'index.html'));
});

app.listen(PORT, () => {
  console.log(`==================================================`);
  console.log(`   SIEM Dashboard Simulator is running!`);
  console.log(`   URL: http://localhost:${PORT}`);
  console.log(`==================================================`);
});
