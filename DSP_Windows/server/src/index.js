require('dotenv').config();
const app = require('./app');
const { PORT } = require('./config');

app.listen(PORT, () => {
  console.log(`[Server] DSP API 서버 실행 중: http://localhost:${PORT}`);
});
