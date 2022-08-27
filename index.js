import express from "express";
import cors from 'cors';

const app = express();
const api = require('./api/api.js')

app.use("/api", )

app.listen(3000, () => {
    console.log('Express server has loaded.')
});