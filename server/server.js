import express from "express"
import cors from "cors"
import 'dotenv/config';
import cookieParser from "cookie-parser";
import connectDB from "./config/mongodb.js";
import authrouter from "./routes/authroute.js";


const app = express();
const port = process.env.PORT || 4000
connectDB();

app.use(express.json());
app.use(cookieParser());
app.use(cors({credentials: true}));


//API endpoints
app.get('/',(req,res)=>{
  res.send('API working')
})
app.use('/api/auth', authrouter);

app.listen(port, ()=>{
  console.log(`server started on PORT : ${port}, http://localhost:${port}`)
});
