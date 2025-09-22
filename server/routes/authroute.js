import express from "express"
import {register, login, logout} from "../controllers/authcontroller.js"
import AuthUser from "../middleware/userauth.js";
import {sendverifyotp, verifyemail, isAuthenticated } from "../controllers/authcontroller.js";

const authrouter = express.Router();

authrouter.post('/register',register);
authrouter.post('/login',login);
authrouter.get('/logout',logout);
authrouter.post('/verifyemail',AuthUser,verifyemail);
authrouter.post('/sendverifyotp',AuthUser, sendverifyotp);
authrouter.get('/isAuthenticated',AuthUser, isAuthenticated);


export default authrouter;