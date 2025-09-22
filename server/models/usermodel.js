import mongoose from "mongoose";

const userschema = new mongoose.Schema({
  name: {type :String, required: true},
  email: {type :String, required: true,unique:true},
  password: {type :String, required: true},
  verifyotp: {type:String, default:''},
  otpexpireat: {type:Number, default:0},
  isverified: {type:Boolean, default:false},
  resetotp: {type:String, default:''},
  resetotpexpireat: {type:Number, default:''}

})
const usermodel =mongoose.models.user || mongoose.model('user', userschema);
export default usermodel;
