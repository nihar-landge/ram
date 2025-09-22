import bcrypt from 'bcryptjs';
import usermodel from '../models/usermodel.js';
import jwt from 'jsonwebtoken';
import transporter from '../config/nodemailer.js';

export const register = async(req,res)=>{
  const {name,email,password} = req.body;
  if(!name || !email || !password){
    return res.json({succes:false, message:'missing details'});
}
  try {
    const existinguser = await usermodel.findOne({email});
    if(existinguser){
       return res.json({succes:false, message:'user already exists'});
    }  
    const hashedpassword = await bcrypt.hash(password,10);
    const user = new usermodel({ name ,email,password:hashedpassword});
    await user.save(); 

    const token = jwt.sign({id : user._id}, process.env.JWT_secret, {expiresIn : '7d'});

    res.cookie('token', token, {
      httpOnly :true,
      secure : process.env.NODE_ENV === 'production',
      sameSite : process.env.NODE_ENV === 'production' ? 'none' : 'strict',
      maxAge : 7 * 24 * 60 * 60 * 1000,
    });

    //sending mail 
    const mailOptions = {
      from : process.env.sender_email,
      to : email,
      subject : "welcome to our AUTH project ",
      text : `the authentication tutorial ${name}, your account ${email} has been created successfully`
    }

    await transporter.sendMail(mailOptions);

    return res.json({succes:true, message:'Registration successful'});
  
  } catch (error) {
    return res.json({succes:false, message: error.message});
  }
}

export const login = async(req,res)=>{
  
  const {email,password} = req.body;

  if(!email || !password){
    return res.json({succes:false, message:'missing details'});
  }

  try {
    const user = await usermodel.findOne({email});

    if(!user){
      return res.json({succes:false, message:'user not found'});
    } 

    const validpassword = await bcrypt.compare(password, user.password);

    if(!validpassword){
      return res.json({succes:false, message:'invalid password'});
    }

     const token = jwt.sign({id : user._id}, process.env.JWT_secret, {expiresIn : '7d'});
     res.cookie('token', token, {
    httpOnly :true,
    secure : process.env.NODE_ENV === 'production',
    sameSite : process.env.NODE_ENV === 'production' ? 'none' : 'strict',
    maxAge : 7 * 24 * 60 * 60 * 1000,
  });

  return res.json({succes:true, message:'Login successful'});

  } catch (error){
    return res.json({succes:false, message: error.message});
  }
}


export const logout = async(req,res)=>{
  try{
    res.clearCookie('token',{
      httpOnly :true,
      secure : process.env.NODE_ENV === 'production',
      sameSite : process.env.NODE_ENV === 'production' ? 'none' : 'strict',
    });

    return res.json({succes:true, message :'logout successfully'});

  }catch(error){
    return res.json({succes:false, message: error.message});
  
  }
}

export const sendverifyotp = async(req,res)=>{
  try{

     const {userid} = req.body;
     const user = await usermodel.findById(userid);

    if(user.isverified){
      return res.json({succes:false, message:'user already verified'});
    }
    const otp = Math.floor( 100000 + Math.random()*900000);
    
    user.verifyotp = otp;
    user.expiresIn = Date.now() + 24 * 60 * 60 * 1000;
    await user.save();

    const mailOptions = {
      from : process.env.sender_email,
      to : user.email,
      subject : "Account verification OTP",
      text : `your OTP is ${otp}`
    }
    await transporter.sendMail(mailOptions);

    return res.json({succes:true, message:'OTP sent successfully'});

  }catch(error){
    return res.json({succes:false, message: error.message});
  }
}

export const verifyemail = async(req,res)=>{

  const {userid,otp} = req.body;

  if(!userid || !otp){
      return res.json({succes:false, message:'missing details'});
    }

  try{
    const user = await usermodel.findById(userid);
    if(!user){
      return res.json({succes:false, message:'user not found'});
    
    }
    if(user.verifyotp !== otp || user.verifyotp === ''){
      return res.json({succes:false, message:'invalid OTP'});
    }
    if(Date.now() > user.expiresIn){
      return res.json({succes:false, message:'OTP expired'});
    }

    user.isverified = true;
    user.verifyotp = '';
    user.expiresIn = 0;
 
    await user.save();
    return res.json({succes:true, message:'Email verified successfully'});


}catch(error){
  return res.json({succes:false, message: error.message});
}
}

//check if user is authrnticated
export const isAuthenticated = async(req,res,next)=>{
  try{
    return res.json({succes:true, message:'user is authenticated'});
  }catch(error){
    return res.json({succes:false, message: error.message});
  }
}

// reset otp 
export const resetpassotp = async(req,res)=>{
  const {email} = req.body;
  if(!email){
    return res.json({succes:false, message:'missing email'});
  
  }
  try{
    const user = await usermodel.findOne({email});
    if(!user){
      return res.json({succes:false, message:'user not found'});
    }
    const otp = Math.floor( 100000 + Math.random()*900000);
    
    user.verifyotp = otp;
    user.expiresIn = Date.now() + 24 * 60 * 60 * 1000;
    await user.save();

    const mailOptions = {
      from : process.env.sender_email,
      to : user.email,
      subject : "Account verification OTP",
      text : `your OTP is ${otp}`
    }
    await transporter.sendMail(mailOptions);

    return res.json({succes:true, message:'OTP sent successfully'});
  }catch(error){
    return res.json({succes:false, message: error.message});
  }
}