//find userid from token sent in cookies

import jwt from 'jsonwebtoken';

const AuthUser = async(req,res,next)=>{
  const {token} = req.cookies;
  if(!token){
    return res.json({succes:false, message:'unauthorized'});
  }
  try{
    const decoded = jwt.verify(token, process.env.JWT_secret);
    if(decoded.id){
      req.body.userid = decoded.id;
    }
    else{
      return res.json({succes:false, message:'unauthorized'});
    }
    next();

} catch(error){
  return res.json({succes:false, message:'unauthorized'});
}
}

export default AuthUser;