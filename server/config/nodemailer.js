import nodemailer from 'nodemailer';
const transporter = nodemailer.createTransport({
    host : 'smtp-relay.brevo.com',
    port : 587,
    auth : {
      user : process.env.SMTP_user,
      pass : process.env.SMTP_password,
    
    }
});

export default transporter;