import Mailgen from "mailgen";
import nodemailer from "nodemailer";


const sendEmail = async (option) => {
    const mailGenerator = new Mailgen({
        theme: "default",
        product: {
            name:"Task Manager",
            link:"https:taskmanagelink.com"
        }
    })

    const emailTextual = mailGenerator.generatePlaintext
    (option.mailContent)

    const emailHtml = mailGenerator.generate(option.mailgenContent)

    const transporter = nodemailer.createTransport({
        host: process.env.MAILTRAP_SMTP_HOST,
        port: process.env.MAILTRAP_SMTP_PORT,
        auth: {
            user: process.env.MAILTRAP_SMTP_USER,
            pass: process.env.MAILTRAP_SMTP_PASS
        }
    })

    const mail = {
        from: "mail.taskmanager@example.com",
        to: option.email,
        subject: option.subject,
        text: emailTextual,
        html: emailHtml
    }
    
    try {
        await transporter.sendMail(mail)
    } catch (error) {
        console.error("Email service failed siliently. Make sure that you have provided your MAILTRAP crendentials in the .enc file")
        console.error("Erroe: ",error)
    }
}




const emailVerificationMailgenContent = (username, verificationUrl) => {
  return {
    body: {
      name: username,
      intro: "Welcome to our App! We're excited to have you on board.",
      action: {
        instructions: "To verify your email, please click on the following button:",
        button: {
          color: "#1aae5a",
          text: "Verify Your Email",
          link: verificationUrl,
        },
      },
      outro:
        "Need help or have questions? Just reply to this email — we'd love to help.",
    },
  };
};

const forgotPasswordMailgenContent = (username, passwordResetUrl) => {
  return {
    body: {
      name: username,
      intro: "We received a request to reset the password for your account.",
      action: {
        instructions: "To reset your password, click the button below:",
        button: {
          color: "#1aae5a",
          text: "Reset Password",
          link: passwordResetUrl,
        },
      },
      outro:
        "Need help or have questions? Just reply to this email — we'd love to help.",
    },
  };
};

export { emailVerificationMailgenContent, forgotPasswordMailgenContent, sendEmail };
