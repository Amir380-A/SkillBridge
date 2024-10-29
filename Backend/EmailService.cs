using System.Net;
using System.Net.Mail;
using System.Threading.Tasks;

namespace Backend.Shared.Utils
{
    public class EmailService
    {
        private readonly SmtpClient _smtpClient;
        private readonly string _fromEmail;

        public EmailService(string smtpHost, int smtpPort, string fromEmail, string fromPassword)
        {
            _fromEmail = fromEmail;

            _smtpClient = new SmtpClient(smtpHost, smtpPort)
            {
                Credentials = new NetworkCredential(fromEmail, fromPassword),
                EnableSsl = true 
            };
        }

        public async Task SendVerificationEmailAsync(string toEmail, string userName, string verificationToken)
        {
            var verifyUrl = $"https://localhost:5129/api/auth/verify-email?token={verificationToken}";
            var subject = "Email Verification";
            var body = $"Hi {userName},\n\nPlease verify your email by clicking the link below:\n\n{verifyUrl}";

            var mailMessage = new MailMessage(_fromEmail, toEmail, subject, body);

            try
            {
                await _smtpClient.SendMailAsync(mailMessage);
            }
            catch (SmtpException ex)
            {
                throw new InvalidOperationException("Failed to send email", ex);
            }
        }
    }
}
