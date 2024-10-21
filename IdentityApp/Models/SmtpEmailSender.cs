using System.Net;
using System.Net.Mail;

namespace IdentityApp.Models
{
    public class SmtpEmailSender : IEmailSender
    {
        private  string? _host;
        private int _port;
        private bool _enableSSL;
        private string? _username;
        private string? _password;   
        public SmtpEmailSender(string? Host, int Port, bool EnableSSL, string? Username ,string? Password)
        {
            _host = Host;
            _port = Port;
            _enableSSL = EnableSSL;
            _username = Username;
            _password = Password;
        }
        public Task SendEmailAsync(string email, string subject, string message)
        {
             var client = new SmtpClient(_host,_port)
             {
                  Credentials = new NetworkCredential(_username,_password),
                  EnableSsl = _enableSSL
             };

            return client.SendMailAsync(new MailMessage(_username ?? "", email, subject, message){IsBodyHtml=true});
        }
    }
}