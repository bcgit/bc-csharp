namespace Org.BouncyCastle.OpenSsl.Tests
{
    internal class TestPassword
        : IPasswordFinder
    {
        private readonly string m_password;

        internal TestPassword(string password)
        {
            m_password = password;
        }

        public char[] GetPassword() => m_password.ToCharArray();
    }
}
