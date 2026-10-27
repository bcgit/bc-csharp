using System;

namespace Org.BouncyCastle.OpenSsl
{
    /// <summary>Supplies the password needed to decrypt encrypted PEM objects.</summary>
    public interface IPasswordFinder
    {
        /// <summary>Return the password to use.</summary>
        /// <returns>The password, or null if none is available.</returns>
        char[] GetPassword();
    }
}
