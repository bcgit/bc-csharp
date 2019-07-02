using Org.BouncyCastle.Crypto.Parameters;

namespace Org.BouncyCastle.Crypto.Modes
{
    public interface IAeadStreamCipher : IAeadCipher
    {
        /// <summary>The stream cipher underlying this algorithm.</summary>
        IStreamCipher GetUnderlyingCipher();
    }
}
