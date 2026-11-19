using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities.Encoders;

namespace Org.BouncyCastle.Crypto.Signers.Xmss.Tests
{
    /// <summary>The digest that signature vectors are kept as, in place of the signatures themselves.</summary>
    internal static class XmssTestData
    {
        /// <summary>
        /// The SHA-256 of <paramref name="data"/>, in lower-case hex: what a known-answer test keeps of a signature,
        /// which is several kilobytes, rather than the signature itself.
        /// </summary>
        internal static string Sha256Hex(byte[] data) =>
            Hex.ToHexString(DigestUtilities.CalculateDigest("SHA-256", data));
    }
}
