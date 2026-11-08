using System;
using System.IO;
using System.Text;

using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities.Encoders;
using Org.BouncyCastle.Utilities.Test;

namespace Org.BouncyCastle.Crypto.Signers.Xmss.Tests
{
    /// <summary>
    /// The test vectors too long to keep inline, embedded from <c>crypto/test/data/xmss/</c>, and the digest that
    /// signature vectors are kept as in their place.
    /// </summary>
    internal static class XmssTestData
    {
        /// <summary>
        /// The SHA-256 of <paramref name="data"/>, in lower-case hex: what a known-answer test keeps of a signature,
        /// which is several kilobytes, rather than the signature itself.
        /// </summary>
        internal static string Sha256Hex(byte[] data) =>
            Hex.ToHexString(DigestUtilities.CalculateDigest("SHA-256", data));

        /// <summary>
        /// The bytes of the hex string in <c>crypto/test/data/xmss/<paramref name="name"/></c>, which may be broken
        /// over several lines.
        /// </summary>
        /// <exception cref="FileNotFoundException">If there is no such resource.</exception>
        internal static byte[] LoadHex(string name)
        {
            string resource = "xmss." + name;

            using (Stream stream = SimpleTest.GetTestDataAsStream(resource))
            {
                if (stream == null)
                    throw new FileNotFoundException("no embedded test data " + resource);

                string text;
                using (StreamReader reader = new StreamReader(stream, Encoding.ASCII))
                {
                    text = reader.ReadToEnd();
                }

                StringBuilder hex = new StringBuilder(text.Length);
                foreach (char c in text)
                {
                    if (!char.IsWhiteSpace(c))
                    {
                        hex.Append(c);
                    }
                }

                return Hex.Decode(hex.ToString());
            }
        }
    }
}
