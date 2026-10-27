using System;

using Org.BouncyCastle.Asn1.Cms;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;

namespace Org.BouncyCastle.Cms
{
    /// <summary>Generator for the RecipientInfo of a single recipient of CMS enveloped or authenticated data.</summary>
    public interface RecipientInfoGenerator
    {
        /// <summary>
        /// Generate a RecipientInfo object for the given key.
        /// </summary>
        /// <param name="contentEncryptionKey">
        /// A <see cref="KeyParameter"/>
        /// </param>
        /// <param name="random">
        /// A <see cref="SecureRandom"/>
        /// </param>
        /// <returns>
        /// A <see cref="RecipientInfo"/>
        /// </returns>
        /// <exception cref="GeneralSecurityException"></exception>
        RecipientInfo Generate(KeyParameter contentEncryptionKey, SecureRandom random);
    }
}
