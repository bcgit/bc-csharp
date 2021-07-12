using System;
using System.IO;

using Org.BouncyCastle.Tls.Crypto;

namespace Org.BouncyCastle.Tls
{
    /// <summary>RSA Utility methods.</summary>
    public abstract class TlsRsaUtilities
    {
        /// <summary>Generate a pre_master_secret and send it encrypted to the server.</summary>
        /// <exception cref="IOException"/>
        public static TlsSecret GenerateEncryptedPreMasterSecret(TlsContext context, TlsCertificate certificate,
            Stream output)
        {
            TlsSecret preMasterSecret = context.Crypto.GenerateRsaPreMasterSecret(context.RsaPreMasterSecretVersion);

            byte[] encryptedPreMasterSecret = preMasterSecret.Encrypt(certificate);
            TlsUtilities.WriteEncryptedPms(context, encryptedPreMasterSecret, output);

            return preMasterSecret;
        }
    }
}
