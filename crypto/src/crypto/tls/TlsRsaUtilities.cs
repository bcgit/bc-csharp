using Org.BouncyCastle.Crypto.Encodings;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Parameters;
using System.IO;

namespace Org.BouncyCastle.Crypto.Tls {

public static class TlsRSAUtilities
{
    public static byte[] GenerateEncryptedPreMasterSecret(TlsContext context, RsaKeyParameters rsaServerPublicKey,
                                                          Stream output)
    {
        /*
         * Choose a PremasterSecret and send it encrypted to the server
         */
        byte[] premasterSecret = new byte[48];
        context.SecureRandom.NextBytes(premasterSecret);
        TlsUtilities.WriteVersion(context.ClientVersion, premasterSecret, 0);

        Pkcs1Encoding encoding = new Pkcs1Encoding(new RsaBlindedEngine());
        encoding.Init(true, new ParametersWithRandom(rsaServerPublicKey, context.SecureRandom));

        try
        {
            byte[] encryptedPreMasterSecret = encoding.ProcessBlock(premasterSecret, 0, premasterSecret.Length);

            if (context.ServerVersion.IsSSL)
            {
                // TODO Do any SSLv3 servers actually expect the length?
                output.Write(encryptedPreMasterSecret, 0, encryptedPreMasterSecret.Length);
            }
            else
            {
                TlsUtilities.WriteOpaque16(encryptedPreMasterSecret, output);
            }
        }
        catch (InvalidCipherTextException e)
        {
            /*
             * This should never happen, only during decryption.
             */
            throw new TlsFatalAlert(AlertDescription.internal_error, e);
        }

        return premasterSecret;
    }
}

}