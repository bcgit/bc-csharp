
namespace Org.BouncyCastle.Crypto.Tls
{
    public class AbstractTlsCipherFactory : TlsCipherFactory
    {        
        #region TlsCipherFactory Members

        public virtual TlsCipher CreateCipher(TlsContext context, EncryptionAlgorithm encryptionAlgorithm, MACAlgorithm digestAlgorithm)
        {
            throw new TlsFatalAlert(AlertDescription.internal_error);
        }

        #endregion      
    }
}
