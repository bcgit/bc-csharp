namespace Org.BouncyCastle.Crypto.Tls
{
    public abstract class AbstractTlsSigner : TlsSigner
    {
        protected TlsContext context;

        public void Init(TlsContext context)
        {
            this.context = context;
        }

        public abstract byte[] GenerateRawSignature(AsymmetricKeyParameter privateKey, byte[] md5AndSha1);

        public abstract bool VerifyRawSignature(byte[] sigBytes, AsymmetricKeyParameter publicKey, byte[] md5AndSha1);

        public abstract ISigner CreateSigner(AsymmetricKeyParameter privateKey);

        public abstract ISigner CreateVerifyer(AsymmetricKeyParameter publicKey);

        public abstract bool IsValidPublicKey(AsymmetricKeyParameter publicKey);
    }
}