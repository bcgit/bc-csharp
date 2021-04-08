namespace Org.BouncyCastle.Crypto.Engines
{
    public class AesWrapPadEngine : Rfc5649WrapEngine
    {
        public AesWrapPadEngine()
            : base(new AesEngine())
        {
        }
    }
}
