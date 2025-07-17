namespace Org.BouncyCastle.Bcpg
{
    public class UnknownBCPGKey
        : OctetArrayBcpgKey
    {
        public UnknownBCPGKey(int length, BcpgInputStream bcpgIn)
            : base(length, bcpgIn)
        {
        }
    }
}