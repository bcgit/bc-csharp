namespace Org.BouncyCastle.Bcpg
{
    /// <remarks>Base class for a PGP object.</remarks>
    public abstract class BcpgObject
    {
        public virtual byte[] GetEncoded() => BcpgOutputStream.GetEncoded(this);

        public abstract void Encode(BcpgOutputStream bcpgOut);
    }
}
