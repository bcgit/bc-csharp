namespace Org.BouncyCastle.Bcpg
{
    /// <remarks>Base class for a PGP object.</remarks>
    public abstract class BcpgObject
    {
        /// <summary>Return the encoded.</summary>
        public virtual byte[] GetEncoded() => BcpgOutputStream.GetEncoded(this);

        public abstract void Encode(BcpgOutputStream bcpgOut);
    }
}
