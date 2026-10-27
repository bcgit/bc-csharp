namespace Org.BouncyCastle.Bcpg
{
    /// <remarks>Base class for a PGP object.</remarks>
    public abstract class BcpgObject
    {
        /// <summary>Return the encoded.</summary>
        public virtual byte[] GetEncoded() => BcpgOutputStream.GetEncoded(this);

        /// <summary>Write the encoding of this object.</summary>
        /// <param name="bcpgOut">The stream to write to.</param>
        public abstract void Encode(BcpgOutputStream bcpgOut);
    }
}
