namespace Org.BouncyCastle.Asn1.Ntt
{
    /// <summary>From RFC 3657</summary>
    // TODO[api] Make static
    public abstract class NttObjectIdentifiers
    {
        /// <summary>The object identifier <c>1.2.392.200011.61.1.1.1.2</c>.</summary>
        public static readonly DerObjectIdentifier IdCamellia128Cbc = new DerObjectIdentifier("1.2.392.200011.61.1.1.1.2");
        /// <summary>The object identifier <c>1.2.392.200011.61.1.1.1.3</c>.</summary>
        public static readonly DerObjectIdentifier IdCamellia192Cbc = new DerObjectIdentifier("1.2.392.200011.61.1.1.1.3");
        /// <summary>The object identifier <c>1.2.392.200011.61.1.1.1.4</c>.</summary>
        public static readonly DerObjectIdentifier IdCamellia256Cbc = new DerObjectIdentifier("1.2.392.200011.61.1.1.1.4");

        /// <summary>The object identifier <c>1.2.392.200011.61.1.1.3.2</c>.</summary>
        public static readonly DerObjectIdentifier IdCamellia128Wrap = new DerObjectIdentifier("1.2.392.200011.61.1.1.3.2");
        /// <summary>The object identifier <c>1.2.392.200011.61.1.1.3.3</c>.</summary>
        public static readonly DerObjectIdentifier IdCamellia192Wrap = new DerObjectIdentifier("1.2.392.200011.61.1.1.3.3");
        /// <summary>The object identifier <c>1.2.392.200011.61.1.1.3.4</c>.</summary>
        public static readonly DerObjectIdentifier IdCamellia256Wrap = new DerObjectIdentifier("1.2.392.200011.61.1.1.3.4");
    }
}
