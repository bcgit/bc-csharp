namespace Org.BouncyCastle.Crypto.Signers.Xmss
{
    /// <summary>A registered parameter set identifier, and the name it is registered under.</summary>
    /// <remarks>
    /// The tables that hold them - <see cref="WotsPlusOid"/>, <see cref="DefaultXmssOid"/> and the XMSS^MT one -
    /// differ only in what they are keyed by, so the key each table looks its entries up by is written once here:
    /// WOTS+'s key is the whole of it, XMSS's is that key and a tree height, and XMSS^MT's is that key and a layer
    /// count.
    /// </remarks>
    internal abstract class XmssOid
    {
        /// <summary>The identifier itself, as registered.</summary>
        private readonly int m_oid;
        /// <summary>The name the parameter set is registered under.</summary>
        private readonly string m_stringRepresentation;

        internal XmssOid(int oid, string stringRepresentation)
        {
            m_oid = oid;
            m_stringRepresentation = stringRepresentation;
        }

        internal int Oid => m_oid;

        public override string ToString() => m_stringRepresentation;

        /// <summary>The WOTS+ half of a lookup key, and the whole of one for the WOTS+ table.</summary>
        internal static string CreateKey(string algorithmName, int digestSize, int winternitzParameter, int len) =>
            algorithmName + "-" + digestSize + "-" + winternitzParameter + "-" + len;

        /// <summary>
        /// An XMSS lookup key: the WOTS+ parameters of its one-time keys, and the height of its tree.
        /// </summary>
        internal static string CreateKey(string algorithmName, int digestSize, int winternitzParameter, int len,
            int height)
        {
            return CreateKey(algorithmName, digestSize, winternitzParameter, len) + "-" + height;
        }

        /// <summary>
        /// An XMSS^MT lookup key: an XMSS key, and the number of layers the total height is divided into.
        /// </summary>
        internal static string CreateKey(string algorithmName, int digestSize, int winternitzParameter, int len,
            int height, int layers)
        {
            return CreateKey(algorithmName, digestSize, winternitzParameter, len, height) + "-" + layers;
        }
    }
}
