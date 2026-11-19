namespace Org.BouncyCastle.Crypto.Signers.Xmss
{
    /// <summary>WOTS+ public key.</summary>
    internal sealed class WotsPlusPublicKeyParameters
    {
        private readonly byte[][] m_publicKey;

        /// <summary>This key's len n-byte blocks, taken over rather than copied in.</summary>
        /// <remarks>
        /// <para>
        /// Both callers that build one - <see cref="WotsPlus.GetPublicKey"/> and
        /// <see cref="WotsPlus.GetPublicKeyFromSignature"/> - allocate the array, fill it with what chain() returns
        /// and hand it straight here, so nothing outside holds the array or any block of it. chain() returns an
        /// array of its own however many steps it takes, so a recovered key never shares storage with the
        /// signature it was recovered from.
        /// </para>
        /// <para>
        /// Nothing escapes either: <see cref="ToNodes"/> is the only way the blocks leave this class and it hands
        /// them to a walk that only reads them. The shape is the caller's as well, and nothing here measures it.
        /// </para>
        /// </remarks>
        /// <param name="publicKey">the len n-byte blocks of the key, which this instance takes over.</param>
        internal WotsPlusPublicKeyParameters(byte[][] publicKey)
        {
            m_publicKey = publicKey;
        }

        /// <summary>
        /// This key's blocks, each wrapped as a height-0 <see cref="XmssNode"/>, as the L-tree walk in
        /// <see cref="XmssNodeUtilities.LTree"/> starts from, and the only way they leave this class.
        /// </summary>
        internal XmssNode[] ToNodes()
        {
            XmssNode[] nodes = new XmssNode[m_publicKey.Length];
            for (int i = 0; i != m_publicKey.Length; i++)
            {
                nodes[i] = new XmssNode(0, m_publicKey[i]);
            }
            return nodes;
        }
    }
}
