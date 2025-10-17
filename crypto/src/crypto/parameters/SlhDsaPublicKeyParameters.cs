using System;

using Org.BouncyCastle.Crypto.Signers.SlhDsa;
using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Crypto.Parameters
{
    public sealed class SlhDsaPublicKeyParameters
        : SlhDsaKeyParameters
    {
        public static SlhDsaPublicKeyParameters FromEncoding(SlhDsaParameters parameters, byte[] encoding)
        {
            if (parameters == null)
                throw new ArgumentNullException(nameof(parameters));
            if (encoding == null)
                throw new ArgumentNullException(nameof(encoding));
            if (encoding.Length != parameters.ParameterSet.PublicKeyLength)
                throw new ArgumentException("invalid encoding", nameof(encoding));

            int n = parameters.ParameterSet.N;
            PK pk = new PK(Arrays.CopyOfRange(encoding, 0, n), Arrays.CopyOfRange(encoding, n, 2 * n));
            return new SlhDsaPublicKeyParameters(parameters, pk);
        }

        private readonly PK m_pk;

        internal SlhDsaPublicKeyParameters(SlhDsaParameters parameters, PK pk)
            : base(false, parameters)
        {
            m_pk = pk;
        }

        public byte[] GetEncoded() => Arrays.Concatenate(m_pk.Seed, m_pk.Root);

        internal PK PK => m_pk;

        internal bool VerifyInternal(byte[] msg, int msgOff, int msgLen, byte[] signature)
        {
            var engine = Parameters.ParameterSet.GetEngine();

            if (engine.SignatureLength != signature.Length)
                return false;

            engine.Init(PK.Seed);

            // compute message digest and index
            IndexedDigest idxDigest = engine.HMsg(signature, 0, PK.Seed, PK.Root, msg, msgOff, msgLen);

            byte[] digest = idxDigest.Digest;
            ulong idxTree = idxDigest.IdxTree;
            uint idxLeaf = idxDigest.IdxLeaf;

            // compute FORS public key
            Adrs adrs = new Adrs(Adrs.ForsTree);
            adrs.SetLayerAddress(0);
            adrs.SetTreeAddress(idxTree);
            adrs.SetKeyPairAddress(idxLeaf);

            byte[] PK_FORS = new byte[engine.N];
            Fors.PKFromSig(engine, signature, digest, adrs, PK_FORS, 0);

            // verify HT signature
            adrs.SetTypeAndClear(Adrs.Tree);
            adrs.SetLayerAddress(0);
            adrs.SetTreeAddress(idxTree);
            adrs.SetKeyPairAddress(idxLeaf);

            HT ht = new HT(engine, null, PK.Seed);
            return ht.Verify(PK_FORS, signature, PK.Seed, idxTree, idxLeaf, PK.Root);
        }
    }
}
