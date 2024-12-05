﻿using System;
using System.Diagnostics;

using Org.BouncyCastle.Pqc.Crypto.SphincsPlus;
using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Crypto.Parameters
{
    public sealed class SlhDsaPrivateKeyParameters
        : SlhDsaKeyParameters
    {
        public static SlhDsaPrivateKeyParameters FromEncoding(SlhDsaParameters parameters, byte[] encoding)
        {
            if (parameters == null)
                throw new ArgumentNullException(nameof(parameters));
            if (encoding == null)
                throw new ArgumentNullException(nameof(encoding));
            if (encoding.Length != parameters.ParameterSet.PrivateKeyLength)
                throw new ArgumentException("invalid encoding", nameof(encoding));

            int n = parameters.ParameterSet.N;
            SK sk = new SK(Arrays.CopyOfRange(encoding, 0, n), Arrays.CopyOfRange(encoding, n, 2 * n));
            PK pk = new PK(Arrays.CopyOfRange(encoding, 2 * n, 3 * n), Arrays.CopyOfRange(encoding, 3 * n, 4 * n));
            return new SlhDsaPrivateKeyParameters(parameters, sk, pk);
        }

        private readonly SK m_sk;
        private readonly PK m_pk;

        internal SlhDsaPrivateKeyParameters(SlhDsaParameters parameters, SK sk, PK pk)
            : base(true, parameters)
        {
            m_sk = sk;
            m_pk = pk;
        }

        public byte[] GetEncoded() => Arrays.ConcatenateAll(m_sk.seed, m_sk.prf, m_pk.seed, m_pk.root);

        public SlhDsaPublicKeyParameters GetPublicKey() => new SlhDsaPublicKeyParameters(Parameters, m_pk);

        public byte[] GetPublicKeyEncoded() => Arrays.Concatenate(m_pk.seed, m_pk.root);

        internal PK PK => m_pk;

        internal SK SK => m_sk;

        internal byte[] SignInternal(byte[] optRand, byte[] msg, int msgOff, int msgLen)
        {
            // # Input: Message M, private key SK = (SK.seed, SK.prf, PK.seed, PK.root)
            // # Output: SPHINCS+ signature SIG

            var engine = Parameters.ParameterSet.GetEngine();

            if (optRand == null)
            {
                optRand = Arrays.CopyOfRange(PK.seed, 0, engine.N);
            }
            else if (optRand.Length != engine.N)
            {
                throw new ArgumentOutOfRangeException(nameof(optRand));
            }

            // init
            engine.Init(PK.seed);

            Fors fors = new Fors(engine);
            byte[] R = engine.PRF_msg(SK.prf, optRand, msg, msgOff, msgLen);

            // compute message digest and index
            IndexedDigest idxDigest = engine.H_msg(R, PK.seed, PK.root, msg, msgOff, msgLen);
            byte[] mHash = idxDigest.digest;
            ulong idx_tree = idxDigest.idx_tree;
            uint idx_leaf = idxDigest.idx_leaf;

            // FORS sign
            Adrs adrs = new Adrs();
            adrs.SetTypeAndClear(Adrs.FORS_TREE);
            adrs.SetTreeAddress(idx_tree);
            adrs.SetKeyPairAddress(idx_leaf);
            SIG_FORS[] sig_fors = fors.Sign(mHash, SK.seed, PK.seed, adrs, legacy: false);

            // get FORS public key - spec shows M?
            adrs = new Adrs();
            adrs.SetTypeAndClear(Adrs.FORS_TREE);
            adrs.SetTreeAddress(idx_tree);
            adrs.SetKeyPairAddress(idx_leaf);

            byte[] PK_FORS = fors.PKFromSig(sig_fors, mHash, PK.seed, adrs, legacy: false);

            // sign FORS public key with HT
            Adrs treeAdrs = new Adrs();
            treeAdrs.SetTypeAndClear(Adrs.TREE);

            HT ht = new HT(engine, SK.seed, PK.seed);

            byte[] signature = new byte[engine.SignatureLength];
            int pos = 0;

            Array.Copy(R, 0, signature, 0, R.Length);
            pos += R.Length;

            for (int i = 0; i < sig_fors.Length; ++i)
            {
                sig_fors[i].CopyToSignature(signature, ref pos);
            }

            ht.Sign(PK_FORS, idx_tree, idx_leaf, signature, ref pos);
            Debug.Assert(pos == engine.SignatureLength);
            return signature;
        }
    }
}
