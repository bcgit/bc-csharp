using System;

using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Crypto.Signers.MLDsa
{
    internal class MLDsaEngine
    {
        internal const int N = 256;
        internal const int Q = 8380417;
        internal const int QInv = 58728449; // Q ^ (-1) mod 2 ^32
        internal const int D = 13;
        internal const int RootOfUnity = 1753;
        internal const int SeedBytes = 32;
        internal const int CrhBytes = 64;
        internal const int RndBytes = 32;
        internal const int TrBytes = 64;

        internal const int PolyT1PackedBytes = 320;
        internal const int PolyT0PackedBytes = 416;

        internal SecureRandom Random { get; private set; }

        internal int K { get; private set; }
        internal int L { get; private set; }
        internal int Eta { get; private set; }
        internal int Tau { get; private set; }
        internal int Beta { get; private set; }
        internal int Gamma1 { get; private set; }
        internal int Gamma2 { get; private set; }
        internal int Omega { get; private set; }
        internal int CTilde { get; private set; }

        internal int PolyVecHPackedBytes { get; private set; }

        internal int PolyZPackedBytes { get; private set; }
        internal int PolyW1PackedBytes { get; private set; }
        internal int PolyEtaPackedBytes { get; private set; }

        internal int CryptoPublicKeyBytes { get; private set; }
        //internal int CryptoSecretKeyBytes { get; private set; }
        internal int CryptoBytes { get; private set; }
        internal int PolyUniformGamma1NBytes { get; private set; }
        internal ShakeSymmetric Symmetric { get; private set; }

        internal MLDsaEngine(int mode, SecureRandom random)
        {
            Random = random;

            switch (mode)
            {
            case 2:
                K = 4;
                L = 4;
                Eta = 2;
                Tau = 39;
                Beta = 78;
                Gamma1 = (1 << 17);
                Gamma2 = ((Q - 1) / 88);
                Omega = 80;
                PolyZPackedBytes = 576;
                PolyW1PackedBytes = 192;
                PolyEtaPackedBytes = 96;
                CTilde = 32;
                break;
            case 3:
                K = 6;
                L = 5;
                Eta = 4;
                Tau = 49;
                Beta = 196;
                Gamma1 = (1 << 19);
                Gamma2 = ((Q - 1) / 32);
                Omega = 55;
                PolyZPackedBytes = 640;
                PolyW1PackedBytes = 128;
                PolyEtaPackedBytes = 128;
                CTilde = 48;
                break;
            case 5:
                K = 8;
                L = 7;
                Eta = 2;
                Tau = 60;
                Beta = 120;
                Gamma1 = (1 << 19);
                Gamma2 = ((Q - 1) / 32);
                Omega = 75;
                PolyZPackedBytes = 640;
                PolyW1PackedBytes = 128;
                PolyEtaPackedBytes = 96;
                CTilde = 64;
                break;
            default:
                throw new ArgumentException("The mode " + mode + "is not supported by ML-DSA");
            }

            Symmetric = new ShakeSymmetric();

            PolyVecHPackedBytes = Omega + K;
            CryptoPublicKeyBytes = SeedBytes + K * PolyT1PackedBytes;
            //CryptoSecretKeyBytes = 2 * SeedBytes + TrBytes + L * PolyEtaPackedBytes + K * PolyEtaPackedBytes + K * PolyT0PackedBytes;
            CryptoBytes = CTilde + L * PolyZPackedBytes + PolyVecHPackedBytes;

            if (Gamma1 == (1 << 17))
            {
                PolyUniformGamma1NBytes = ((576 + Symmetric.Stream256BlockBytes - 1) / Symmetric.Stream256BlockBytes);
            }
            else if (Gamma1 == (1 << 19))
            {
                PolyUniformGamma1NBytes = ((640 + Symmetric.Stream256BlockBytes - 1) / Symmetric.Stream256BlockBytes);
            }
            else
            {
                throw new ArgumentException("Wrong ML-DSA Gamma1!");
            }
        }

        internal static byte[] CalculatePublicKeyHash(byte[] rho, byte[] encT1)
        {
            byte[] tr = new byte[TrBytes];

            ShakeDigest d = new ShakeDigest(256);
            d.BlockUpdate(rho, 0, rho.Length);
            d.BlockUpdate(encT1, 0, encT1.Length);
            d.OutputFinal(tr, 0, TrBytes);

            return tr;
        }

        internal void GenerateKeyPair(out byte[] rho, out byte[] k, out byte[] tr, out byte[] s1,
            out byte[] s2, out byte[] t0, out byte[] encT1, out byte[] seed)
        {
            seed = SecureRandom.GetNextBytes(Random, SeedBytes);

            GenerateKeyPairInternal(seed, out rho, out k, out tr, out s1, out s2, out t0, out encT1);
        }

        internal void GenerateKeyPairInternal(byte[] seed, out byte[] rho, out byte[] k, out byte[] tr,
            out byte[] s1_, out byte[] s2_, out byte[] t0_, out byte[] encT1)
        {
            byte[] buf = new byte[2 * SeedBytes + CrhBytes];
            buf[0] = (byte)K;
            buf[1] = (byte)L;

            ShakeDigest shake256Digest = new ShakeDigest(256);
            shake256Digest.BlockUpdate(seed, 0, SeedBytes);
            shake256Digest.BlockUpdate(buf, 0, 2); // K, L
            shake256Digest.OutputFinal(buf, 0, 2 * SeedBytes + CrhBytes);

            byte[] rhoPrime = new byte[CrhBytes];
            tr = new byte[TrBytes];
            rho = new byte[SeedBytes];
            k = new byte[SeedBytes];
            s1_ = new byte[L * PolyEtaPackedBytes];
            s2_ = new byte[K * PolyEtaPackedBytes];
            t0_ = new byte[K * PolyT0PackedBytes];
            PolyVecMatrix matrix = new PolyVecMatrix(this);

            PolyVec s1 = new PolyVec(this, L);
            PolyVec s2 = new PolyVec(this, K), t1 = new PolyVec(this, K), t0 = new PolyVec(this, K);

            Array.Copy(buf, 0, rho, 0, SeedBytes);
            Array.Copy(buf, SeedBytes, rhoPrime, 0, CrhBytes);
            Array.Copy(buf, SeedBytes + CrhBytes, k, 0, SeedBytes);

            matrix.ExpandMatrix(rho);

            s1.UniformEta(rhoPrime, 0);
            s2.UniformEta(rhoPrime, (ushort)L);

            {
                PolyVec s1Hat = new PolyVec(this, L);
                s1.CopyTo(s1Hat);
                s1Hat.Ntt();

                matrix.PointwiseMontgomery(t1, s1Hat);
            }

            t1.Reduce();
            t1.InverseNttToMont();

            t1.Add(s2);
            t1.ConditionalAddQ();
            t1.Power2Round(t0);

            encT1 = Packing.PackPublicKey(t1, this);

            shake256Digest.BlockUpdate(rho, 0, rho.Length);
            shake256Digest.BlockUpdate(encT1, 0, encT1.Length);
            shake256Digest.OutputFinal(tr, 0, TrBytes);

            Packing.PackSecretKey(t0_, s1_, s2_, t0, s1, s2, this);
        }

        internal byte[] DeriveT1(byte[] rho, byte[] s1Enc, byte[] s2Enc, byte[] t0Enc)
        {
            PolyVecMatrix matrix = new PolyVecMatrix(this);

            PolyVec s1 = new PolyVec(this, L);
            PolyVec s2 = new PolyVec(this, K), t1 = new PolyVec(this, K), t0 = new PolyVec(this, K);

            Packing.UnpackSecretKey(t0, s1, s2, t0Enc, s1Enc, s2Enc, this);

            matrix.ExpandMatrix(rho);

            {
                PolyVec s1Hat = new PolyVec(this, L);
                s1.CopyTo(s1Hat);
                s1Hat.Ntt();

                matrix.PointwiseMontgomery(t1, s1Hat);
            }

            t1.Reduce();
            t1.InverseNttToMont();

            t1.Add(s2);
            t1.ConditionalAddQ();
            t1.Power2Round(t0);

            return Packing.PackPublicKey(t1, this);
        }

        internal void MsgRepBegin(ShakeDigest d, byte[] tr) => d.BlockUpdate(tr, 0, TrBytes);

        internal static ShakeDigest MsgRepCreateDigest() => new ShakeDigest(256);

        internal void MsgRepEndSign(ShakeDigest d, byte[] sig, int siglen, byte[] rho, byte[] k, byte[] t0Enc,
            byte[] s1Enc, byte[] s2Enc)
        {
            var rnd = new byte[RndBytes];

            var random = Random;
            if (random != null)
            {
                random.NextBytes(rnd);
            }

            MsgRepEndSignInternal(d, sig, siglen, rho, k, t0Enc, s1Enc, s2Enc, rnd);
        }

        internal void MsgRepEndSignInternal(ShakeDigest d, byte[] sig, int siglen, byte[] rho, byte[] k, byte[] t0Enc,
            byte[] s1Enc, byte[] s2Enc, byte[] rnd)
        {
            byte[] mu = new byte[CrhBytes];
            d.OutputFinal(mu, 0, CrhBytes);

            byte[] seedBuf = new byte[3 * SeedBytes + 2 * CrhBytes];
            byte[] rhoPrime = new byte[CrhBytes];
            PolyVecMatrix matrix = new PolyVecMatrix(this);
            PolyVec s1 = new PolyVec(this, L), y = new PolyVec(this, L), z = new PolyVec(this, L);
            PolyVec t0 = new PolyVec(this, K), s2 = new PolyVec(this, K), w1 = new PolyVec(this, K),
                w0 = new PolyVec(this, K), h = new PolyVec(this, K);
            Poly cp = new Poly(this);

            Packing.UnpackSecretKey(t0, s1, s2, t0Enc, s1Enc, s2Enc, this);

            d.BlockUpdate(k, 0, SeedBytes);
            d.BlockUpdate(rnd, 0, RndBytes);
            d.BlockUpdate(mu, 0, CrhBytes);
            d.OutputFinal(rhoPrime, 0, CrhBytes);

            matrix.ExpandMatrix(rho);

            s1.Ntt();
            s2.Ntt();
            t0.Ntt();

            ushort nonce = 0;

            int count = 0;
            while (++count <= 1000)
            {
                // Sample intermediate vector
                y.UniformGamma1(rhoPrime, nonce++);
                y.CopyTo(z);
                z.Ntt();

                // Matrix-vector multiplication
                matrix.PointwiseMontgomery(w1, z);
                w1.Reduce();
                w1.InverseNttToMont();

                // Decompose w and call the random oracle
                w1.ConditionalAddQ();
                w1.Decompose(w0);

                w1.PackW1(this, sig, 0);

                d.BlockUpdate(mu, 0, CrhBytes);
                d.BlockUpdate(sig, 0, K * PolyW1PackedBytes);
                d.OutputFinal(sig, 0, CTilde);

                cp.Challenge(sig, 0, CTilde);
                cp.PolyNtt();

                // Compute z, reject if it reveals secret
                z.PointwisePolyMontgomery(cp, s1);
                z.InverseNttToMont();
                z.Add(y);
                z.Reduce();
                if (z.CheckNorm(Gamma1 - Beta))
                    continue;

                h.PointwisePolyMontgomery(cp, s2);
                h.InverseNttToMont();
                w0.Subtract(h);
                w0.Reduce();
                if (w0.CheckNorm(Gamma2 - Beta))
                    continue;

                h.PointwisePolyMontgomery(cp, t0);
                h.InverseNttToMont();
                h.Reduce();
                if (h.CheckNorm(Gamma2))
                    continue;

                w0.Add(h);
                w0.ConditionalAddQ();
                int n = h.MakeHint(w0, w1);
                if (n > Omega)
                    continue;

                Packing.PackSignature(sig, z, h, this);
                return;
            }

            // TODO[pqc] Exception type and message
            throw new InvalidOperationException();
        }

        internal bool MsgRepEndVerifyInternal(ShakeDigest d, byte[] sig, int siglen, byte[] rho, byte[] encT1)
        {
            if (siglen != CryptoBytes)
                return false;

            PolyVec h = new PolyVec(this, K);
            PolyVec z = new PolyVec(this, L);

            if (!Packing.UnpackSignature(z, h, sig, this))
                return false;

            if (z.CheckNorm(Gamma1 - Beta))
                return false;

            byte[] buf = new byte[System.Math.Max(CrhBytes + K * PolyW1PackedBytes, CTilde)];

            // Mu
            d.DoFinal(buf, 0);

            Poly cp = new Poly(this);
            PolyVecMatrix matrix = new PolyVecMatrix(this);
            PolyVec t1 = new PolyVec(this, K), w1 = new PolyVec(this, K);

            Packing.UnpackPublicKey(t1, encT1, this);

            cp.Challenge(sig, 0, CTilde);

            matrix.ExpandMatrix(rho);

            z.Ntt();
            matrix.PointwiseMontgomery(w1, z);

            cp.PolyNtt();

            t1.ShiftLeft();
            t1.Ntt();
            t1.PointwisePolyMontgomery(cp, t1);

            w1.Subtract(t1);
            w1.Reduce();
            w1.InverseNttToMont();

            w1.ConditionalAddQ();
            w1.UseHint(w1, h);

            w1.PackW1(this, buf, CrhBytes);

            d.BlockUpdate(buf, 0, CrhBytes + K * PolyW1PackedBytes);
            d.OutputFinal(buf, 0, CTilde);

            return Arrays.FixedTimeEquals(CTilde, sig, 0, buf, 0);
        }

        internal ShakeDigest MsgRepPreHash(byte[] tr, byte[] msg, int msgOff, int msgLen)
        {
            var d = MsgRepCreateDigest();
            MsgRepBegin(d, tr);
            d.BlockUpdate(msg, msgOff, msgLen);
            return d;
        }

        internal void Sign(byte[] sig, int siglen, byte[] msg, int msgOff, int msgLen, byte[] rho, byte[] k, byte[] tr,
            byte[] t0Enc, byte[] s1Enc, byte[] s2Enc)
        {
            var d = MsgRepPreHash(tr, msg, msgOff, msgLen);
            MsgRepEndSign(d, sig, siglen, rho, k, t0Enc, s1Enc, s2Enc);
        }

        internal void SignInternal(byte[] sig, int siglen, byte[] msg, int msgOff, int msgLen, byte[] rho, byte[] k,
            byte[] tr, byte[] t0Enc, byte[] s1Enc, byte[] s2Enc, byte[] rnd)
        {
            var d = MsgRepPreHash(tr, msg, msgOff, msgLen);
            MsgRepEndSignInternal(d, sig, siglen, rho, k, t0Enc, s1Enc, s2Enc, rnd);
        }

        internal bool VerifyInternal(byte[] sig, int siglen, byte[] msg, int msgOff, int msgLen, byte[] rho, byte[] encT1,
            byte[] tr)
        {
            var d = MsgRepPreHash(tr, msg, msgOff, msgLen);
            return MsgRepEndVerifyInternal(d, sig, siglen, rho, encT1);
        }
    }
}
