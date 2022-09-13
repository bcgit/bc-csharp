using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Reflection.Emit;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using static Org.BouncyCastle.Tls.DtlsReliableHandshake;

namespace Org.BouncyCastle.Pqc.Crypto.Crystals.Dilithium
{
    internal class DilithiumEngine
    {
        private SecureRandom _random;

        public const int N = 256;
        public const int Q = 8380417;
        public const int QInv = 58728449; // Q ^ (-1) mod 2 ^32
        public const int D = 13;
        public const int RootOfUnity = 1753;
        public const int SeedBytes = 32;
        public const int CrhBytes = 64;
        public const bool RandomizedSigning = false;

        public const int PolyT1PackedBytes = 320;
        public const int PolyT0PackedBytes = 416;

        public int Mode { get; private set; }

        public int K { get; private set; }
        public int L { get; private set; }
        public int Eta { get; private set; }
        public int Tau { get; private set; }
        public int Beta { get; private set; }
        public int Gamma1 { get; private set; }
        public int Gamma2 { get; private set; }
        public int Omega { get; private set; }

        public int PolyVecHPackedBytes { get; private set; }

        public int PolyZPackedBytes { get; private set; }
        public int PolyW1PackedBytes { get; private set; }
        public int PolyEtaPackedBytes { get; private set; }
        
        public int CryptoPublicKeyBytes { get; private set; }
        public int CryptoSecretKeyBytes { get; private set; }
        public int CryptoBytes { get; private set; }
        public int PolyUniformGamma1NBytes { get; private set; }

        public DilithiumEngine(int mode, SecureRandom random)
        {
            Mode = mode;
            switch (Mode)
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
                    break;
                default:
                    throw new ArgumentException("The mode " + mode + "is not supported by Crystals Dilithium!");
            }

            _random = random;
            PolyVecHPackedBytes = Omega + K;
            CryptoPublicKeyBytes = SeedBytes + K * PolyT1PackedBytes;
            CryptoSecretKeyBytes = 3 * SeedBytes + L * PolyEtaPackedBytes + K * PolyEtaPackedBytes + K * PolyT0PackedBytes;
            CryptoBytes = SeedBytes + L * PolyZPackedBytes + PolyVecHPackedBytes;

            if (Gamma1 == (1 << 17))
            {
                PolyUniformGamma1NBytes = ((576 + Symmetric.Shake256Rate - 1) / Symmetric.Shake256Rate);
            }
            else if (Gamma1 == (1 << 19))
            {
                PolyUniformGamma1NBytes = ((640 + Symmetric.Shake256Rate - 1) / Symmetric.Shake256Rate);
            }
            else
            {
                throw new ArgumentException("Wrong Dilithium Gamma1!");
            }
        }
        
        public void GenerateKeyPair(byte[] pk, byte[] sk)
        {
            byte[] SeedBuf = new byte[SeedBytes];
            byte[] buf = new byte[2 * SeedBytes + CrhBytes];
            byte[] tr = new byte[SeedBytes];

            byte[] rho, rhoPrime, key;

            PolyVecMatrix Matrix = new PolyVecMatrix(this);

            PolyVecL s1 = new PolyVecL(this), s1Hat;
            PolyVecK s2 = new PolyVecK(this), t1 = new PolyVecK(this), t0 = new PolyVecK(this);

            _random.NextBytes(SeedBuf);

            //Console.WriteLine("SeedBuf = {0}", Convert.ToHexString(SeedBuf));


            ShakeDigest Shake256Digest = new ShakeDigest(256);
            Shake256Digest.BlockUpdate(SeedBuf, 0, SeedBytes);
            Shake256Digest.DoFinal(buf, 0, 2 * SeedBytes + CrhBytes);

            rho = Arrays.CopyOfRange(buf, 0, SeedBytes);
            rhoPrime = Arrays.CopyOfRange(buf, SeedBytes, SeedBytes + CrhBytes);
            key = Arrays.CopyOfRange(buf, SeedBytes + CrhBytes, 2 * SeedBytes + CrhBytes);

            Matrix.ExpandMatrix(rho);

            s1.UniformEta(rhoPrime, (ushort)0);

            s2.UniformEta(rhoPrime, (ushort)L);

            s1Hat = new PolyVecL(this);

            s1.CopyPolyVecL(s1Hat);
            s1Hat.Ntt();

            Matrix.PointwiseMontgomery(t1, s1Hat);

            t1.Reduce();
            t1.InverseNttToMont();

            t1.AddPolyVecK(s2);
            t1.ConditionalAddQ();
            t1.Power2Round(t0);

            //Console.WriteLine("t1 = ");
            //for (int i = 0; i < K; ++i)
            //{
            //    Console.Write(String.Format("{0} [", i));
            //    foreach (short coeff in t1.Vec[i].Coeffs)
            //    {
            //        Console.Write(String.Format("{0}, ", coeff));
            //    }
            //    Console.Write("]\n");
            //}

            //Console.WriteLine("rho = {0}", Convert.ToHexString(rho));

            Packing.PackPublicKey(pk, rho, t1, this);

            Shake256Digest.BlockUpdate(pk, 0, CryptoPublicKeyBytes);
            Shake256Digest.DoFinal(tr, 0, SeedBytes);

            Packing.PackSecretKey(sk, rho, tr, key, t0, s1, s2, this);
        }

        public void SignSignature(byte[] sig, int siglen, byte[] msg, int msglen, byte[] sk)
        {
            int n;
            byte[] SeedBuf = new byte[3 * SeedBytes + 2 * CrhBytes];
            byte[] rho = new byte[SeedBytes], tr = new byte[SeedBytes], key = new byte[SeedBytes], mu = new byte[CrhBytes], rhoPrime = new byte[CrhBytes];
            ushort nonce = 0;
            PolyVecMatrix Matrix = new PolyVecMatrix(this);
            PolyVecL s1 = new PolyVecL(this), y = new PolyVecL(this), z = new PolyVecL(this);
            PolyVecK t0 = new PolyVecK(this), s2 = new PolyVecK(this), w1 = new PolyVecK(this), w0 = new PolyVecK(this), h = new PolyVecK(this);
            Poly cp = new Poly(this);

            Packing.UnpackSecretKey(rho, tr, key, t0, s1, s2, sk, this);

            ShakeDigest ShakeDigest256 = new ShakeDigest(256);
            ShakeDigest256.BlockUpdate(tr, 0, SeedBytes);
            ShakeDigest256.BlockUpdate(msg, 0, msglen);
            ShakeDigest256.DoFinal(mu, 0, CrhBytes);

            if (RandomizedSigning)
            {
                _random.NextBytes(rhoPrime);
            }
            else
            {
                byte[] KeyMu = Arrays.CopyOf(key, SeedBytes + CrhBytes);
                Array.Copy(mu, 0, KeyMu, SeedBytes, CrhBytes);
                ShakeDigest256.BlockUpdate(KeyMu, 0, SeedBytes + CrhBytes);
                ShakeDigest256.DoFinal(rhoPrime, 0, CrhBytes);
            }

            Matrix.ExpandMatrix(rho);

            //Console.WriteLine("Matrix = [");
            //for (int i = 0; i < K; i++)
            //{
            //    Console.Write("[", i);
            //    for (int j = 0; j < L; j++)
            //    {
            //        Console.Write("{0} {1} [", i, j);
            //        for (int co = 0; co < N; co++)
            //        {
            //            Console.Write("{0}, ", Matrix.Matrix[i].Vec[j].Coeffs[co]);
            //        }
            //        Console.Write("]\n");
            //    }
            //    Console.Write("]\n");
            //}
            //Console.Write("]\n");

            s1.Ntt();
            s2.Ntt();
            t0.Ntt();

        rej:
            y.UniformGamma1(rhoPrime, nonce++);
            y.CopyPolyVecL(z);
            z.Ntt();

            Matrix.PointwiseMontgomery(w1, z);

            //Console.WriteLine("w1 = ");
            //for (int i = 0; i < K; ++i)
            //{
            //    Console.Write(String.Format("{0} [", i));
            //    foreach (int coeff in w1.Vec[i].Coeffs)
            //    {
            //        Console.Write(String.Format("{0}, ", coeff));
            //    }
            //    Console.Write("]\n");
            //}


            w1.Reduce();
            w1.InverseNttToMont();

            w1.ConditionalAddQ();
            w1.Decompose(w0);
            
            //Console.WriteLine("w0 = ");
            //for (int i = 0; i < K; ++i)
            //{
            //    Console.Write(String.Format("{0} [", i));
            //    foreach (int coeff in w0.Vec[i].Coeffs)
            //    {
            //        Console.Write(String.Format("{0}, ", coeff));
            //    }
            //    Console.Write("]\n");
            //}

            w1.PackW1(sig);

            ShakeDigest256.BlockUpdate(mu, 0, CrhBytes);
            ShakeDigest256.BlockUpdate(sig, 0, K * PolyW1PackedBytes);
            ShakeDigest256.DoFinal(sig, 0, SeedBytes);

            cp.Challenge(sig);

            cp.PolyNtt();

            z.PointwisePolyMontgomery(cp, s1);
            z.InverseNttToMont();
            z.AddPolyVecL(y);
            z.Reduce();
            if (z.CheckNorm(Gamma1 - Beta))
            {
                goto rej;
            }

            //Console.WriteLine("cp = ");
            //Console.Write("[");
            //foreach (int coeff in cp.Coeffs)
            //{
            //    Console.Write(String.Format("{0}, ", coeff));
            //}
            //Console.Write("]\n");

            //Console.WriteLine("s2 = ");
            //for (int i = 0; i < K; ++i)
            //{
            //    Console.Write(String.Format("{0} [", i));
            //    foreach (int coeff in s2.Vec[i].Coeffs)
            //    {
            //        Console.Write(String.Format("{0}, ", coeff));
            //    }
            //    Console.Write("]\n");
            //}

            h.PointwisePolyMontgomery(cp, s2);
            h.InverseNttToMont();

            //Console.WriteLine("h = ");
            //for (int i = 0; i < K; ++i)
            //{
            //    Console.Write(String.Format("{0} [", i));
            //    foreach (int coeff in h.Vec[i].Coeffs)
            //    {
            //        Console.Write(String.Format("{0}, ", coeff));
            //    }
            //    Console.Write("]\n");
            //}

            w0.Subtract(h);
            w0.Reduce();
            if (w0.CheckNorm(Gamma2 - Beta))
            {
                goto rej;
            }

            h.PointwisePolyMontgomery(cp, t0);
            h.InverseNttToMont();
            h.Reduce();
            if (h.CheckNorm(Gamma2))
            {
                goto rej;
            }

            w0.AddPolyVecK(h);

            //Console.WriteLine("w0 = ");
            //for (int i = 0; i < K; ++i)
            //{
            //    Console.Write(String.Format("{0} [", i));
            //    foreach (int coeff in w0.Vec[i].Coeffs)
            //    {
            //        Console.Write(String.Format("{0}, ", coeff));
            //    }
            //    Console.Write("]\n");
            //}

            w0.ConditionalAddQ();

            //Console.WriteLine("w0 = ");
            //for (int i = 0; i < K; ++i)
            //{
            //    Console.Write(String.Format("{0} [", i));
            //    foreach (int coeff in w0.Vec[i].Coeffs)
            //    {
            //        Console.Write(String.Format("{0}, ", coeff));
            //    }
            //    Console.Write("]\n");
            //}

            //Console.WriteLine("w1 = ");
            //for (int i = 0; i < K; ++i)
            //{
            //    Console.Write(String.Format("{0} [", i));
            //    foreach (int coeff in w1.Vec[i].Coeffs)
            //    {
            //        Console.Write(String.Format("{0}, ", coeff));
            //    }
            //    Console.Write("]\n");
            //}

            n = h.MakeHint(w0, w1);
            if (n > Omega)
            {
                goto rej;
            }


            //Console.WriteLine("z = ");
            //for (int i = 0; i < L; ++i)
            //{
            //    Console.Write(String.Format("{0} [", i));
            //    foreach (int coeff in z.Vec[i].Coeffs)
            //    {
            //        Console.Write(String.Format("{0}, ", coeff));
            //    }
            //    Console.Write("]\n");
            //}

            //Console.WriteLine("h = ");
            //for (int i = 0; i < K; ++i)
            //{
            //    Console.Write(String.Format("{0} [", i));
            //    foreach (int coeff in h.Vec[i].Coeffs)
            //    {
            //        Console.Write(String.Format("{0}, ", coeff));
            //    }
            //    Console.Write("]\n");
            //}

            Packing.PackSignature(sig, sig, z, h, this);
        }

        public void Sign(byte[] sig, int siglen, byte[] msg, int msglen, byte[] sk)
        {
            SignSignature(sig, siglen, msg, msglen, sk);
        }

        public bool SignVerify(byte[] msg, int msglen, byte[] sig, int siglen, byte[] pk)
        {
            byte[] buf = new byte[K * PolyW1PackedBytes], rho = new byte[SeedBytes], mu = new byte[CrhBytes], c = new byte[SeedBytes], c2 = new byte[SeedBytes];
            Poly cp = new Poly(this);
            PolyVecMatrix Matrix = new PolyVecMatrix(this);
            PolyVecL z = new PolyVecL(this);
            PolyVecK t1 = new PolyVecK(this), w1 = new PolyVecK(this), h = new PolyVecK(this);

            if (sig.Length != CryptoBytes + msg.Length)
            {
                return false;
            }

            Packing.UnpackPublicKey(rho, t1, pk, this);

            //Console.WriteLine("rho = "+Convert.ToHexString(rho));

            //Console.WriteLine("t1 = ");
            //for (int i = 0; i < K; ++i)
            //{
            //    Console.Write(String.Format("{0} [", i));
            //    foreach (int coeff in t1.Vec[i].Coeffs)
            //    {
            //        Console.Write(String.Format("{0}, ", coeff));
            //    }
            //    Console.Write("]\n");
            //}


            if (!Packing.UnpackSignature(c, z, h, sig, this))
            {
                return false;
            }

            if (z.CheckNorm(Gamma1 - Beta))
            {
                return false;
            }

            //Console.WriteLine("z = ");
            //for (int i = 0; i < L; ++i)
            //{
            //    Console.Write(String.Format("{0} [", i));
            //    foreach (int coeff in z.Vec[i].Coeffs)
            //    {
            //        Console.Write(String.Format("{0}, ", coeff));
            //    }
            //    Console.Write("]\n");
            //}

            //Console.WriteLine("h = ");
            //for (int i = 0; i < K; ++i)
            //{
            //    Console.Write(String.Format("{0} [", i));
            //    foreach (int coeff in h.Vec[i].Coeffs)
            //    {
            //        Console.Write(String.Format("{0}, ", coeff));
            //    }
            //    Console.Write("]\n");
            //}



            ShakeDigest Shake256Digest = new ShakeDigest(256);
            Shake256Digest.BlockUpdate(pk, 0, CryptoPublicKeyBytes);
            Shake256Digest.DoFinal(mu, 0, SeedBytes);

            Shake256Digest.BlockUpdate(mu, 0, SeedBytes);
            Shake256Digest.BlockUpdate(msg, 0, msglen);
            Shake256Digest.DoFinal(mu, 0);

            cp.Challenge(c);

            Matrix.ExpandMatrix(rho);

            z.Ntt();
            Matrix.PointwiseMontgomery(w1, z);

            cp.PolyNtt();

            t1.ShiftLeft();
            t1.Ntt();
            t1.PointwisePolyMontgomery(cp, t1);

            w1.Subtract(t1);
            w1.Reduce();
            w1.InverseNttToMont();

            w1.ConditionalAddQ();
            w1.UseHint(w1, h);

            w1.PackW1(buf);

            Shake256Digest.BlockUpdate(mu, 0, CrhBytes);
            Shake256Digest.BlockUpdate(buf, 0, K * PolyW1PackedBytes);
            Shake256Digest.DoFinal(c2, 0, SeedBytes);

            for (int i = 0; i < SeedBytes; ++i)
            {
                if (c[i] != c2[i])
                {
                    return false;
                }
            }
            return true;
        }
        
        public bool SignOpen(byte[] msg, int msglen, byte[] sig, int siglen, byte[] pk)
        {
            int i;
            if (siglen < CryptoBytes)
            {
                goto badsig;
            }

            Array.Copy(sig, CryptoBytes, msg, 0, siglen - CryptoBytes);
            if (SignVerify(msg, siglen - CryptoBytes, sig, siglen, pk))
            {
                return true;
            }

        badsig:
            for (i = 0; i < msg.Length; i++)
            {
                msg[i] = 0;
            }
            return false;
        }
    }
}
