﻿using System.Diagnostics;

using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Pqc.Crypto.Crystals.Dilithium
{
    internal class Packing
    {
        internal static byte[] PackPublicKey(PolyVec t1, DilithiumEngine engine)
        {
            Debug.Assert(t1.Vec.Length == engine.K);
            byte[] output = new byte[engine.CryptoPublicKeyBytes - DilithiumEngine.SeedBytes];
            for (int i = 0; i < engine.K; i++)
            {
                t1.Vec[i].PolyT1Pack(output, i * DilithiumEngine.PolyT1PackedBytes);
            }
            return output;
        }

        internal static void UnpackPublicKey(PolyVec t1, byte[] pk, DilithiumEngine engine)
        {
            Debug.Assert(t1.Vec.Length == engine.K);
            for (int i = 0; i < engine.K; ++i)
            {
                t1.Vec[i].PolyT1Unpack(pk, i * DilithiumEngine.PolyT1PackedBytes);
            }
        }

        internal static void PackSecretKey(byte[] t0_, byte[] s1_, byte[] s2_, PolyVec t0, PolyVec s1, PolyVec s2,
            DilithiumEngine engine)
        {
            Debug.Assert(t0.Vec.Length == engine.K);
            Debug.Assert(s1.Vec.Length == engine.L);
            Debug.Assert(s2.Vec.Length == engine.K);

            int i;
            for (i = 0; i < engine.L; ++i)
            {
                s1.Vec[i].PolyEtaPack(s1_, i * engine.PolyEtaPackedBytes);
            }
            for (i = 0; i < engine.K; ++i)
            {
                s2.Vec[i].PolyEtaPack(s2_, i * engine.PolyEtaPackedBytes);
            }
            for (i = 0; i < engine.K; ++i)
            {
                t0.Vec[i].PolyT0Pack(t0_, i * DilithiumEngine.PolyT0PackedBytes);
            }
        }

        internal static void UnpackSecretKey(PolyVec t0, PolyVec s1, PolyVec s2, byte[] t0Enc, byte[] s1Enc,
            byte[] s2Enc, DilithiumEngine engine)
        {
            Debug.Assert(t0.Vec.Length == engine.K);
            Debug.Assert(s1.Vec.Length == engine.L);
            Debug.Assert(s2.Vec.Length == engine.K);

            int i;
            for (i = 0; i < engine.L; ++i)
            {
                s1.Vec[i].PolyEtaUnpack(s1Enc,i * engine.PolyEtaPackedBytes);
            }
            for (i = 0; i < engine.K; ++i)
            {
                s2.Vec[i].PolyEtaUnpack(s2Enc,i * engine.PolyEtaPackedBytes);
            }
            for (i = 0; i < engine.K; ++i)
            {
                t0.Vec[i].PolyT0Unpack(t0Enc,i * DilithiumEngine.PolyT0PackedBytes);
            }
        }

        internal static void PackSignature(byte[] sig, //byte[] c,
            PolyVec z, PolyVec h, DilithiumEngine engine)
        {
            Debug.Assert(z.Vec.Length == engine.L);
            Debug.Assert(h.Vec.Length == engine.K);

            int i, j;

            //Array.Copy(c, 0, sig, 0, engine.CTilde);

            int end = engine.CTilde;
            for (i = 0; i < engine.L; ++i)
            {
                z.Vec[i].PackZ(sig, end);
                end += engine.PolyZPackedBytes;
            }

            for (i = 0; i < engine.Omega + engine.K; ++i)
            {
                sig[end + i] = 0;
            }

            int k = 0;
            for (i = 0; i < engine.K; ++i)
            {
                for (j = 0; j < DilithiumEngine.N; ++j)
                {
                    if (h.Vec[i].Coeffs[j] != 0)
                    {
                        sig[end + k++] = (byte)j;
                    }
                }
                sig[end + engine.Omega + i] = (byte)k;
            }
        }

        internal static bool UnpackSignature(PolyVec z, PolyVec h, byte[] sig, DilithiumEngine engine)
        {
            Debug.Assert(z.Vec.Length == engine.L);
            Debug.Assert(h.Vec.Length == engine.K);

            int i, j;

            int end = engine.CTilde;
            for (i = 0; i < engine.L; ++i)
            {
                int pos = end;
                end += engine.PolyZPackedBytes;

                z.Vec[i].UnpackZ(Arrays.CopyOfRange(sig, pos, end));
            }

            int k = 0;
            for (i = 0; i < engine.K; ++i)
            {
                for (j = 0; j < DilithiumEngine.N; ++j)
                {
                    h.Vec[i].Coeffs[j] = 0;
                }

                int sig_end_omega_i = sig[end + engine.Omega + i];
                if (sig_end_omega_i < k || sig_end_omega_i > engine.Omega)
                    return false;

                for (j = k; j < sig_end_omega_i; ++j)
                {
                    if (j > k && sig[end + j] <= sig[end + j - 1])
                        return false;

                    h.Vec[i].Coeffs[sig[end + j]] = 1;
                }

                k = sig_end_omega_i;
            }
            for (j = k; j < engine.Omega; ++j)
            {
                if (sig[end + j] != 0)
                    return false;
            }
            return true;
        }
    }
}
