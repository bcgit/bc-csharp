using System;
using System.Collections.Generic;

using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Utilities;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Pqc.Crypto.NtruPrime
{
    internal class NtruPrimeEngine
    {
        // Key Sizes
        private readonly int _skBytes; // [KEM] Size of secret key
        private readonly int _pkBytes; // [KEM] Size of public key
        private readonly int _ctBytes; // [KEM] Size of ciphertext

        private readonly int _secretKeyBytes; // C Reference: SecretKey_bytes
        private readonly int _publicKeyBytes; // C Reference: PublicKey_bytes
        private readonly int _ciphertextsBytes; // C Reference: Ciphertext_bytes

        private readonly int _confirmBytes;
        private readonly int _inputsBytes; // For encoding _I-bit inputs
        private readonly int _topBytes;
        private readonly int _seedBytes;
        private readonly int _smallBytes;
        private readonly int _hashBytes;

        private readonly int SessionKeyBytes;

        // Parameters for NTRU
        private readonly int _p;
        private readonly int _q;

        private readonly int _roundedBytes; // Defined in params.h

        // private readonly int _rqBytes; // Defined in params.h - Public key bytes for streamlined nTRU
        private readonly bool _lpr;
        private readonly int _w;
        private readonly int _tau0;
        private readonly int _tau1;
        private readonly int _tau2;
        private readonly int _tau3;

        private readonly int _I;

        private readonly int _q12;
        private readonly uint _q31Div, _q31Mod; // 0x80000000 / q, 0x80000000 % q

        public int PrivateKeySize => _skBytes;
        public int PublicKeySize => _pkBytes;
        public int CipherTextSize => _ctBytes;
        public int SessionKeySize => SessionKeyBytes;

        public NtruPrimeEngine(int p, int q, bool lpr, int w, int tau0, int tau1, int tau2, int tau3,
            int skBytes, int pkBytes, int ctBytes, int roundedBytes, int rqBytes, int defaultKeyLen)
        {
            this._p = p;
            this._q = q;
            this._w = w;
            this._tau0 = tau0;
            this._tau1 = tau1;
            this._tau2 = tau2;
            this._tau3 = tau3;

            // KEM parameters
            this._roundedBytes = roundedBytes;
            this._skBytes = skBytes;
            this._pkBytes = pkBytes;
            this._ctBytes = ctBytes;

            this._lpr = lpr;

            this._confirmBytes = 32;
            this.SessionKeyBytes = defaultKeyLen;

            _smallBytes = ((p + 3) / 4);
            _q12 = ((q - 1) / 2);
            _q31Div = 0x80000000U / (uint)q;
            _q31Mod = 0x80000000U % (uint)q;
            _hashBytes = 32;

            if (lpr)
            {
                _seedBytes = 32;
                _I = 256;
                _inputsBytes = _I / 8;
                _topBytes = _I / 2;
                _ciphertextsBytes = roundedBytes + _topBytes;
                _secretKeyBytes = _smallBytes;
                _publicKeyBytes = _seedBytes + roundedBytes;
            }
            else
            {
                _inputsBytes = _smallBytes;
                _ciphertextsBytes = _roundedBytes;
                _secretKeyBytes = (2*_smallBytes);
                _publicKeyBytes = rqBytes;
            }
        }

        public void kem_keypair(byte[] pk, byte[] sk, SecureRandom random) //KEM_KeyGen
        {
            KeyGen(random, pk, sk);
            Array.Copy(pk, 0, sk, _secretKeyBytes, _publicKeyBytes);
            random.NextBytes(sk, _secretKeyBytes + _publicKeyBytes, _inputsBytes);
            HashPrefix(sk, 4, pk, _publicKeyBytes);
        }

        public void kem_enc(byte[] ct, byte[] ss, byte[] pk, SecureRandom random)
        {
            sbyte[] inputs;

            if (_lpr)
            {
                inputs = new sbyte[_I];
            }
            else
            {
                inputs = new sbyte[_p];
            }

            byte[] r_enc = new byte[_inputsBytes];
            byte[] cache = new byte[_hashBytes];

            HashPrefix(cache, 4, pk, _publicKeyBytes);

            if (_lpr)
            {
                InputsRandom(inputs, random);
            }
            else
            {
                ShortRandom(inputs, random);
            }

            Hide(ct, r_enc, inputs, pk, cache);
            HashSession(ss, 1, r_enc, ct);
        }

        public void kem_dec(byte[] ss, byte[] ct, byte[] sk)
        {
            byte[] pk = new byte[sk.Length - _secretKeyBytes];

            // Shift sk by _secretKeyBytes and copy to pk

            Array.Copy(sk, _secretKeyBytes, pk, 0, pk.Length);

            byte[] rho = new byte[pk.Length - _publicKeyBytes];

            // Shift pk by _publicKeyBytes and fill rho
            Array.Copy(pk, _publicKeyBytes, rho, 0, rho.Length);

            byte[] cache = new byte[rho.Length - _inputsBytes];

            // Shift rho by _inputsBytes and fill cache

            Array.Copy(rho, _inputsBytes, cache, 0, cache.Length);

            sbyte[] r;

            if (_lpr)
            {
                r = new sbyte[_I];
            }
            else
            {
                r = new sbyte[_p];
            }

            byte[] r_enc = new byte[_inputsBytes];
            byte[] cnew = new byte[_ciphertextsBytes + _confirmBytes];

            byte[] ct_dec = Arrays.Clone(ct); // ct somehow gets modified in Decrypt

            Decrypt(r, ct_dec, sk);

            Hide(cnew, r_enc, r, pk, cache);

            int mask = ctDiffMask(ct, cnew);

            for (int i = 0; i < _inputsBytes; ++i)
            {
                r_enc[i] ^= (byte)(mask & (r_enc[i] ^ rho[i]));
            }

            HashSession(ss, 1 + mask, r_enc, ct);
        }

        // ---------------------------------------------------------------------

        private void KeyGen(SecureRandom random, byte[] pk, byte[] sk) // ZKeyGen
        {
            if (_lpr)
            {
                short[] A = new short[_p];
                sbyte[] a = new sbyte[_p];

                // BEGIN: XKeyGen
                byte[] seedOut = new byte[_seedBytes];
                random.NextBytes(seedOut);
                Array.Copy(seedOut, 0, pk, 0, _seedBytes);
                short[] genOut = new short[_p];
                Generator(genOut, seedOut);

                // BEGIN: XKeyGen > KeyGen
                ShortRandom(a, random);
                short[] aG = new short[_p];
                NtruPrimeUtilities.RqMult(aG, genOut, a, _p, _q);
                Round(A, aG);
                // END XKeyGen > KeyGen
                // END: XKeyGen

                byte[] roundedEncOut = new byte[pk.Length];
                RoundedEncode(roundedEncOut, A);

                Array.Copy(roundedEncOut, 0, pk, _seedBytes, pk.Length - _seedBytes);

                ByteEncode(sk, a);
            }
            else
            {
                // KeyGen
                short[] h = new short[_p];
                sbyte[] f = new sbyte[_p];

                sbyte[] ginv = new sbyte[_p];
                sbyte[] g = new sbyte[_p];
                short[] finv = new short[_p];

                do
                {
                    ByteRandom(g, random);
                }
                while (NtruPrimeUtilities.R3Recip(ginv, g, _p) != 0);

                ShortRandom(f, random);
                NtruPrimeUtilities.RqRecip3(finv, f, _p, _q);
                NtruPrimeUtilities.RqMult(h, finv, g, _p, _q);
                // END KeyGen

                RqEncode(pk, h);

                ByteEncode(sk, f);

                byte[] smallEncOut = new byte[sk.Length];
                ByteEncode(smallEncOut, ginv);

                Array.Copy(smallEncOut, 0, sk, _smallBytes, sk.Length - _smallBytes);
            }
        }

        //----------------------- Streamlined --------------------------------

        private void ByteRandom(sbyte[] output, SecureRandom random)
        {
            byte[] smallRandom = new byte[4];
            for (int i = 0;i < _p;++i)
            {
                random.NextBytes(smallRandom);
                output[i] = (sbyte)((((BitConverter.ToUInt32(smallRandom, 0) & 0x3fffffff) * 3) >> 30)-1);
            };
        }

        private void RqEncode(byte[] output, short[] r)
        {
            ushort[] R = new ushort[_p];
            ushort[] M = new ushort[_p];

            for (int i = 0; i < _p; ++i)
            {
                R[i] = (ushort)(r[i] + _q12);
                M[i] = (ushort)_q;
            }

            Encode(output, 0, R, M, _p);
        }

        private void RqDecode(short[] output, byte[] s)
        {
            ushort[] R = new ushort[_p];
            ushort[] M = new ushort[_p];

            for (int i = 0; i < _p; ++i)
            {
                M[i] = (ushort)_q;
            }

            List<byte> rList = new List<byte>(s);
            List<ushort> mList = new List<ushort>(M);

            List<ushort> decoded = Decode(rList, mList);

            for (int i = 0; i < _p; ++i)
            {
                output[i] = (short)(decoded[i] - _q12);
            }
        }

        private void RqMult3(short[] output, short[] f)
        {
            for (int i = 0; i < _p; ++i)
            {
                output[i] = ArithmeticMod_q(f[i] * 3);
            }
        }

        private void R3FromRq(sbyte[] output, short[] r)
        {
            for (int i = 0; i < _p; ++i)
            {
                output[i] = (sbyte)ArithmeticMod_3(r[i]);
            }
        }

        private int WeightMask(sbyte[] r)
        {
            int weight = 0;

            for (int i = 0; i < _p; ++i)
            {
                weight += r[i]&1;
            }

            return NtruPrimeUtilities.NonZeroMask(weight - _w);
        }

        //---------------------------------------------------------------------

        private List<ushort> Decode(List<byte> S, List<ushort> M)
        {
            int limit = 16384;

            if (M.Count == 0)
            {
                return new List<ushort>();
            }

            if (M.Count == 1)
            {
                if (M[0] == 1)
                {
                    return new List<ushort>() { 0 };
                }
                if (M[0] <= 256)
                {
                    return new List<ushort>() { (ushort)Mod(S[0], M[0]) };
                } else
                {
                    return new List<ushort>() { (ushort)Mod(S[0] + (((uint)S[1]) << 8), M[0]) };
                }
            }

            int k = 0;
            List<ushort> bottomr = new List<ushort>();
            List<uint> bottomt = new List<uint>();
            List<ushort> M2 = new List<ushort>();

            for (int i = 0; i < M.Count - 1; i += 2)
            {
                uint m = (uint)(M[i] * M[i + 1]);
                ushort r = 0;
                uint t = 1;

                while (m >= limit)
                {
                    r = (ushort)(r + S[k] * t);
                    t = t * 256;
                    k = k + 1;
                    m = (uint)System.Math.Floor((double)((m + 255) / 256));
                }
                bottomr.Add(r);
                bottomt.Add(t);
                M2.Add((ushort)m);
            }

            if (M.Count % 2 != 0)
            {
                M2.Add(M[M.Count - 1]);
            }

            List<byte> S2 = new List<byte>();

            S2 = S.GetRange(k, S.Count - k);

            List<ushort> R2 = Decode(S2, M2);

            List<ushort> R = new List<ushort>();

            for (int i = 0; i < M.Count - 1; i += 2)
            {
                uint r = bottomr[i / 2];
                uint t = bottomt[i / 2];
                r += (uint)(t * R2[i / 2]);
                R.Add((ushort)Mod(r, M[i]));
                R.Add((ushort)(Mod(System.Math.Floor((double)r / M[i]), M[i + 1])));
            }
            if (M.Count % 2 != 0)
            {
                R.Add(R2[M2.Count - 1]);
            }
            return R;
        }

        private int Encode(byte[] output, int outputPos, ushort[] R, ushort[] M, long len)
        {
            int limit = 16384;
            if (len == 1)
            {
                ushort r = R[0];
                ushort m = M[0];

                while (m > 1)
                {
                    output[outputPos++] = (byte)r;
                    r >>= 8;
                    m = (ushort)((m + 255) >> 8);
                }
            }

            if (len > 1)
            {
                ushort[] R2 = new ushort[(len + 1) / 2];
                ushort[] M2 = new ushort[(len + 1) / 2];

                int i;
                for (i = 0; i < len - 1; i += 2)
                {
                    uint m0 = M[i];
                    uint r = R[i] + R[i + 1] * m0;
                    uint m = M[i + 1] * m0;

                    while (m >= limit)
                    {
                        output[outputPos++] = (byte)r;
                        r >>= 8;
                        m = (m + 255) >> 8;
                    }

                    R2[i / 2] = (ushort)r;
                    M2[i / 2] = (ushort)m;
                }

                if (i < len)
                {
                    R2[i / 2] = R[i];
                    M2[i / 2] = M[i];
                }

                outputPos = Encode(output, outputPos, R2, M2, (len + 1) / 2);
            }

            return outputPos;
        }

        private void Encrypt(byte[] output, sbyte[] r, byte[] pk) // ZEncrypt
        {
            if (_lpr)
            {
                short[] A = new short[_p];
                short[] B = new short[_p];
                sbyte[] T = new sbyte[_I];

                byte[] pkMinusSeed = new byte[pk.Length - _seedBytes];
                Array.Copy(pk, _seedBytes, pkMinusSeed, 0, pkMinusSeed.Length);

                RoundedDecode(A, pkMinusSeed);

                // BEGIN: XEncrypt
                short[] G = new short[_p];
                sbyte[] b = new sbyte[_p];
                byte[] seedOut = new byte[_seedBytes];

                Array.Copy(pk, 0, seedOut, 0, _seedBytes);

                Generator(G, seedOut);
                HashShort(b, r);

                // BEGIN: Encrypt
                short[] bG = new short[_p];
                short[] bA = new short[_p];

                NtruPrimeUtilities.RqMult(bG, G, b, _p, _q);

                Round(B, bG);

                NtruPrimeUtilities.RqMult(bA, A, b, _p, _q);

                for (int i = 0; i < _I; ++i)
                {
                    T[i] = Top(ArithmeticMod_q(bA[i] + r[i] * _q12));
                }
                // END: Encrypt
                // END: XEncrypt

                RoundedEncode(output, B);
                byte[] topEncOut = new byte[output.Length];
                TopEncode(topEncOut, T);
                Array.Copy(topEncOut, 0, output, _roundedBytes, output.Length - _roundedBytes);
            }
            else
            {
                short[] h = new short[_p];
                short[] c = new short[_p];

                RqDecode(h, pk);

                // Encrypt
                short[] hr = new short[_p];
                NtruPrimeUtilities.RqMult(hr, h, r, _p, _q);
                Round(c, hr);
                // END Encrypt

                RoundedEncode(output, c);
            }
        }

        private void Decrypt(sbyte[] output, byte[] c, byte[] sk) // ZDecrypt
        {
            if (_lpr)
            {
                sbyte[] a = new sbyte[_p];
                short[] B = new short[_p];
                sbyte[] T = new sbyte[_I];

                ByteDecode(a, sk);
                RoundedDecode(B, c);

                Array.Copy(c, _roundedBytes, c, 0, c.Length - _roundedBytes);

                TopDecode(T, c);

                // BEGIN: XDecrypt
                short[] aB = new short[_p];

                NtruPrimeUtilities.RqMult(aB, B, a, _p, _q);

                for (int i = 0; i < _I; ++i)
                {
                    int freeze = ArithmeticMod_q(Right(T[i]) - aB[i] + 4 * _w + 1);
                    output[i] = (sbyte)(-NtruPrimeUtilities.NegativeMask(freeze));
                }
                // END: XDecrypt
            }
            else
            {
                sbyte[] f = new sbyte[_p];
                sbyte[] v = new sbyte[_p];

                short[] c2 = new short[_p];

                ByteDecode(f, sk);

                byte[] skShift = new byte[sk.Length];

                Array.Copy(sk, _smallBytes, skShift, 0, skShift.Length - _smallBytes);

                ByteDecode(v, skShift);

                RoundedDecode(c2, c);

                short[] cf = new short[_p];
                short[] cf3 = new short[_p];
                sbyte[] e = new sbyte[_p];
                sbyte[] ev = new sbyte[_p];

                NtruPrimeUtilities.RqMult(cf, c2, f, _p, _q);
                RqMult3(cf3, cf);
                R3FromRq(e, cf3);
                NtruPrimeUtilities.R3Mult(ev, e, v, _p);

                int mask = WeightMask(ev);

                for (int i = 0; i < _w; ++i)
                {
                    output[i] = (sbyte)(((ev[i] ^ 1) & ~mask) ^ 1);
                }

                for (int i = _w; i < _p; ++i)
                {
                    output[i] = (sbyte)(ev[i] & ~mask);
                }
            }
        }

        private void Hide(byte[] output, byte[] r_enc, sbyte[] r, byte[] pk, byte[] cache)
        {
            /* c,r_enc = Hide(r,pk,cache); cache is Hash4(pk) */

            if (_lpr)
            {
                InputsEncode(r_enc, r);
            }
            else
            {
                ByteEncode(r_enc, r);
            }

            Encrypt(output, r, pk);

            Array.Copy(output, 0, output, _ctBytes, output.Length - _ctBytes);

            HashConfirm(output, r_enc, pk, cache);
        }

        private void Generator(short[] output, byte[] seed)
        {
            uint[] L = Expand(seed);

            for (int i = 0; i < _p; i++)
            {
                output[i] = (short)((L[i] % _q) - _q12);
            }
        }

        private uint[] Expand(byte[] k)
        {
            byte[] data = new byte[_p * 4];

            // AES256 CTR
            BufferedBlockCipher cipher = new BufferedBlockCipher(new SicBlockCipher(AesUtilities.CreateEngine()));
            KeyParameter kp = new KeyParameter(k);
            cipher.Init(true, new ParametersWithIV(kp, new byte[16]));
            int len = cipher.ProcessBytes(data, 0, _p * 4, data, 0);
            len += cipher.DoFinal(data, len);

            return Pack.LE_To_UInt32(data, 0, _p);
        }

        private void ShortRandom(sbyte[] output, SecureRandom random)
        {
            uint[] L = new uint[_p];
            byte[] shortRandom = new byte[4];

            for (int i = 0; i < _p; ++i)
            {
                random.NextBytes(shortRandom);
                L[i] = BitConverter.ToUInt32(shortRandom, 0);
            }
            ShortFromList(output, L);
        }

        private void ShortFromList(sbyte[] output, uint[] L_in)
        {
            uint[] L = new uint[_p];

            for (int i = 0; i < _w; ++i)
            {
                L[i] = (uint)(L_in[i] & -2);
            }

            for (int i = _w; i < _p; ++i)
            {
                L[i] = (uint)(L_in[i] & -3) | 1;
            }

            NtruPrimeUtilities.SortUInt32(L);

            for (int i = 0; i < _p; ++i)
            {
                output[i] = (sbyte)((L[i] & 3) - 1);
            }
        }

        private void Round(short[] output, short[] aG)
        {
            for (int i = 0; i < _p; ++i)
            {
                output[i] = (short)(aG[i] - ArithmeticMod_3(aG[i]));
            }
        }

        private void InputsRandom(sbyte[] output, SecureRandom random)
        {
            byte[] s = new byte[_inputsBytes];
            random.NextBytes(s);
            for (int i = 0; i < _I; ++i)
            {
                output[i] = (sbyte)(1 & (s[i >> 3] >> (i & 7)));
            }
        }

        private void InputsEncode(byte[] output, sbyte[] r)
        {
            for (int i = 0; i < _inputsBytes; ++i)
            {
                output[i] = 0;
            }

            for (int i = 0; i < _I; ++i)
            {
                output[i >> 3] |= (byte)(r[i] << (i & 7));
            }
        }

        private void RoundedEncode(byte[] output, short[] A)
        {
            ushort[] R = new ushort[_p];
            ushort[] M = new ushort[_p];

            for (int i = 0; i < _p; ++i)
            {
                R[i] = (ushort)(((A[i] + _q12) * 10923) >> 15);
            }

            for (int i = 0; i < _p; ++i)
            {
                M[i] = (ushort)((_q + 2) / 3);
            }

            Encode(output, 0, R, M, _p);
        }

        private void RoundedDecode(short[] output, byte[] s)
        {
            List<ushort> M = new List<ushort>(_p);
            List<byte> S = new List<byte>(s);

            for (int i = 0; i < _p; ++i)
            {
                M.Add((ushort)((_q + 2) / 3));
            }

            List<ushort> decoded = Decode(S, M);

            for (int i = 0; i < _p; ++i)
            {
                output[i] = (short)((decoded[i] * 3) - _q12);
            }
        }

        private void ByteEncode(byte[] output, sbyte[] a)
        {
            sbyte x;
            for (int i = 0; i < _p / 4; ++i)
            {
                int x0 = a[4 * i] + 1;
                int x1 = (a[4 * i + 1] + 1) << 2;
                int x2 = (a[4 * i + 2] + 1) << 4;
                int x3 = (a[4 * i + 3] + 1) << 6;
                x = (sbyte)(x0 + x1 + x2 + x3);
                output[i] = (byte)x;
            }
            output[_p / 4] = (byte)(a[_p - 1] + 1);
        }

        private void ByteDecode(sbyte[] output, byte[] s)
        {
            byte x;
            for (int i = 0; i < _p / 4; ++i)
            {
                x = s[i];
                output[i * 4] = (sbyte)((x & 3) - 1);
                x >>= 2;
                output[i * 4 + 1] = (sbyte)((x & 3) - 1);
                x >>= 2;
                output[i * 4 + 2] = (sbyte)((x & 3) - 1);
                x >>= 2;
                output[i * 4 + 3] = (sbyte)((x & 3) - 1);
            }

            x = s[_p / 4];
            output[_p / 4 * 4] = (sbyte)((x & 3) - 1);
        }

        private void TopEncode(byte[] output, sbyte[] T)
        {
            for (int i = 0; i < _topBytes; ++i)
            {
                output[i] = (byte)(T[2 * i] + (T[2 * i + 1] << 4));
            }
        }

        private void TopDecode(sbyte[] output, byte[] s)
        {
            for (int i = 0; i < _topBytes; ++i)
            {
                output[2 * i] = (sbyte)(s[i] & 15);
                output[2 * i + 1] = (sbyte)(s[i] >> 4);
            }
        }

        private void HashShort(sbyte[] output, sbyte[] r)
        {
            byte[] s = new byte[_inputsBytes];
            byte[] h = new byte[_hashBytes];
            uint[] L = new uint[_p];

            InputsEncode(s, r);
            HashPrefix(h, 5, s, s.Length);
            L = Expand(h);
            ShortFromList(output, L);
        }

        private void HashPrefix(byte[] output, int b, byte[] input, int inlen)
        {
            byte[] h = new byte[64];

            Sha512Digest sha512 = new Sha512Digest();
            sha512.Update((byte)b);
            sha512.BlockUpdate(input, 0, inlen);
            sha512.DoFinal(h, 0);

            Array.Copy(h, 0, output, output.Length - 32, 32);
        }

        private void HashConfirm(byte[] output, byte[] r, byte[] pk, byte[] cache)
        {
            byte[] x;
            if (_lpr)
            {
                x = new byte[_inputsBytes + _hashBytes];

                Array.Copy(r, 0, x, 0, _inputsBytes);
                Array.Copy(cache, 0, x, _inputsBytes, _hashBytes);
            }
            else
            {
                x = new byte[_hashBytes * 2];

                byte[] prefix = new byte[_hashBytes];
                HashPrefix(prefix, 3, r, _inputsBytes);

                Array.Copy(prefix, 0, x, 0, _hashBytes);
                Array.Copy(cache, 0, x, _hashBytes, _hashBytes);
            }
            HashPrefix(output, 2, x, x.Length);
        }

        private void HashSession(byte[] output, int b, byte[] y, byte[] z)
        {
            byte[] x;

            if (_lpr)
            {
                x = new byte[_inputsBytes + _ciphertextsBytes + _confirmBytes];

                Array.Copy(y, 0, x, 0, _inputsBytes);
                Array.Copy(z, 0, x, _inputsBytes, _ciphertextsBytes + _confirmBytes);
            }
            else
            {
                x = new byte[_hashBytes + _ciphertextsBytes + _confirmBytes];

                byte[] prefix = new byte[_hashBytes];
                HashPrefix(prefix, 3, y, _inputsBytes);

                Array.Copy(prefix, 0, x, 0, _hashBytes);
                Array.Copy(z, 0, x, _hashBytes, _ciphertextsBytes + _confirmBytes);
            }

            byte[] hash = new byte[32];
            HashPrefix(hash, b, x, x.Length);
            Array.Copy(hash, 0, output, 0, output.Length);
        }

        private int ctDiffMask(byte[] c, byte[] c2)
        {
            int x = c.Length ^ c2.Length;
            for (int i = 0; i < c.Length && i < c2.Length; ++i)
            {
                x |= c[i] ^ c2[i];
            }

            // Return 0 if matching, else -1
            return (-x | x) >> 31;
        }

        // Arithmetics

        // For public values only (decoding); secret values go through NtruPrimeUtilities.Freeze
        private double Mod(double a, double b)
        {
            return a - b * System.Math.Floor(a / b);
        }

        private short ArithmeticMod_q(int x)  // Fq_freeze
        {
            return (short)NtruPrimeUtilities.Freeze(x, _q, _q31Div, _q31Mod);
        }

        private short ArithmeticMod_3(int x) // F3_freeze
        {
            return (short)NtruPrimeUtilities.Freeze3(x);
        }

        private sbyte Top(int C)
        {
            return (sbyte)((_tau1 * (C + _tau0) + 16384) >> 15);
        }

        private short Right(sbyte T)
        {
            return ArithmeticMod_q(_tau3 * T - _tau2);
        }
    }
}
