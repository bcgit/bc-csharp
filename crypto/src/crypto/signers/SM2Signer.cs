using System;
using System.Diagnostics;

using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Math.EC;
using Org.BouncyCastle.Math.EC.Multiplier;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities;
using Org.BouncyCastle.Utilities.Encoders;

namespace Org.BouncyCastle.Crypto.Signers
{
    /// <summary>The SM2 Digital Signature algorithm.</summary>
    public class SM2Signer
        : ISigner
    {
        private enum State
        {
            Uninitialized = 0,
            Init          = 1,
            Data          = 2,
        }

        private readonly IDsaKCalculator kCalculator = new RandomDsaKCalculator();
        private readonly IDigest digest;
        private readonly IDsaEncoding encoding;

        private State m_state = State.Uninitialized;
        private ECDomainParameters ecParams;
        private ECPoint pubPoint;
        private ECKeyParameters ecKey;
        private byte[] z;

        public SM2Signer()
            : this(StandardDsaEncoding.Instance, new SM3Digest())
        {
        }

        public SM2Signer(IDigest digest)
            : this(StandardDsaEncoding.Instance, digest)
        {
        }

        public SM2Signer(IDsaEncoding encoding)
            : this(encoding, new SM3Digest())
        {
        }

        public SM2Signer(IDsaEncoding encoding, IDigest digest)
        {
            this.encoding = encoding;
            this.digest = digest;
        }

        public virtual string AlgorithmName => "SM2Sign";

        public virtual void Init(bool forSigning, ICipherParameters parameters)
        {
            ICipherParameters baseParam;
            byte[] userID;

            if (parameters is ParametersWithID withID)
            {
                baseParam = withID.Parameters;
                userID = withID.GetID();

                // The length in bits must be expressible in two bytes
                if (userID.Length >= 8192)
                    throw new ArgumentException("SM2 user ID must be less than 2^16 bits long");
            }
            else
            {
                baseParam = parameters;
                // the default value, string value is "1234567812345678"
                userID = Hex.DecodeStrict("31323334353637383132333435363738");
            }

            if (forSigning)
            {
                var ecPrivateKey = (ECPrivateKeyParameters)ParameterUtilities.GetRandom(baseParam, out var random);

                ecKey = ecPrivateKey;
                ecParams = ecPrivateKey.Parameters;

                BigInteger d = ecPrivateKey.D;
                BigInteger n = ecParams.N;

                if (d.CompareTo(BigInteger.One) < 0 || d.CompareTo(n.Subtract(BigInteger.One)) >= 0)
                    throw new ArgumentException("SM2 private key out of range");

                kCalculator.Init(n, CryptoServicesRegistrar.GetSecureRandom(random));
                pubPoint = CreateBasePointMultiplier().Multiply(ecParams.G, d).Normalize();
            }
            else
            {
                var ecPublicKey = (ECPublicKeyParameters)baseParam;

                ecKey = ecPublicKey;
                ecParams = ecPublicKey.Parameters;
                pubPoint = ecPublicKey.Q;
            }

            digest.Reset();
            z = GetZ(userID);
            m_state = State.Init;
        }

        public virtual void Update(byte b)
        {
            CheckData();

            digest.Update(b);
        }

        public virtual void BlockUpdate(byte[] input, int inOff, int inLen)
        {
            CheckData();

            digest.BlockUpdate(input, inOff, inLen);
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        public virtual void BlockUpdate(ReadOnlySpan<byte> input)
        {
            CheckData();

            digest.BlockUpdate(input);
        }
#endif

        public virtual int GetMaxSignatureSize() => encoding.GetMaxEncodingSize(ecParams.N);

        public virtual byte[] GenerateSignature()
        {
            CheckData();

            byte[] eHash = DigestUtilities.DoFinal(digest);

            BigInteger n = ecParams.N;
            BigInteger e = CalculateE(n, eHash);
            BigInteger d = ((ECPrivateKeyParameters)ecKey).D;

            BigInteger r, s;

            ECMultiplier basePointMultiplier = CreateBasePointMultiplier();

            // 5.2.1 Draft RFC:  SM2 Public Key Algorithms
            do // generate s
            {
                BigInteger k;
                do // generate r
                {
                    // A3
                    k = kCalculator.NextK();

                    // A4
                    ECPoint p = basePointMultiplier.Multiply(ecParams.G, k).Normalize();

                    // A5
                    r = e.Add(p.AffineXCoord.ToBigInteger()).Mod(n);
                }
                while (r.SignValue == 0 || r.Add(k).Equals(n));

                // A6
                BigInteger dPlus1ModN = BigIntegers.ModOddInverse(n, d.Add(BigIntegers.One));

                s = k.Subtract(r.Multiply(d)).Mod(n);
                s = dPlus1ModN.Multiply(s).Mod(n);
            }
            while (s.SignValue == 0);

            // A7
            try
            {
                return encoding.Encode(ecParams.N, r, s);
            }
            catch (Exception ex)
            {
                throw new CryptoException("unable to encode signature: " + ex.Message, ex);
            }
            finally
            {
                Reset();
            }
        }

        public virtual bool VerifySignature(byte[] signature)
        {
            CheckData();

            try
            {
                BigInteger[] rs = encoding.Decode(ecParams.N, signature);

                return VerifySignature(rs[0], rs[1]);
            }
            catch (Exception)
            {
            }
            finally
            {
                Reset();
            }

            return false;
        }

        public virtual void Reset()
        {
            switch (m_state)
            {
            case State.Init:
                return;
            case State.Data:
                break;
            default:
                throw new InvalidOperationException(AlgorithmName + " needs to be initialized");
            }

            digest.Reset();
            m_state = State.Init;
        }

        private bool VerifySignature(BigInteger r, BigInteger s)
        {
            BigInteger n = ecParams.N;

            // 5.3.1 Draft RFC:  SM2 Public Key Algorithms
            // B1
            if (r.CompareTo(BigInteger.One) < 0 || r.CompareTo(n) >= 0)
                return false;

            // B2
            if (s.CompareTo(BigInteger.One) < 0 || s.CompareTo(n) >= 0)
                return false;

            // B3
            byte[] eHash = DigestUtilities.DoFinal(digest);

            // B4
            BigInteger e = CalculateE(n, eHash);

            // B5
            BigInteger t = r.Add(s).Mod(n);
            if (t.SignValue == 0)
                return false;

            // B6
            ECPoint q = ((ECPublicKeyParameters)ecKey).Q;
            ECPoint x1y1 = ECAlgorithms.SumOfTwoMultiplies(ecParams.G, s, q, t).Normalize();
            if (x1y1.IsInfinity)
                return false;

            // B7
            BigInteger expectedR = e.Add(x1y1.AffineXCoord.ToBigInteger()).Mod(n);

            return expectedR.Equals(r);
        }

        private void CheckData()
        {
            switch (m_state)
            {
            case State.Init:
                break;
            case State.Data:
                return;
            default:
                throw new InvalidOperationException(AlgorithmName + " needs to be initialized");
            }

            digest.BlockUpdate(z, 0, z.Length);
            m_state = State.Data;
        }

        private byte[] GetZ(byte[] userID)
        {
            AddUserID(digest, userID);

            AddFieldElement(digest, ecParams.Curve.A);
            AddFieldElement(digest, ecParams.Curve.B);
            AddFieldElement(digest, ecParams.G.AffineXCoord);
            AddFieldElement(digest, ecParams.G.AffineYCoord);
            AddFieldElement(digest, pubPoint.AffineXCoord);
            AddFieldElement(digest, pubPoint.AffineYCoord);

            return DigestUtilities.DoFinal(digest);
        }

        private static void AddUserID(IDigest digest, byte[] userID)
        {
            uint len = (uint)(userID.Length * 8);
            Debug.Assert(len >> 16 == 0);

            digest.Update((byte)(len >> 8));
            digest.Update((byte)len);
            digest.BlockUpdate(userID, 0, userID.Length);
        }

        private static void AddFieldElement(IDigest digest, ECFieldElement v)
        {
            byte[] p = v.GetEncoded();
            digest.BlockUpdate(p, 0, p.Length);
        }

        protected virtual BigInteger CalculateE(BigInteger n, byte[] message)
        {
            // TODO Should hashes larger than the order be truncated as with ECDSA?
            return new BigInteger(1, message);
        }

        protected virtual ECMultiplier CreateBasePointMultiplier()
        {
            return new FixedPointCombMultiplier();
        }
    }
}
