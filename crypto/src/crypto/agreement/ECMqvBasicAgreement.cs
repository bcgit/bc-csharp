using System;

using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Math.EC;
using Org.BouncyCastle.Security;

namespace Org.BouncyCastle.Crypto.Agreement
{
    /// <summary>EC MQV key agreement.</summary>
    // TODO[api] sealed
    public class ECMqvBasicAgreement
        : IBasicAgreement
    {
        /// <summary>The private parameters set by <c>Init</c>.</summary>
        // TODO[api] private
        protected internal MqvPrivateParameters privParams;

        /// <inheritdoc/>
        public virtual void Init(ICipherParameters parameters)
        {
            var kParam = ParameterUtilities.IgnoreRandom(parameters);

            if (!(kParam is MqvPrivateParameters mqvPrivateParameters))
                throw new ArgumentException($"{nameof(ECMqvBasicAgreement)} expects {nameof(MqvPrivateParameters)}");

            this.privParams = mqvPrivateParameters;
        }

        /// <inheritdoc/>
        public virtual int GetFieldSize() => privParams.StaticPrivateKey.Parameters.Curve.FieldElementEncodingLength;

        /// <inheritdoc/>
        public virtual BigInteger CalculateAgreement(ICipherParameters pubKey) =>
            CalculateAgreementFieldElement(privParams, (MqvPublicParameters)pubKey).ToBigInteger();

        internal static ECFieldElement CalculateAgreementFieldElement(MqvPrivateParameters privateParameters,
            MqvPublicParameters publicParameters)
        {
            ECPrivateKeyParameters staticPrivateKey = privateParameters.StaticPrivateKey;
            ECDomainParameters parameters = staticPrivateKey.Parameters;

            if (!parameters.Equals(publicParameters.StaticPublicKey.Parameters))
                throw new InvalidOperationException("ECMQV public key components have wrong domain parameters");

            ECPoint agreement = CalculateMqvAgreement(parameters, staticPrivateKey,
                privateParameters.EphemeralPrivateKey, privateParameters.EphemeralPublicKey,
                publicParameters.StaticPublicKey, publicParameters.EphemeralPublicKey).Normalize();

            if (agreement.IsInfinity)
                throw new InvalidOperationException("Infinity is not a valid agreement value for MQV");

            return agreement.AffineXCoord;
        }

        // The ECMQV Primitive as described in SEC-1, 3.4
        private static ECPoint CalculateMqvAgreement(ECDomainParameters parameters, ECPrivateKeyParameters d1U,
            ECPrivateKeyParameters d2U, ECPublicKeyParameters Q2U, ECPublicKeyParameters Q1V, ECPublicKeyParameters Q2V)
        {
            BigInteger n = parameters.N;
            int e = (n.BitLength + 1) / 2;
            BigInteger powE = BigInteger.One.ShiftLeft(e);

            ECCurve curve = parameters.Curve;

            ECPoint q2u = ECAlgorithms.CleanPoint(curve, Q2U.Q);
            ECPoint q1v = ECAlgorithms.CleanPoint(curve, Q1V.Q);
            ECPoint q2v = ECAlgorithms.CleanPoint(curve, Q2V.Q);

            BigInteger x = q2u.AffineXCoord.ToBigInteger();
            BigInteger xBar = x.Mod(powE);
            BigInteger Q2UBar = xBar.SetBit(e);
            BigInteger s = d1U.D.Multiply(Q2UBar).Add(d2U.D).Mod(n);

            BigInteger xPrime = q2v.AffineXCoord.ToBigInteger();
            BigInteger xPrimeBar = xPrime.Mod(powE);
            BigInteger Q2VBar = xPrimeBar.SetBit(e);

            BigInteger hs = parameters.H.Multiply(s).Mod(n);

            return ECAlgorithms.SumOfTwoMultipliesSecret(q1v, Q2VBar.Multiply(hs).Mod(n), q2v, hs);
        }
    }
}
