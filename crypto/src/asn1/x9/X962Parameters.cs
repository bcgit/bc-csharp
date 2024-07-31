using System;

using Org.BouncyCastle.Asn1;

namespace Org.BouncyCastle.Asn1.X9
{
    public class X962Parameters
        : Asn1Encodable, IAsn1Choice
    {
        private readonly Asn1Object _params;

		public static X962Parameters GetInstance(object obj)
		{
            if (obj == null)
                return null;

			if (obj is X962Parameters x962Parameters)
				return x962Parameters;

			if (obj is Asn1Object asn1Object)
				return new X962Parameters(asn1Object);

			if (obj is byte[] bytes)
			{
				try
				{
					return new X962Parameters(Asn1Object.FromByteArray(bytes));
				}
				catch (Exception e)
				{
					throw new ArgumentException("unable to parse encoded data: " + e.Message, e);
				}
			}

			throw new ArgumentException("unknown object in GetInstance()");
		}

        public static X962Parameters GetInstance(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            Asn1Utilities.GetInstanceChoice(taggedObject, declaredExplicit, GetInstance);

        public static X962Parameters GetTagged(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            Asn1Utilities.GetTaggedChoice(taggedObject, declaredExplicit, GetInstance);

        public X962Parameters(
            X9ECParameters ecParameters)
        {
            this._params = ecParameters.ToAsn1Object();
        }

		public X962Parameters(
            DerObjectIdentifier namedCurve)
        {
            this._params = namedCurve;
        }

        public X962Parameters(
            Asn1Null obj)
        {
            this._params = obj;
        }

        private X962Parameters(Asn1Object obj)
        {
            this._params = obj;
        }

		public bool IsNamedCurve
        {
			get { return (_params is DerObjectIdentifier); }
        }

		public bool IsImplicitlyCA
        {
			get { return (_params is Asn1Null); }
        }

		public Asn1Object Parameters
        {
            get { return _params; }
        }

		/**
         * Produce an object suitable for an Asn1OutputStream.
         * <pre>
         * Parameters ::= CHOICE {
         *    ecParameters ECParameters,
         *    namedCurve   CURVES.&amp;id({CurveNames}),
         *    implicitlyCA Null
         * }
         * </pre>
         */
        public override Asn1Object ToAsn1Object()
        {
            return _params;
        }
    }
}
