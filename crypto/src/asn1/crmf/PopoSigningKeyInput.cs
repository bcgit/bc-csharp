using System;

using Org.BouncyCastle.Asn1.X509;

namespace Org.BouncyCastle.Asn1.Crmf
{
    /// <summary>The POPOSigningKeyInput structure of RFC 4211.</summary>
    public class PopoSigningKeyInput
        : Asn1Encodable
    {
        /// <summary>Return an <see cref="PopoSigningKeyInput"/> from the given object.</summary>
        /// <param name="obj">
        /// An <see cref="PopoSigningKeyInput"/>, an object from which one can be constructed, or null.
        /// </param>
        /// <returns>The <see cref="PopoSigningKeyInput"/>, or null if <paramref name="obj"/> is null.</returns>
        public static PopoSigningKeyInput GetInstance(object obj)
        {
            if (obj == null)
                return null;
            if (obj is PopoSigningKeyInput popoSigningKeyInput)
                return popoSigningKeyInput;
            return new PopoSigningKeyInput(Asn1Sequence.GetInstance(obj));
        }

        /// <summary>Return an <see cref="PopoSigningKeyInput"/> from a tagged object.</summary>
        /// <param name="taggedObject">The tagged object.</param>
        /// <param name="declaredExplicit">true if the tagging is explicit, false if implicit.</param>
        /// <returns>The <see cref="PopoSigningKeyInput"/>.</returns>
        public static PopoSigningKeyInput GetInstance(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new PopoSigningKeyInput(Asn1Sequence.GetInstance(taggedObject, declaredExplicit));

        /// <summary>Return an <see cref="PopoSigningKeyInput"/> from a tagged object.</summary>
        /// <param name="taggedObject">The tagged object.</param>
        /// <param name="declaredExplicit">true if the tagging is explicit, false if implicit.</param>
        /// <returns>The <see cref="PopoSigningKeyInput"/>.</returns>
        public static PopoSigningKeyInput GetTagged(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new PopoSigningKeyInput(Asn1Sequence.GetTagged(taggedObject, declaredExplicit));

        private readonly AuthInfo m_authInfo;
        private readonly SubjectPublicKeyInfo m_publicKey;

        private PopoSigningKeyInput(Asn1Sequence seq)
        {
            int count = seq.Count, pos = 0;
            if (count != 2)
                throw new ArgumentException("Bad sequence size: " + count, nameof(seq));

            m_authInfo = Asn1Utilities.Read(seq, ref pos, AuthInfo.GetInstance);
            m_publicKey = Asn1Utilities.Read(seq, ref pos, SubjectPublicKeyInfo.GetInstance);

            if (pos != count)
                throw new ArgumentException("Unexpected elements in sequence", nameof(seq));
        }

        /// <summary>Create a new <see cref="PopoSigningKeyInput"/>.</summary>
        /// <param name="authInfo">The auth info.</param>
        /// <param name="publicKey">The public key.</param>
        public PopoSigningKeyInput(AuthInfo authInfo, SubjectPublicKeyInfo publicKey)
        {
            m_authInfo = authInfo ?? throw new ArgumentNullException(nameof(authInfo));
            m_publicKey = publicKey ?? throw new ArgumentNullException(nameof(publicKey));
        }

        /** Creates a new PopoSigningKeyInput with sender name as authInfo. */
        public PopoSigningKeyInput(GeneralName sender, SubjectPublicKeyInfo spki)
        {
            m_authInfo = new AuthInfo(sender);
            m_publicKey = spki ?? throw new ArgumentNullException(nameof(spki));
        }

        /** Creates a new PopoSigningKeyInput using password-based MAC. */
        public PopoSigningKeyInput(PKMacValue pkmac, SubjectPublicKeyInfo spki)
        {
            m_authInfo = new AuthInfo(pkmac);
            m_publicKey = spki ?? throw new ArgumentNullException(nameof(spki));
        }

        /// <summary>Gets the auth info value.</summary>
        public virtual AuthInfo AuthInfoValue => m_authInfo;

        /** Returns the sender field, or null if authInfo is publicKeyMac */
        public virtual GeneralName Sender => m_authInfo.Sender;

        /** Returns the publicKeyMac field, or null if authInfo is sender */
        public virtual PKMacValue PublicKeyMac => m_authInfo.PublicKeyMac;

        /// <summary>Gets the public key.</summary>
        public virtual SubjectPublicKeyInfo PublicKey => m_publicKey;

        /**
         * <pre>
         * PopoSigningKeyInput ::= SEQUENCE {
         *        authInfo             CHOICE {
         *                                 sender              [0] GeneralName,
         *                                 -- used only if an authenticated identity has been
         *                                 -- established for the sender (e.g., a DN from a
         *                                 -- previously-issued and currently-valid certificate
         *                                 publicKeyMac        PKMacValue },
         *                                 -- used if no authenticated GeneralName currently exists for
         *                                 -- the sender; publicKeyMac contains a password-based MAC
         *                                 -- on the DER-encoded value of publicKey
         *        publicKey           SubjectPublicKeyInfo }  -- from CertTemplate
         * </pre>
         * @return a basic ASN.1 object representation.
         */
        public override Asn1Object ToAsn1Object() => new DerSequence(m_authInfo, m_publicKey);

        /// <summary>
        /// The authentication information choice of the POPOSigningKeyInput structure of RFC 4211: a sender or a public
        /// key MAC.
        /// </summary>
        public sealed class AuthInfo
            : Asn1Encodable, IAsn1Choice
        {
            /// <summary>Return an <see cref="AuthInfo"/> from the given object.</summary>
            /// <param name="obj">
            /// An <see cref="AuthInfo"/>, an object from which one can be constructed, or null.
            /// </param>
            /// <returns>The <see cref="AuthInfo"/>, or null if <paramref name="obj"/> is null.</returns>
            public static AuthInfo GetInstance(object obj) => Asn1Utilities.GetInstanceChoice(obj, GetOptional);

            /// <summary>Return an <see cref="AuthInfo"/> from a tagged object.</summary>
            /// <param name="taggedObject">The tagged object.</param>
            /// <param name="declaredExplicit">true if the tagging is explicit, false if implicit.</param>
            /// <returns>The <see cref="AuthInfo"/>.</returns>
            public static AuthInfo GetInstance(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
                Asn1Utilities.GetInstanceChoice(taggedObject, declaredExplicit, GetInstance);

            /// <summary>Return an <see cref="AuthInfo"/> from the given element, if it is one.</summary>
            /// <param name="element">The element.</param>
            /// <returns>The <see cref="AuthInfo"/>, or null if <paramref name="element"/> is null.</returns>
            public static AuthInfo GetOptional(Asn1Encodable element)
            {
                if (element == null)
                    throw new ArgumentNullException(nameof(element));

                if (element is AuthInfo authInfo)
                    return authInfo;

                Asn1TaggedObject sender = Asn1TaggedObject.GetContextOptional(element, 0);
                if (sender != null)
                    return new AuthInfo(GeneralName.GetTagged(sender, true));

                PKMacValue publicKeyMac = PKMacValue.GetOptional(element);
                if (publicKeyMac != null)
                    return new AuthInfo(publicKeyMac);

                return null;
            }

            /// <summary>Return an <see cref="AuthInfo"/> from a tagged object.</summary>
            /// <param name="taggedObject">The tagged object.</param>
            /// <param name="declaredExplicit">true if the tagging is explicit, false if implicit.</param>
            /// <returns>The <see cref="AuthInfo"/>.</returns>
            public static AuthInfo GetTagged(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
                Asn1Utilities.GetTaggedChoice(taggedObject, declaredExplicit, GetInstance);

            private readonly GeneralName m_sender;
            private readonly PKMacValue m_publicKeyMac;

            /// <summary>Create a new <see cref="AuthInfo"/>.</summary>
            /// <param name="sender">The sender.</param>
            public AuthInfo(GeneralName sender)
            {
                m_sender = sender ?? throw new ArgumentNullException(nameof(sender));
                m_publicKeyMac = null;
            }

            /// <summary>Create a new <see cref="AuthInfo"/>.</summary>
            /// <param name="publicKeyMac">The public key mac.</param>
            public AuthInfo(PKMacValue publicKeyMac)
            {
                m_sender = null;
                m_publicKeyMac = publicKeyMac ?? throw new ArgumentNullException(nameof(publicKeyMac));
            }

            /// <summary>Gets the public key mac.</summary>
            public PKMacValue PublicKeyMac => m_publicKeyMac;

            /// <summary>Gets the sender.</summary>
            public GeneralName Sender => m_sender;

            /// <inheritdoc/>
            public override Asn1Object ToAsn1Object()
            {
                if (m_sender != null)
                {
                    return new DerTaggedObject(true, 0, m_sender);
                }
                else if (m_publicKeyMac != null)
                {
                    return m_publicKeyMac.ToAsn1Object();
                }
                else
                {
                    throw new InvalidOperationException();
                }
            }
        }
    }
}
