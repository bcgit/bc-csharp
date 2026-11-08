using System;
using System.IO;

using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Iana;
using Org.BouncyCastle.Asn1.Isara;
using Org.BouncyCastle.Asn1.Nist;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Utilities;
using Org.BouncyCastle.Pqc.Asn1;
using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Crypto.Signers.Xmss
{
    /// <summary>
    /// The XMSS / XMSS^MT (RFC 8391, SP 800-208) half of the key factories: <c>PrivateKeyFactory</c>,
    /// <c>PublicKeyFactory</c>, <c>PrivateKeyInfoFactory</c> and <c>SubjectPublicKeyInfoFactory</c>.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Every method answers null for a key or a key info that is not XMSS / XMSS^MT. A key info that is, but does not
    /// decode, is reported as an <see cref="ArgumentException"/>: bc-java's factories are declared to throw
    /// IOException and report it as that, with the same messages; here the factories report every other malformed key
    /// as an ArgumentException, and these do the same. A failure the decode does not foresee may still come out as an
    /// <see cref="InvalidOperationException"/>, as it does from the key classes.
    /// </para>
    /// <para>
    /// A standard parameter set (one with an RFC 8391 / SP 800-208 parameter-set identifier) has its private key
    /// written under the RFC 9802 algorithm identifier, id-alg-xmss-hashsig / id-alg-xmssmt-hashsig. RFC 9802 defines
    /// the public key only: the private key octets are bc-java's encoding, the four octet parameter-set identifier
    /// followed by BC's raw private key and traversal state, which no implementation outside Bouncy Castle is known to
    /// read. Any other parameter set is written in the legacy
    /// <see cref="PqcObjectIdentifiers"/> form, with <see cref="XmssKeyParams"/> / <see cref="XmssMTKeyParams"/> beside
    /// the algorithm and an <see cref="XmssPrivateKey"/> / <see cref="XmssMTPrivateKey"/> inside. Both forms carry the
    /// key's index and its traversal state, so a key read back signs at the index it was written at.
    /// </para>
    /// </remarks>
    internal static class XmssKeyUtilities
    {
        /// <summary>
        /// The SubjectPublicKeyInfo for an XMSS or XMSS^MT public key, or null if the key is neither.
        /// </summary>
        /// <exception cref="ArgumentException">If the key has no parameter set OID and its n is not the natural
        /// output size of its tree digest, which the legacy form cannot record.</exception>
        internal static SubjectPublicKeyInfo CreateSubjectPublicKeyInfo(AsymmetricKeyParameter publicKey)
        {
            if (publicKey is XmssPublicKeyParameters xmssKey)
            {
                byte[] publicSeed = xmssKey.GetPublicSeed();
                byte[] root = xmssKey.GetRoot();
                byte[] keyEnc = xmssKey.GetEncoded();
                if (keyEnc.Length > publicSeed.Length + root.Length)
                {
                    // RFC 9802: raw RFC 8391 public key, no parameters, no ASN.1 wrapping.
                    AlgorithmIdentifier rawAlgID = new AlgorithmIdentifier(IanaObjectIdentifiers.id_alg_xmss_hashsig);

                    return new SubjectPublicKeyInfo(rawAlgID, keyEnc);
                }

                AlgorithmIdentifier algID = new AlgorithmIdentifier(PqcObjectIdentifiers.xmss,
                    new XmssKeyParams(xmssKey.Parameters.Height, LegacyTreeAlgID(xmssKey.TreeDigest,
                        xmssKey.Parameters.TreeDigestOid, xmssKey.Parameters.TreeDigestSize)));

                return new SubjectPublicKeyInfo(algID, new XmssPublicKey(publicSeed, root));
            }
            if (publicKey is XmssMTPublicKeyParameters xmssMTKey)
            {
                byte[] publicSeed = xmssMTKey.GetPublicSeed();
                byte[] root = xmssMTKey.GetRoot();
                byte[] keyEnc = xmssMTKey.GetEncoded();
                if (keyEnc.Length > publicSeed.Length + root.Length)
                {
                    // RFC 9802: raw RFC 8391 public key, no parameters, no ASN.1 wrapping.
                    AlgorithmIdentifier rawAlgID =
                        new AlgorithmIdentifier(IanaObjectIdentifiers.id_alg_xmssmt_hashsig);

                    return new SubjectPublicKeyInfo(rawAlgID, keyEnc);
                }

                XmssMTParameters parameters = xmssMTKey.Parameters;
                AlgorithmIdentifier algID = new AlgorithmIdentifier(PqcObjectIdentifiers.xmss_mt,
                    new XmssMTKeyParams(parameters.Height, parameters.Layers, LegacyTreeAlgID(xmssMTKey.TreeDigest,
                        parameters.TreeDigestOid, parameters.TreeDigestSize)));

                return new SubjectPublicKeyInfo(algID, new XmssMTPublicKey(publicSeed, root));
            }

            return null;
        }

        /// <summary>
        /// The PrivateKeyInfo for an XMSS or XMSS^MT private key, or null if the key is neither.
        /// </summary>
        /// <remarks>
        /// The index, the maximum index and the traversal state are read under the key's lock, the lock a signature
        /// is taken under, so the three are one position: a key written out while it signs is written either before
        /// the signature or after it.
        /// </remarks>
        /// <exception cref="InvalidOperationException">If the key has been destroyed, or its index and traversal
        /// state disagree.</exception>
        /// <exception cref="ArgumentException">As for <see cref="CreateSubjectPublicKeyInfo"/>.</exception>
        internal static PrivateKeyInfo CreatePrivateKeyInfo(AsymmetricKeyParameter privateKey, Asn1Set attributes)
        {
            if (privateKey is XmssPrivateKeyParameters xmssKey)
            {
                XmssParameters parameters = xmssKey.Parameters;

                if (parameters.ParameterSetOid != 0)
                {
                    // Any standard (RFC 8391 / SP 800-208) parameter set is written under the RFC 9802 OID, matching
                    // the SubjectPublicKeyInfo of the public half, so the two halves of a key pair share one algorithm
                    // OID; the private key body is bc-java's, RFC 9802 defining none. The 4-octet parameter-set OID
                    // ahead of the raw key recovers the full parameter set, n included, which the legacy
                    // XmssKeyParams (height and tree digest OID only) cannot represent for the SP 800-208 sets. A
                    // non-standard tree height has no parameter-set OID and falls through to the legacy form.
                    return RawPrivateKeyInfo(IanaObjectIdentifiers.id_alg_xmss_hashsig, parameters.ParameterSetOid,
                        xmssKey.GetEncoded(), attributes);
                }

                AlgorithmIdentifier algID = new AlgorithmIdentifier(PqcObjectIdentifiers.xmss,
                    new XmssKeyParams(parameters.Height, LegacyTreeAlgID(xmssKey.TreeDigest, parameters.TreeDigestOid,
                        parameters.TreeDigestSize)));

                return new PrivateKeyInfo(algID, XmssCreateKeyStructure(xmssKey), attributes);
            }
            if (privateKey is XmssMTPrivateKeyParameters xmssMTKey)
            {
                XmssMTParameters parameters = xmssMTKey.Parameters;

                if (parameters.ParameterSetOid != 0)
                {
                    // as in the XMSS branch above
                    return RawPrivateKeyInfo(IanaObjectIdentifiers.id_alg_xmssmt_hashsig, parameters.ParameterSetOid,
                        xmssMTKey.GetEncoded(), attributes);
                }

                AlgorithmIdentifier algID = new AlgorithmIdentifier(PqcObjectIdentifiers.xmss_mt,
                    new XmssMTKeyParams(parameters.Height, parameters.Layers, LegacyTreeAlgID(xmssMTKey.TreeDigest,
                        parameters.TreeDigestOid, parameters.TreeDigestSize)));

                return new PrivateKeyInfo(algID, XmssMTCreateKeyStructure(xmssMTKey), attributes);
            }

            return null;
        }

        /// <summary>
        /// The public key parameters for an XMSS or XMSS^MT SubjectPublicKeyInfo, or null if its algorithm is
        /// neither.
        /// </summary>
        /// <exception cref="ArgumentException">If the key info does not decode to a key.</exception>
        internal static AsymmetricKeyParameter CreatePublicKey(SubjectPublicKeyInfo keyInfo)
        {
            DerObjectIdentifier algOid = keyInfo.Algorithm.Algorithm;

            if (algOid.Equals(PqcObjectIdentifiers.xmss_mt)
                || algOid.Equals(IsaraObjectIdentifiers.id_alg_xmssmt)
                || algOid.Equals(IanaObjectIdentifiers.id_alg_xmssmt_hashsig))
            {
                // every step the encoding drives sits inside the try, the GetInstance() calls included
                try
                {
                    XmssMTKeyParams keyParams = XmssMTKeyParams.GetInstance(keyInfo.Algorithm.Parameters);

                    if (keyParams != null)
                    {
                        DerObjectIdentifier treeDigest = keyParams.TreeDigest.Algorithm;

                        XmssPublicKey xmssMTPublicKey = XmssPublicKey.GetInstance(
                            Required(keyInfo.ParsePublicKey()));

                        return new XmssMTPublicKeyParameters.Builder(new XmssMTParameters(keyParams.Height,
                                keyParams.Layers, XmssEngine.GetDigest(treeDigest)))
                            .WithPublicSeed(xmssMTPublicKey.GetPublicSeed())
                            .WithRoot(xmssMTPublicKey.GetRoot()).Build();
                    }

                    // RFC 9802 carries the raw RFC 8391 key; the legacy draft form wrapped it in an OCTET STRING.
                    byte[] keyEnc = RawPublicKey(keyInfo);

                    if (keyEnc.Length < 4)
                        throw new IOException("XMSS^MT public key data too short");

                    int oid = (int)Pack.BE_To_UInt32(keyEnc, 0);
                    XmssMTParameters parameters = XmssMTParameters.LookupByOid(oid);
                    if (parameters == null)
                        throw new IOException("unknown XMSS^MT public key OID: " + oid);

                    // the builder also takes root || SEED without the OID, which this form never is: a key cut
                    // short by the OID's four bytes would otherwise read as one whose root starts with them
                    RequireRawPublicKeySize(keyEnc, parameters.TreeDigestSize);

                    return new XmssMTPublicKeyParameters.Builder(parameters).WithPublicKey(keyEnc).Build();
                }
                catch (IOException e)
                {
                    throw new ArgumentException(e.Message, e);
                }
                catch (Exception e) when (e is ArgumentException || e is ArithmeticException)
                {
                    // the height and layer count are whatever the key's parameters said they were; one too wide for
                    // the int it is read into is an ArithmeticException from DerInteger.IntValueExact
                    throw new ArgumentException("malformed XMSS^MT public key: " + e.Message, e);
                }
            }

            if (algOid.Equals(PqcObjectIdentifiers.xmss)
                || algOid.Equals(IsaraObjectIdentifiers.id_alg_xmss)
                || algOid.Equals(IanaObjectIdentifiers.id_alg_xmss_hashsig))
            {
                // as in the XMSS^MT branch above: the whole decode is inside the try
                try
                {
                    XmssKeyParams keyParams = XmssKeyParams.GetInstance(keyInfo.Algorithm.Parameters);

                    if (keyParams != null)
                    {
                        DerObjectIdentifier treeDigest = keyParams.TreeDigest.Algorithm;

                        XmssPublicKey xmssPublicKey = XmssPublicKey.GetInstance(Required(keyInfo.ParsePublicKey()));

                        return new XmssPublicKeyParameters.Builder(new XmssParameters(keyParams.Height,
                                XmssEngine.GetDigest(treeDigest)))
                            .WithPublicSeed(xmssPublicKey.GetPublicSeed())
                            .WithRoot(xmssPublicKey.GetRoot()).Build();
                    }

                    // RFC 9802 carries the raw RFC 8391 key; the legacy draft form wrapped it in an OCTET STRING.
                    byte[] keyEnc = RawPublicKey(keyInfo);

                    if (keyEnc.Length < 4)
                        throw new IOException("XMSS public key data too short");

                    int oid = (int)Pack.BE_To_UInt32(keyEnc, 0);
                    XmssParameters parameters = XmssParameters.LookupByOid(oid);
                    if (parameters == null)
                        throw new IOException("unknown XMSS public key OID: " + oid);

                    // the builder also takes root || SEED without the OID, which this form never is: a key cut
                    // short by the OID's four bytes would otherwise read as one whose root starts with them
                    RequireRawPublicKeySize(keyEnc, parameters.TreeDigestSize);

                    return new XmssPublicKeyParameters.Builder(parameters).WithPublicKey(keyEnc).Build();
                }
                catch (IOException e)
                {
                    throw new ArgumentException(e.Message, e);
                }
                catch (Exception e) when (e is ArgumentException || e is ArithmeticException)
                {
                    // the height is whatever the key's parameters said it was
                    throw new ArgumentException("malformed XMSS public key: " + e.Message, e);
                }
            }

            return null;
        }

        /// <summary>
        /// The private key parameters for an XMSS or XMSS^MT PrivateKeyInfo, or null if its algorithm is neither.
        /// </summary>
        /// <remarks>The key comes back at the index the encoding carries, with the traversal state it carries.
        /// </remarks>
        /// <exception cref="ArgumentException">If the key info does not decode to a key.</exception>
        internal static AsymmetricKeyParameter CreatePrivateKey(PrivateKeyInfo keyInfo)
        {
            DerObjectIdentifier algOid = keyInfo.PrivateKeyAlgorithm.Algorithm;

            if (algOid.Equals(PqcObjectIdentifiers.xmss)
                || algOid.Equals(IsaraObjectIdentifiers.id_alg_xmss))
            {
                // as in CreatePublicKey: the GetInstance() calls belong inside the try, and so does the parameters
                // lookup that follows them - this OID form must carry XmssKeyParams
                byte[] secretKeySeed = null, secretKeyPrf = null;
                XmssPrivateKeyParameters.Builder keyBuilder = null;
                try
                {
                    XmssKeyParams keyParams = XmssKeyParams.GetInstance(keyInfo.PrivateKeyAlgorithm.Parameters);
                    if (keyParams == null)
                        throw new IOException("no parameters found in XMSS private key");

                    DerObjectIdentifier treeDigest = keyParams.TreeDigest.Algorithm;

                    XmssPrivateKey xmssPrivateKey = XmssPrivateKey.GetInstance(Required(keyInfo.ParsePrivateKey()));

                    secretKeySeed = xmssPrivateKey.GetSecretKeySeed();
                    secretKeyPrf = xmssPrivateKey.GetSecretKeyPrf();

                    keyBuilder = new XmssPrivateKeyParameters
                        .Builder(new XmssParameters(keyParams.Height, XmssEngine.GetDigest(treeDigest)))
                        .WithIndex(xmssPrivateKey.Index)
                        .WithSecretKeySeed(secretKeySeed)
                        .WithSecretKeyPrf(secretKeyPrf)
                        .WithPublicSeed(xmssPrivateKey.GetPublicSeed())
                        .WithRoot(xmssPrivateKey.GetRoot());

                    // whatever the version says: XmssPrivateKey accepts the [0] field at version 0 too, and a shard
                    // read back without its bound would be widened to the whole tree
                    if (xmssPrivateKey.MaxIndex >= 0)
                    {
                        keyBuilder.WithMaxIndex(xmssPrivateKey.MaxIndex);
                    }

                    byte[] bdsState = xmssPrivateKey.GetBdsState();
                    if (bdsState != null)
                    {
                        Bds bds = XmssEngine.GetBdsFromEncoding(bdsState, xmssPrivateKey.GetPublicSeed());
                        keyBuilder.WithBdsState(bds.WithWotsDigest(treeDigest));
                    }

                    return keyBuilder.Build();
                }
                catch (IOException e)
                {
                    throw new ArgumentException(e.Message, e);
                }
                catch (Exception e)
                    when (e is ArgumentException || e is InvalidOperationException || e is ArithmeticException)
                {
                    // the height is whatever the key's parameters said it was, and the stored BDS state is whatever
                    // the key carried: one that does not match its own tree is refused, as is a key missing a seed
                    throw new ArgumentException("malformed XMSS private key: " + e.Message, e);
                }
                finally
                {
                    Wipe(secretKeySeed);
                    Wipe(secretKeyPrf);
                    keyBuilder?.ClearSecrets();
                }
            }
            if (algOid.Equals(PqcObjectIdentifiers.xmss_mt)
                || algOid.Equals(IsaraObjectIdentifiers.id_alg_xmssmt))
            {
                // as in the XMSS branch above
                byte[] secretKeySeed = null, secretKeyPrf = null;
                XmssMTPrivateKeyParameters.Builder keyBuilder = null;
                try
                {
                    XmssMTKeyParams keyParams = XmssMTKeyParams.GetInstance(keyInfo.PrivateKeyAlgorithm.Parameters);
                    if (keyParams == null)
                        throw new IOException("no parameters found in XMSS^MT private key");

                    DerObjectIdentifier treeDigest = keyParams.TreeDigest.Algorithm;

                    XmssMTPrivateKey xmssMTPrivateKey =
                        XmssMTPrivateKey.GetInstance(Required(keyInfo.ParsePrivateKey()));

                    secretKeySeed = xmssMTPrivateKey.GetSecretKeySeed();
                    secretKeyPrf = xmssMTPrivateKey.GetSecretKeyPrf();

                    keyBuilder = new XmssMTPrivateKeyParameters
                        .Builder(new XmssMTParameters(keyParams.Height, keyParams.Layers,
                            XmssEngine.GetDigest(treeDigest)))
                        .WithIndex(xmssMTPrivateKey.Index)
                        .WithSecretKeySeed(secretKeySeed)
                        .WithSecretKeyPrf(secretKeyPrf)
                        .WithPublicSeed(xmssMTPrivateKey.GetPublicSeed())
                        .WithRoot(xmssMTPrivateKey.GetRoot());

                    // as in the XMSS branch: the [0] field is honoured at any version
                    if (xmssMTPrivateKey.MaxIndex >= 0)
                    {
                        keyBuilder.WithMaxIndex(xmssMTPrivateKey.MaxIndex);
                    }

                    byte[] bdsState = xmssMTPrivateKey.GetBdsState();
                    if (bdsState != null)
                    {
                        BdsStateMap bdsStateMap = XmssEngine.GetBdsStateMapFromEncoding(bdsState,
                            xmssMTPrivateKey.GetPublicSeed());
                        keyBuilder.WithBdsState(bdsStateMap.WithWotsDigest(treeDigest));
                    }

                    return keyBuilder.Build();
                }
                catch (IOException e)
                {
                    throw new ArgumentException(e.Message, e);
                }
                catch (Exception e)
                    when (e is ArgumentException || e is InvalidOperationException || e is ArithmeticException)
                {
                    // as in the XMSS branch: the height, the layer count and the per-layer states are the key's own
                    throw new ArgumentException("malformed XMSS^MT private key: " + e.Message, e);
                }
                finally
                {
                    Wipe(secretKeySeed);
                    Wipe(secretKeyPrf);
                    keyBuilder?.ClearSecrets();
                }
            }
            if (algOid.Equals(IanaObjectIdentifiers.id_alg_xmss_hashsig))
            {
                // bc-java's private key encoding under the RFC 9802 OID, used for the standard sets: the octets are
                // the 4-octet parameter-set OID followed by the raw private key encoding, recovered through
                // LookupByOid so the full parameter set (n included) is restored
                byte[] keyEnc = null, rawKey = null;
                XmssPrivateKeyParameters.Builder keyBuilder = null;
                try
                {
                    keyEnc = Asn1OctetString.GetInstance(Required(keyInfo.ParsePrivateKey())).GetOctets();
                    if (keyEnc.Length < 4)
                        throw new IOException("XMSS private key data too short");

                    int paramSet = (int)Pack.BE_To_UInt32(keyEnc, 0);
                    XmssParameters xmssParams = XmssParameters.LookupByOid(paramSet);
                    if (xmssParams == null)
                        throw new IOException("unknown XMSS private key OID: " + paramSet);

                    rawKey = Arrays.CopyOfRange(keyEnc, 4, keyEnc.Length);

                    keyBuilder = new XmssPrivateKeyParameters.Builder(xmssParams).WithPrivateKey(rawKey);
                    return keyBuilder.Build();
                }
                catch (IOException e)
                {
                    throw new ArgumentException(e.Message, e);
                }
                catch (ArgumentException e)
                {
                    throw new ArgumentException("malformed XMSS private key: " + e.Message, e);
                }
                finally
                {
                    Wipe(keyEnc);
                    Wipe(rawKey);
                    keyBuilder?.ClearSecrets();
                }
            }
            if (algOid.Equals(IanaObjectIdentifiers.id_alg_xmssmt_hashsig))
            {
                byte[] keyEnc = null, rawKey = null;
                XmssMTPrivateKeyParameters.Builder keyBuilder = null;
                try
                {
                    keyEnc = Asn1OctetString.GetInstance(Required(keyInfo.ParsePrivateKey())).GetOctets();
                    if (keyEnc.Length < 4)
                        throw new IOException("XMSS^MT private key data too short");

                    int paramSet = (int)Pack.BE_To_UInt32(keyEnc, 0);
                    XmssMTParameters xmssMTParams = XmssMTParameters.LookupByOid(paramSet);
                    if (xmssMTParams == null)
                        throw new IOException("unknown XMSS^MT private key OID: " + paramSet);

                    rawKey = Arrays.CopyOfRange(keyEnc, 4, keyEnc.Length);

                    keyBuilder = new XmssMTPrivateKeyParameters.Builder(xmssMTParams).WithPrivateKey(rawKey);
                    return keyBuilder.Build();
                }
                catch (IOException e)
                {
                    throw new ArgumentException(e.Message, e);
                }
                catch (ArgumentException e)
                {
                    throw new ArgumentException("malformed XMSS^MT private key: " + e.Message, e);
                }
                finally
                {
                    Wipe(keyEnc);
                    Wipe(rawKey);
                    keyBuilder?.ClearSecrets();
                }
            }

            return null;
        }

        /// <summary>
        /// The PrivateKeyInfo under the RFC 9802 OID, in bc-java's encoding: the 4-octet parameter-set OID followed by
        /// the raw key, as an OCTET STRING.
        /// </summary>
        private static PrivateKeyInfo RawPrivateKeyInfo(DerObjectIdentifier algOid, int parameterSetOid,
            byte[] rawKey, Asn1Set attributes)
        {
            byte[] keyEnc = Arrays.Concatenate(Pack.UInt32_To_BE((uint)parameterSetOid), rawKey);
            try
            {
                // the PrivateKeyInfo holds the DER encoding of this OCTET STRING, a copy of its own
                return new PrivateKeyInfo(new AlgorithmIdentifier(algOid), new DerOctetString(keyEnc), attributes);
            }
            finally
            {
                Wipe(keyEnc);
                Wipe(rawKey);
            }
        }

        private static void RequireRawPublicKeySize(byte[] keyEnc, int n)
        {
            if (keyEnc.Length != 4 + 2 * n)
                throw new ArgumentException("public key has wrong size");
        }

        /// <summary>A decoded body that is not there at all is a malformed key, not a null to dereference.</summary>
        private static Asn1Object Required(Asn1Object obj) =>
            obj ?? throw new ArgumentException("missing key data");

        private static byte[] RawPublicKey(SubjectPublicKeyInfo keyInfo)
        {
            byte[] keyEnc = keyInfo.PublicKey.GetOctets();

            // a key that is well-formed DER for an OCTET STRING is the legacy wrapping of the raw key
            if (!IsRaw(keyEnc) && keyEnc[0] == Asn1Tags.OctetString)
                return Asn1OctetString.GetInstance(keyEnc).GetOctets();

            return keyEnc;
        }

        /// <summary>
        /// Whether <paramref name="data"/> is not a single DER tag-length-value whose length covers the rest of it,
        /// read as bc-java's <c>Utils.isRaw</c> reads it.
        /// </summary>
        private static bool IsRaw(byte[] data)
        {
            int pos = 0;

            Read(data, ref pos);                    // tag
            int length = Read(data, ref pos);
            if (length >= 0 && length != (length & 0x7f))
            {
                int count = length & 0x7f;
                // more length octets than an int holds cannot describe the rest of the data
                if (count > 4)
                    return true;

                length = 0;
                while (count-- != 0)
                {
                    length = (length << 8) + Read(data, ref pos);
                }
            }

            return length != data.Length - pos;
        }

        /// <summary>The next byte, or -1 at the end of the data, which does not move past it.</summary>
        private static int Read(byte[] data, ref int pos) => (pos < data.Length) ? data[pos++] : -1;

        /// <summary>
        /// The ASN.1 structure an XMSS private key is written as in the legacy form, from the key's own fields, under
        /// the key's lock: the index, the maximum index and the traversal state are three records of one position,
        /// and reading them in three unsynchronized steps would let a signature land between two of them.
        /// </summary>
        private static XmssPrivateKey XmssCreateKeyStructure(XmssPrivateKeyParameters keyParams)
        {
            int totalHeight = keyParams.Parameters.Height;

            lock (keyParams)
            {
                Bds bdsState = keyParams.GetBdsState();
                int index = bdsState.Index;

                if (!XmssEngine.IsStoredIndexValid(totalHeight, index))
                    throw new ArgumentException("index out of bounds");

                byte[] publicSeed = keyParams.GetPublicSeed();
                byte[] bdsStateBinary = EncodeState(() => XmssEngine.GetEncodedBdsState(bdsState, publicSeed),
                    "error encoding BDS state");
                int maxIndex = bdsState.MaxIndex;

                byte[] secretKeySeed = keyParams.GetSecretKeySeed();
                byte[] secretKeyPrf = null;
                try
                {
                    secretKeyPrf = keyParams.GetSecretKeyPrf();

                    if (maxIndex != (1 << totalHeight) - 1)
                    {
                        return new XmssPrivateKey(index, secretKeySeed, secretKeyPrf, publicSeed, keyParams.GetRoot(),
                            bdsStateBinary, maxIndex);
                    }

                    return new XmssPrivateKey(index, secretKeySeed, secretKeyPrf, publicSeed, keyParams.GetRoot(),
                        bdsStateBinary);
                }
                finally
                {
                    Wipe(secretKeySeed);
                    Wipe(secretKeyPrf);
                }
            }
        }

        /// <summary>
        /// As <see cref="XmssCreateKeyStructure"/>, for XMSS^MT. The index is taken from the key and carried as a
        /// long, so nothing narrows it: the raw encoding writes it into ceil(height / 8) bytes, too few for the
        /// exhausted index 2^height at a height that is a multiple of eight, and this form has no such limit.
        /// </summary>
        /// <remarks>
        /// The index and the per-layer states are two records of one position, and a key whose two disagree is
        /// refused on the way back in, so it is refused here rather than written out.
        /// </remarks>
        private static XmssMTPrivateKey XmssMTCreateKeyStructure(XmssMTPrivateKeyParameters keyParams)
        {
            XmssMTParameters parameters = keyParams.Parameters;
            int totalHeight = parameters.Height;

            lock (keyParams)
            {
                BdsStateMap bdsState = keyParams.GetBdsState();
                long index = keyParams.Index;

                if (!XmssEngine.IsStoredIndexValid(totalHeight, index))
                    throw new ArgumentException("index out of bounds");

                // the index check reads the secret seed, which a destroyed key no longer holds
                if (keyParams.IsDestroyed)
                    throw new InvalidOperationException("key destroyed");

                keyParams.ValidateIndex();

                byte[] publicSeed = keyParams.GetPublicSeed();
                byte[] bdsStateBinary = EncodeState(() => XmssEngine.GetEncodedBdsState(bdsState, publicSeed),
                    "error encoding BDS state map");
                long maxIndex = bdsState.MaxIndex;

                byte[] secretKeySeed = keyParams.GetSecretKeySeed();
                byte[] secretKeyPrf = null;
                try
                {
                    secretKeyPrf = keyParams.GetSecretKeyPrf();

                    if (maxIndex != (1L << totalHeight) - 1)
                    {
                        return new XmssMTPrivateKey(index, secretKeySeed, secretKeyPrf, publicSeed,
                            keyParams.GetRoot(), bdsStateBinary, maxIndex);
                    }

                    return new XmssMTPrivateKey(index, secretKeySeed, secretKeyPrf, publicSeed, keyParams.GetRoot(),
                        bdsStateBinary);
                }
                finally
                {
                    Wipe(secretKeySeed);
                    Wipe(secretKeyPrf);
                }
            }
        }

        private static void Wipe(byte[] buf)
        {
            if (buf != null)
            {
                Arrays.ZeroMemory(buf);
            }
        }

        /// <summary>A traversal state the codec cannot write is a key in a state it should not be in.</summary>
        private static byte[] EncodeState(Func<byte[]> encode, string message)
        {
            try
            {
                return encode();
            }
            catch (IOException e)
            {
                throw new InvalidOperationException(message, e);
            }
        }

        /// <summary>
        /// The tree digest of the legacy key parameters, which name the digest and nothing else: a key is read back
        /// with n equal to the digest's natural output size, so a key whose n differs is refused here, at write
        /// time, rather than written in a form that cannot be read back.
        /// </summary>
        /// <exception cref="ArgumentException">If the tree digest is not one the legacy form can name, or n is not
        /// its natural output size.</exception>
        private static AlgorithmIdentifier LegacyTreeAlgID(string treeDigest, DerObjectIdentifier treeDigestOid,
            int n)
        {
            AlgorithmIdentifier algID = LookupTreeAlgID(treeDigest);

            if (n != XmssDigestUtilities.GetDigestSize(treeDigestOid))
            {
                throw new ArgumentException("XMSS tree digest " + treeDigest + " with n = " + n
                    + " has no parameter set OID and cannot be written in the legacy key encoding");
            }
            return algID;
        }

        private static AlgorithmIdentifier LookupTreeAlgID(string treeDigest)
        {
            if (treeDigest.Equals("SHA-256"))
                return new AlgorithmIdentifier(NistObjectIdentifiers.IdSha256);
            if (treeDigest.Equals("SHA-512"))
                return new AlgorithmIdentifier(NistObjectIdentifiers.IdSha512);
            if (treeDigest.Equals("SHAKE128"))
                return new AlgorithmIdentifier(NistObjectIdentifiers.IdShake128);
            if (treeDigest.Equals("SHAKE256"))
                return new AlgorithmIdentifier(NistObjectIdentifiers.IdShake256);

            throw new ArgumentException("unknown tree digest: " + treeDigest);
        }
    }
}
