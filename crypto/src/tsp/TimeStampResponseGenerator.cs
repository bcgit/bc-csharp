using System;
using System.Collections.Generic;
using System.IO;

using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Cmp;
using Org.BouncyCastle.Asn1.Cms;
using Org.BouncyCastle.Asn1.Tsp;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Math;

namespace Org.BouncyCastle.Tsp
{
    /// <summary>Generator for RFC 3161 Time Stamp Responses.</summary>
    /// <remarks>
    /// The generator checks each request against the accepted algorithms, policies and extensions it was configured
    /// with. A request that fails the checks, or a missing time source, produces a rejection response rather than an
    /// exception.
    /// </remarks>
    public class TimeStampResponseGenerator
    {
        private PkiStatus status;

        private Asn1EncodableVector statusStrings;

        private int failInfo;
        private TimeStampTokenGenerator tokenGenerator;
        private IList<string> acceptedAlgorithms;
        private IList<string> acceptedPolicies;
        private IList<string> acceptedExtensions;

        /// <summary>Create a generator that accepts any policy and extension.</summary>
        /// <param name="tokenGenerator">The generator used to create the time-stamp tokens.</param>
        /// <param name="acceptedAlgorithms">The object identifiers of the accepted digest algorithms.</param>
        public TimeStampResponseGenerator(
            TimeStampTokenGenerator tokenGenerator,
            IList<string> acceptedAlgorithms)
            : this(tokenGenerator, acceptedAlgorithms, null, null)
        {
        }

        /// <summary>Create a generator that accepts any extension.</summary>
        /// <param name="tokenGenerator">The generator used to create the time-stamp tokens.</param>
        /// <param name="acceptedAlgorithms">The object identifiers of the accepted digest algorithms.</param>
        /// <param name="acceptedPolicy">
        /// The object identifiers of the accepted policies, or null to accept any.
        /// </param>
        public TimeStampResponseGenerator(
            TimeStampTokenGenerator tokenGenerator,
            IList<string> acceptedAlgorithms,
            IList<string> acceptedPolicy)
            : this(tokenGenerator, acceptedAlgorithms, acceptedPolicy, null)
        {
        }

        /// <summary>Create a generator.</summary>
        /// <param name="tokenGenerator">The generator used to create the time-stamp tokens.</param>
        /// <param name="acceptedAlgorithms">The object identifiers of the accepted digest algorithms.</param>
        /// <param name="acceptedPolicies">
        /// The object identifiers of the accepted policies, or null to accept any.
        /// </param>
        /// <param name="acceptedExtensions">
        /// The object identifiers of the accepted request extensions, or null to accept any.
        /// </param>
        public TimeStampResponseGenerator(
            TimeStampTokenGenerator tokenGenerator,
            IList<string> acceptedAlgorithms,
            IList<string> acceptedPolicies,
            IList<string> acceptedExtensions)
        {
            this.tokenGenerator = tokenGenerator;
            this.acceptedAlgorithms = acceptedAlgorithms;
            this.acceptedPolicies = acceptedPolicies;
            this.acceptedExtensions = acceptedExtensions;

            statusStrings = new Asn1EncodableVector();
        }

        private void AddStatusString(string statusString)
        {
            statusStrings.Add(new DerUtf8String(statusString));
        }

        private void SetFailInfoField(int field)
        {
            failInfo |= field;
        }

        private PkiStatusInfo GetPkiStatusInfo()
        {
            Asn1EncodableVector v = new Asn1EncodableVector(3);
            v.Add(DerInteger.ValueOf((int)status));

            if (statusStrings.Count > 0)
            {
                v.Add(new PkiFreeText(new DerSequence(statusStrings)));
            }

            if (failInfo != 0)
            {
                v.Add(new FailInfo(failInfo));
            }

            return PkiStatusInfo.GetInstance(new DerSequence(v));
        }

        /// <summary>Return an appropriate TimeStampResponse.</summary>
        /// <remarks>
        /// If genTime is null a timeNotAvailable error response will be returned. If the request is not acceptable a
        /// rejection response carrying the failure information will be returned.
        /// </remarks>
        /// <param name="request">The request this response is for.</param>
        /// <param name="serialNumber">The serial number for the response token.</param>
        /// <param name="genTime">The generation time for the response token.</param>
        /// <returns>The <see cref="TimeStampResponse"/>.</returns>
        /// <exception cref="TspException">The token or response could not be created.</exception>
        public TimeStampResponse Generate(TimeStampRequest request, BigInteger serialNumber, DateTime? genTime)
        {
            TimeStampResp resp;

            try
            {
                if (genTime == null)
                    throw new TspValidationException("The time source is not available.",
                        PkiFailureInfo.TimeNotAvailable);

                request.Validate(acceptedAlgorithms, acceptedPolicies, acceptedExtensions);

                this.status = PkiStatus.Granted;
                this.AddStatusString("Operation Okay");

                PkiStatusInfo pkiStatusInfo = GetPkiStatusInfo();

                ContentInfo tstTokenContentInfo;
                try
                {
                    TimeStampToken token = tokenGenerator.Generate(request, serialNumber, genTime.Value);

                    tstTokenContentInfo = token.ToCmsSignedData().ContentInfo;
                }
                catch (IOException e)
                {
                    throw new TspException("Timestamp token received cannot be converted to ContentInfo", e);
                }

                resp = new TimeStampResp(pkiStatusInfo, tstTokenContentInfo);
            }
            catch (TspValidationException e)
            {
                status = PkiStatus.Rejection;

                this.SetFailInfoField(e.FailureCode);
                this.AddStatusString(e.Message);

                PkiStatusInfo pkiStatusInfo = GetPkiStatusInfo();

                resp = new TimeStampResp(pkiStatusInfo, null);
            }

            try
            {
                return new TimeStampResponse(resp);
            }
            catch (IOException e)
            {
                throw new TspException("created badly formatted response!", e);
            }
        }

        /// <summary>Return a granted TimeStampResponse with a caller-supplied status string.</summary>
        /// <remarks>
        /// As for <see cref="Generate"/>, a null genTime or an unacceptable request results in a rejection response.
        /// </remarks>
        /// <param name="request">The request this response is for.</param>
        /// <param name="serialNumber">The serial number for the response token.</param>
        /// <param name="genTime">The generation time for the response token.</param>
        /// <param name="statusString">The status string to include in a granted response.</param>
        /// <param name="additionalExtensions">Extensions to add to the token, or null for none.</param>
        /// <returns>The <see cref="TimeStampResponse"/>.</returns>
        /// <exception cref="TspException">The token or response could not be created.</exception>
        public TimeStampResponse GenerateGrantedResponse(TimeStampRequest request, BigInteger serialNumber,
            DateTime? genTime, string statusString, X509Extensions additionalExtensions)
        {
            if (genTime == null)
                throw new TspValidationException("The time source is not available.",
                    PkiFailureInfo.TimeNotAvailable);

            request.Validate(acceptedAlgorithms, acceptedPolicies, acceptedExtensions);

            this.status = PkiStatus.Granted;
            this.statusStrings = new Asn1EncodableVector();

            if (statusString != null)
            {
                this.AddStatusString(statusString);
            }

            PkiStatusInfo pkiStatusInfo = GetPkiStatusInfo();

            ContentInfo tstTokenContentInfo;
            try
            {
                TimeStampToken token = tokenGenerator.Generate(request, serialNumber, genTime.Value,
                    additionalExtensions);

                tstTokenContentInfo = token.ToCmsSignedData().ContentInfo;
            }
            catch (TspException)
            {
                throw;
            }
            catch (IOException e)
            {
                throw new TspException("Timestamp token received cannot be converted to ContentInfo", e);
            }

            try
            {
                return new TimeStampResponse(new DLSequence(pkiStatusInfo.ToAsn1Object(), tstTokenContentInfo.ToAsn1Object()));
            }
            catch (IOException e)
            {
                throw new TspException("created badly formatted response!", e);
            }
        }

        internal class FailInfo
            : DerBitString
        {
            internal FailInfo(int failInfoValue)
                : base(failInfoValue)
            {
            }
        }

        /**
         * Generate a generic rejection response based on a TSPValidationException or
         * an Exception. Exceptions which are not an instance of TSPValidationException
         * will be treated as systemFailure. The return value of exception.getMessage() will
         * be used as the status string for the response.
         *
         * @param exception the exception thrown on validating the request.
         * @return a TimeStampResponse.
         * @throws TSPException if a failure response cannot be generated.
         */
        public TimeStampResponse GenerateRejectedResponse(Exception exception)
        {
            if (exception is TspValidationException tspValidationException)
                return GenerateFailResponse(PkiStatus.Rejection, tspValidationException.FailureCode, exception.Message);

            return GenerateFailResponse(PkiStatus.Rejection, PkiFailureInfo.SystemFailure, exception.Message);
        }

        /// <summary>Generate a TimeStampResponse with chosen status and FailInfoField.</summary>
        /// <param name="status">The PKIStatus to set.</param>
        /// <param name="failInfoField">The FailInfoField to set.</param>
        /// <param name="statusString">An optional string describing the failure.</param>
        /// <returns>A <see cref="TimeStampResponse"/> with a failInfoField and optional statusString.</returns>
        /// <exception cref="TspException">The response could not be created.</exception>
        public TimeStampResponse GenerateFailResponse(PkiStatus status, int failInfoField, string statusString)
        {
            this.status = status;
            this.statusStrings = new Asn1EncodableVector();

            this.SetFailInfoField(failInfoField);

            if (statusString != null)
            {
                this.AddStatusString(statusString);
            }

            PkiStatusInfo pkiStatusInfo = GetPkiStatusInfo();

            TimeStampResp resp = new TimeStampResp(pkiStatusInfo, null);

            try
            {
                return new TimeStampResponse(resp);
            }
            catch (IOException e)
            {
                throw new TspException("created badly formatted response!", e);
            }
        }
    }
}
