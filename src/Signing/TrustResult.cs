using System.Linq;
using System.Collections.Generic;

namespace PackageSigning
{
    public class TrustResult
    {
        public bool Trusted { get; }
        public IEnumerable<TrustedPublisher> TrustedPublishers { get; }

        public TrustResult(IEnumerable<TrustedPublisher> publishers)
        {
            TrustedPublishers = publishers;
            Trusted = publishers.Any();
        }
    }
}