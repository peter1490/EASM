//! Subdomain-takeover fingerprints for dangling DNS records.
//!
//! A CNAME that still points at a decommissioned SaaS tenant is claimable by
//! whoever registers that tenant name next — they then serve content, and hold a
//! valid certificate, on the victim's own hostname. The signature set below is
//! the community-maintained one behind `subjack`, `nuclei`'s takeover templates
//! and the `can-i-take-over-xyz` catalogue.
//!
//! Two things decide whether a dangling record is claimable, and both are
//! checked before anything is reported:
//!
//! 1. the CNAME target's zone is one of the services below, and
//! 2. the service says the tenant is unclaimed — either the target does not
//!    resolve at all (NXDOMAIN), or it resolves and serves the provider's
//!    "no such account" page, whose exact wording is the `fingerprint` here.
//!
//! Reporting on (1) alone is what produces the false positives these scanners
//! are known for: a live Netlify site is also a CNAME to `netlify.app`.

/// One provider's takeover signature.
#[derive(Debug, Clone, Copy)]
pub struct TakeoverSignature {
    /// Provider name, as the report should read.
    pub service: &'static str,
    /// CNAME target suffixes that delegate to this provider.
    pub cname_suffixes: &'static [&'static str],
    /// Body text the provider serves for an unclaimed tenant. Empty means the
    /// provider has none, so only an NXDOMAIN target is conclusive.
    pub fingerprints: &'static [&'static str],
    /// Whether an NXDOMAIN on the target alone proves the name is claimable.
    /// False for providers that keep the DNS entry alive after release.
    pub nxdomain_is_takeover: bool,
    /// Documented as actually claimable today. Some entries are kept because the
    /// dangling record is still a defect worth reporting even where the provider
    /// has since blocked re-registration.
    pub claimable: bool,
}

macro_rules! sig {
    ($service:expr, $suffixes:expr, $fingerprints:expr, $nx:expr, $claimable:expr) => {
        TakeoverSignature {
            service: $service,
            cname_suffixes: &$suffixes,
            fingerprints: &$fingerprints,
            nxdomain_is_takeover: $nx,
            claimable: $claimable,
        }
    };
}

pub const TAKEOVER_SIGNATURES: &[TakeoverSignature] = &[
    sig!("AWS S3", ["s3.amazonaws.com", "s3-website", "amazonaws.com"],
         ["The specified bucket does not exist", "NoSuchBucket"], false, true),
    sig!("AWS Elastic Beanstalk", ["elasticbeanstalk.com"], [], true, true),
    sig!("AWS CloudFront", ["cloudfront.net"],
         ["Bad request", "ERROR: The request could not be satisfied"], false, false),
    sig!("Azure", ["azurewebsites.net", "cloudapp.net", "cloudapp.azure.com",
                   "trafficmanager.net", "blob.core.windows.net", "azureedge.net",
                   "azure-api.net", "azurehdinsight.net", "azurecontainer.io"],
         ["404 Web Site not found"], true, true),
    sig!("GitHub Pages", ["github.io", "github.map.fastly.net"],
         ["There isn't a GitHub Pages site here",
          "For root URLs (like http://example.com/) you must provide an index.html file"],
         false, true),
    sig!("GitLab Pages", ["gitlab.io"], ["The page you're looking for could not be found"], false, true),
    sig!("Heroku", ["herokuapp.com", "herokudns.com", "herokussl.com"],
         ["No such app", "herokucdn.com/error-pages/no-such-app.html"], false, true),
    sig!("Shopify", ["myshopify.com"],
         ["Sorry, this shop is currently unavailable",
          "Only one step left!"], false, true),
    sig!("Fastly", ["fastly.net", "fastlylb.net"],
         ["Fastly error: unknown domain"], false, false),
    sig!("Pantheon", ["pantheonsite.io"], ["404 error unknown site!"], false, true),
    sig!("Tumblr", ["domains.tumblr.com"],
         ["Whatever you were looking for doesn't currently exist at this address"], false, true),
    sig!("WordPress.com", ["wordpress.com"], ["Do you want to register"], false, true),
    sig!("Bitbucket", ["bitbucket.io"], ["Repository not found"], false, true),
    sig!("Ghost", ["ghost.io"], ["The thing you were looking for is no longer here"], false, true),
    sig!("Helpjuice", ["helpjuice.com"], ["We could not find what you're looking for"], false, true),
    sig!("HelpScout", ["helpscoutdocs.com"], ["No settings were found for this company"], false, true),
    sig!("Zendesk", ["zendesk.com"], ["Help Center Closed"], false, false),
    sig!("Desk.com", ["desk.com"], ["Sorry, We Couldn't Find That Page"], false, true),
    sig!("Surge.sh", ["surge.sh"], ["project not found"], false, true),
    sig!("Netlify", ["netlify.app", "netlify.com"], ["Not Found - Request ID"], false, true),
    sig!("Vercel", ["vercel.app", "vercel-dns.com", "now.sh"],
         ["The deployment could not be found on Vercel",
          "DEPLOYMENT_NOT_FOUND"], false, true),
    sig!("Cargo Collective", ["cargocollective.com"], ["404 Not Found"], false, true),
    sig!("Statuspage", ["statuspage.io"],
         ["You are being redirected", "This page is parked"], false, false),
    sig!("Uservoice", ["uservoice.com"], ["This UserVoice subdomain is currently available"], false, true),
    sig!("Campaign Monitor", ["createsend.com"],
         ["Trying to access your account?", "double-check the URL"], false, true),
    sig!("Acquia", ["acquia-sites.com"], ["The site you are looking for could not be found"], false, true),
    sig!("Readme.io", ["readme.io"], ["Project doesnt exist... yet!"], false, true),
    sig!("Intercom", ["custom.intercom.help"],
         ["This page is reserved for artistic dogs", "Uh oh. That page doesn't exist"], false, true),
    sig!("Webflow", ["proxy.webflow.com", "proxy-ssl.webflow.com", "webflow.io"],
         ["The page you are looking for doesn't exist or has been moved"], false, false),
    sig!("Kinsta", ["kinsta.cloud"], ["No Site For Domain"], false, true),
    sig!("LaunchRock", ["launchrock.com"], ["It looks like you may have taken a wrong turn"], false, true),
    sig!("Smartling", ["smartling.com"], ["Domain is not configured"], false, true),
    sig!("Strikingly", ["s.strikinglydns.com", "strikinglydns.com"],
         ["But if you're looking to build your own website"], false, true),
    sig!("Tilda", ["tilda.ws"], ["Please renew your subscription"], false, true),
    sig!("Wishpond", ["wishpond.com"], ["https://www.wishpond.com/404?utm_source=jekyll"], false, true),
    sig!("Aftership", ["aftership.com"], ["Oops.</h2><p class=\"text-muted\">The page you're looking for doesn't exist."], false, true),
    sig!("Agile CRM", ["agilecrm.com"], ["Sorry, this page is no longer available"], false, true),
    sig!("Airee", ["cdn.airee.ru"], ["Ошибка 402. Сервис Айри.рф не оплачен"], false, true),
    sig!("Anima", ["animaapp.io"], ["If this is your website and you've just created it"], false, true),
    sig!("Bigcartel", ["bigcartel.com"], ["<h1>Oops! We couldn&#8217;t find that page.</h1>"], false, true),
    sig!("Feedpress", ["redirect.feedpress.me"], ["The feed has not been found."], false, true),
    sig!("Frontify", ["frontify.com"], ["404 - Page Not Found"], false, true),
    sig!("Hatena Blog", ["hatenablog.com"], ["404 Blog is not found"], false, true),
    sig!("JetBrains", ["myjetbrains.com"], ["is not a registered InCloud YouTrack"], false, true),
    sig!("Mashery", ["mashery.com"], ["Unrecognized domain"], false, false),
    sig!("Ngrok", ["ngrok.io"], ["Tunnel *.ngrok.io not found"], false, true),
    sig!("Short.io", ["cname.short.io"], ["Link does not exist"], false, true),
    sig!("Simplebooklet", ["simplebooklet.com"], ["We can't find this <a href=\"https://simplebooklet.com"], false, true),
    sig!("Teamwork", ["teamwork.com"], ["Oops - We didn't find your site."], false, true),
    sig!("Thinkific", ["thinkific.com"], ["You may have mistyped the address or the page may have moved."], false, true),
    sig!("Unbounce", ["unbouncepages.com"], ["The requested URL was not found on this server"], false, false),
    sig!("Uptimerobot", ["stats.uptimerobot.com"], ["page not found"], false, true),
    sig!("Worksites", ["worksites.net"], ["Hello! Sorry, but the website you&rsquo;re looking for doesn&rsquo;t exist."], false, true),
];

/// Which provider, if any, a CNAME target belongs to.
pub fn match_service(cname_target: &str) -> Option<&'static TakeoverSignature> {
    let target = cname_target.trim_end_matches('.').to_ascii_lowercase();
    TAKEOVER_SIGNATURES.iter().find(|sig| {
        sig.cname_suffixes.iter().any(|suffix| {
            target == *suffix || target.ends_with(&format!(".{}", suffix)) || target.contains(suffix)
        })
    })
}

/// Does an HTTP response body carry this provider's "unclaimed tenant" page?
pub fn body_matches_fingerprint(signature: &TakeoverSignature, body: &str) -> bool {
    signature
        .fingerprints
        .iter()
        .any(|needle| body.contains(needle))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cname_targets_map_to_their_provider() {
        assert_eq!(match_service("myapp.herokuapp.com").unwrap().service, "Heroku");
        assert_eq!(match_service("acme.github.io.").unwrap().service, "GitHub Pages");
        assert_eq!(
            match_service("shop.s3.amazonaws.com").unwrap().service,
            "AWS S3"
        );
        assert_eq!(match_service("MyApp.AzureWebsites.NET").unwrap().service, "Azure");
    }

    #[test]
    fn unrelated_targets_match_nothing() {
        assert!(match_service("www.example.com").is_none());
        assert!(match_service("mail.google.com").is_none());
    }

    #[test]
    fn fingerprints_gate_the_verdict() {
        let heroku = match_service("gone.herokuapp.com").unwrap();
        assert!(body_matches_fingerprint(heroku, "<h1>No such app</h1>"));
        // A live app must not match.
        assert!(!body_matches_fingerprint(heroku, "<h1>Welcome to my app</h1>"));
    }

    #[test]
    fn every_signature_can_reach_a_verdict() {
        // A signature with neither a body fingerprint nor NXDOMAIN semantics could
        // never be confirmed, so it would only ever produce noise.
        for sig in TAKEOVER_SIGNATURES {
            assert!(
                !sig.fingerprints.is_empty() || sig.nxdomain_is_takeover,
                "{} has no way to confirm a takeover",
                sig.service
            );
            assert!(!sig.cname_suffixes.is_empty(), "{} matches nothing", sig.service);
        }
    }
}
