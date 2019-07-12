//! A very simple crate to use `letsencrypt.org` to serve an encrypted
//! website using warp.

use warp::{path, Filter};

/// Run forever on the current thread, serving using TLS to serve on the given domain.
///
/// This function accepts a single [`warp::Filter`](warp::Filter)
/// which is the site to host.  `lets_encrypt` requires the capability
/// to serve port 80 and port 443.  It obtains TLS credentials from
/// `letsencrypt.org` and then serves up the site on port 443.  It
/// also serves redirects on port 80.  Errors are reported on stderr.
pub fn lets_encrypt<F>(service: F, domain: &str)
where
    F: warp::Filter<Error = warp::Rejection> + Send + Sync + 'static,
    F::Extract: warp::reply::Reply,
{
    use acme_client::Directory;

    let directory = Directory::lets_encrypt().expect("Trouble connecting to let's encrypt");
    let account = directory
        .account_registration()
        .register()
        .expect("Trouble registring for an account.");

    // Create a identifier authorization for example.com
    let authorization = account
        .authorization(domain)
        .expect("Trouble creating authorization for the account for the domain.");

    // Validate ownership of example.com with http challenge
    let http_challenge = authorization
        .get_http_challenge()
        // .ok_or("HTTP challenge not found")
        .expect("Problem with the challenge");

    {
        let authorization = http_challenge.key_authorization().to_string();
        let token_name = Box::leak(http_challenge.token().to_string().into_boxed_str());
        let domain = domain.to_string();
        std::thread::spawn(move || {
            use std::str::FromStr;
            let token = warp::path!(".well-known" / "acme-challenge")
                .and(warp::path(token_name))
                .map(move || authorization.clone());
            let redirect = warp::path::tail()
                .map(move |path: warp::path::Tail| {
                    println!("redirecting to https://{}/{}", domain, path.as_str());
                    warp::redirect::redirect(warp::http::Uri::from_str(&format!("https://{}/{}",
                                                                                &domain,
                                                                                path.as_str()))
                                             .expect("problem with uri?"))
                });
            warp::serve(token.or(redirect))
                .run(([0, 0, 0, 0], 80));
        });
    }

    // http_challenge.save_key_authorization("/var/www")?;
    std::thread::sleep(std::time::Duration::from_millis(500));
    http_challenge.validate().expect("Trouble validating.");

    let cert = account
        .certificate_signer(&[domain])
        .sign_certificate()
        .expect("Trouble signing?");
    cert.save_signed_certificate("certificate.pem")
        .expect("Touble saving pem");
    cert.save_private_key("certificate.key")
        .expect("Trouble saving key");

    warp::serve(service)
        .tls("certificate.pem", "certificate.key")
        .run(([0, 0, 0, 0], 443));
}
