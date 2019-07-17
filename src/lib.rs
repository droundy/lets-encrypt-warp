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
    let pem_name = format!("{}.pem", domain);
    let key_name = format!("{}.key", domain);

    const TMIN: std::time::Duration = std::time::Duration::from_secs(60*60*24*30);
    if time_to_expiration(&pem_name).filter(|&t| t > TMIN).is_none() {
        let directory = Directory::lets_encrypt().expect("Trouble connecting to let's encrypt");
        if let Ok(account) = directory.account_registration().register() {
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
                .certificate_signer(&[&domain])
                .sign_certificate()
                .expect("Trouble signing?");
            cert.save_signed_certificate(&pem_name).expect("Touble saving pem");
            cert.save_private_key(&key_name).expect("Trouble saving key");
        } else if time_to_expiration(&pem_name).is_some() {
            println!("We probably hit our rate limit, so let's hope we've got a valid certificate already.");
            // We just need to start the redirection portion.
            let domain = domain.to_string();
            std::thread::spawn(move || {
                use std::str::FromStr;
                let redirect = warp::path::tail()
                    .map(move |path: warp::path::Tail| {
                        println!("redirecting to https://{}/{}", domain, path.as_str());
                        warp::redirect::redirect(warp::http::Uri::from_str(&format!("https://{}/{}",
                                                                                    &domain,
                                                                                    path.as_str()))
                                                 .expect("problem with uri?"))
                    });
                warp::serve(redirect).run(([0, 0, 0, 0], 80));
            });
        } else {
            println!("We seem to have failed at every turn to get lets-encrypt working!");
            std::process::exit(1);
        }
    }

    warp::serve(service)
        .tls(pem_name, key_name)
        .run(([0, 0, 0, 0], 443));
}

fn time_to_expiration<P: AsRef<std::path::Path>>(p: P) -> Option<std::time::Duration> {
    let file = std::fs::File::open(p).ok()?;
    x509_parser::pem::Pem::read(std::io::BufReader::new(file)).ok()?.0
        .parse_x509().ok()?
        .tbs_certificate.validity.time_to_expiration()
}
