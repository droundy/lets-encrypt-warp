use warp::{path, Filter};

/// Run forever on the current thread, serving using TLS to serve on the given domain.
///
/// Errors are reported on stderr.
#[macro_export]
macro_rules! lets_encrypt {
    ($service:expr, $domain:expr) => {{
        use acme_client::Directory;
        use warp::{path, Filter};

        let directory = Directory::lets_encrypt().expect("Trouble connecting to let's encrypt");
        let account = directory
            .account_registration()
            .register()
            .expect("Trouble registring for an account.");

        // Create a identifier authorization for example.com
        let authorization = account
            .authorization($domain)
            .expect("Trouble creating authorization for the account for the domain.");

        // Validate ownership of example.com with http challenge
        let http_challenge = authorization
            .get_http_challenge()
            // .ok_or("HTTP challenge not found")
            .expect("Problem with the challenge");

        let authorization = http_challenge.key_authorization().to_string();
        let token_name = Box::leak(http_challenge.token().to_string().into_boxed_str());
        std::thread::spawn(move || {
            use std::str::FromStr;
            let token = warp::path!(".well-known" / "acme-challenge")
                .and(warp::path(token_name))
                .map(move || authorization.clone());
            let redirect = warp::path::tail()
                .map(|path: warp::path::Tail| {
                    println!("redirecting to https://{}", path.as_str());
                    warp::redirect::redirect(warp::http::Uri::from_str(&format!("https://{}", path.as_str()))
                                             .expect("problem with uri?"))
                });
            warp::serve(
                token.or(redirect)
            )
            .run(([0, 0, 0, 0], 80));
        });

        // http_challenge.save_key_authorization("/var/www")?;
        std::thread::sleep(std::time::Duration::from_millis(500));
        http_challenge.validate().expect("Trouble validating.");

        let cert = account
            .certificate_signer(&[$domain])
            .sign_certificate()
            .expect("Trouble signing?");
        cert.save_signed_certificate("certificate.pem")
            .expect("Touble saving pem");
        cert.save_private_key("certificate.key")
            .expect("Trouble saving key");

        warp::serve($service)
            .tls("certificate.pem", "certificate.key")
            .run(([0, 0, 0, 0], 443));
    }};
}

#[cfg(test)]
mod tests {
    fn should_compile_but_not_complete() {
        use warp::Filter;
        let x = warp::path("foo").map(|| "bar");
        lets_encrypt!(x, "example.com");
    }
    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }
}

/// Run forever on the current thread, serving using TLS to serve on the given domain.
///
/// Errors are reported on stderr.
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

    let authorization = http_challenge.key_authorization().to_string();
    let token_name = Box::leak(http_challenge.token().to_string().into_boxed_str());
    std::thread::spawn(move || {
        use std::str::FromStr;
        let token = warp::path!(".well-known" / "acme-challenge")
            .and(warp::path(token_name))
            .map(move || authorization.clone());
        let redirect = warp::path::tail()
            .map(|path: warp::path::Tail| {
                println!("redirecting to https://{}", path.as_str());
                warp::redirect::redirect(warp::http::Uri::from_str(&format!("https://{}", path.as_str()))
                                         .expect("problem with uri?"))
            });
        warp::serve(token.or(redirect))
            .run(([0, 0, 0, 0], 80));
    });

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
