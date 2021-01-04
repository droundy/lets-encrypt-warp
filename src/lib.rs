//! A very simple crate to use `letsencrypt.org` to serve an encrypted
//! website using warp.

use futures::channel::oneshot;
use futures::try_join;
use warp::Filter;

static PORT_HTTP: u16 = 80;
static PORT_HTTPS: u16 = 443;

/// Run forever on the current thread, serving using TLS to serve on the given domain.
///
/// This function accepts a single [`warp::Filter`](warp::Filter)
/// which is the site to host.  `lets_encrypt` requires the capability
/// to serve port 80 and port 443.  It obtains TLS credentials from
/// `letsencrypt.org` and then serves up the site on port 443.  It
/// also serves redirects on port 80.  Errors are reported on stderr.
pub async fn lets_encrypt<F>(service: F, email: &str, domain: &str) -> Result<(), acme_lib::Error>
where
    F: warp::Filter<Error = warp::Rejection> + Send + Sync + 'static,
    F::Extract: warp::reply::Reply,
    F: Clone,
{
    let domain = domain.to_string();

    let pem_name = format!("{}.pem", domain);
    let key_name = format!("{}.key", domain);

    // Use DirectoryUrl::LetsEncrypStaging for dev/testing.
    let url = acme_lib::DirectoryUrl::LetsEncrypt;

    // Save/load keys and certificates to current dir.
    let persist = acme_lib::persist::FilePersist::new(".");

    // Create a directory entrypoint.
    let dir = acme_lib::Directory::from_url(persist, url)?;

    // Reads the private account key from persistence, or
    // creates a new one before accessing the API to establish
    // that it's there.
    let acc = dir.account(email)?;

    // Order a new TLS certificate for a domain.
    let ord_new = acc.new_order(&domain, &[])?;
    let ord_new = std::sync::Arc::new(std::sync::RwLock::new(ord_new));

    loop {
        const TMIN: std::time::Duration = std::time::Duration::from_secs(60 * 60 * 24 * 30);
        println!(
            "The time to expiration of {:?} is {:?}",
            pem_name,
            time_to_expiration(&pem_name)
        );
        if time_to_expiration(&pem_name)
            .filter(|&t| t > TMIN)
            .is_none()
        {
            // If the ownership of the domain(s) have already been authorized
            // in a previous order, you might be able to skip validation. The
            // ACME API provider decides.
            let ord_csr = loop {
                // are we done?
                if let Some(ord_csr) = ord_new.clone().read().unwrap().confirm_validations() {
                    break ord_csr;
                }

                // Get the possible authorizations (for a single domain
                // this will only be one element).
                let authorizations = {
                    let ord_new = ord_new.clone();
                    tokio::task::spawn_blocking(move || ord_new.read().unwrap().authorizations())
                        .await
                        .expect("authorizations could not spawned")?
                };

                // For HTTP, the challenge is a text file that needs to
                // be placed in your web server at:
                //
                //   .well-known/acme-challenge/<token>
                //
                // The important thing is that it's accessible over the
                // web for the domain(s) you are trying to get a
                // certificate for:
                //
                // http://mydomain.io/.well-known/acme-challenge/<token>
                //
                for authorization in authorizations {
                    let challenge = authorization.http_challenge();

                    let token: String = challenge.http_token().into();
                    let proof: String = challenge.http_proof();
                    let service = warp::path!(".well-known" / "acme-challenge" / ..)
                        .and(warp::path(token))
                        .map(move || proof.clone());

                    // Start up a short-lived server on port 80 to respond to
                    // the ACME provider's probes.
                    let (tx80, rx80) = oneshot::channel();
                    let s_validate = tokio::spawn(async move {
                        warp::serve(service)
                            .bind_with_graceful_shutdown(([0, 0, 0, 0], PORT_HTTP), async {
                                rx80.await.ok();
                            })
                            .1
                            .await
                    });

                    // After the file is accessible from the web, the calls this
                    // to tell the ACME API to start checking the existence of
                    // the proof.
                    //
                    // The order at ACME will change status to either confirm
                    // ownership of the domain, or fail due to the not finding
                    // the proof. To see the change, we poll the API with 5000
                    // milliseconds wait between.
                    tokio::task::spawn_blocking(|| challenge.validate(5000))
                        .await
                        .expect("spawning validation failed")?;
                    tx80.send(()).unwrap(); // Now stop the server on port 80
                    s_validate
                        .await
                        .expect("validation server did not shut down gracefully");
                }

                // Update the state against the ACME API.
                {
                    let ord_new = ord_new.clone();
                    tokio::task::spawn_blocking(move || ord_new.write().unwrap().refresh())
                        .await
                        .expect("spawning refresh failed")?;
                }
            };

            // Ownership is proven. Create a private/public key pair for the
            // certificate. These are provided for convenience, you can
            // provide your own keypair instead if you want.
            let (pkey_pri, pkey_pub) = acme_lib::create_p384_key();

            // Submit the CSR. This causes the ACME provider to enter a state
            // of "processing" that must be polled until the certificate is
            // either issued or rejected. Again we poll for the status change.
            let ord_cert = ord_csr.finalize_pkey(pkey_pri, pkey_pub, 5000)?;

            // Now download the certificate. Also stores the cert in the
            // persistence.
            let cert = ord_cert.download_and_save_cert()?;
            std::fs::write(&pem_name, cert.certificate())?;
            std::fs::write(&key_name, cert.private_key())?;
        }

        // Now we have working keys, let us use them!
        let (tx80, rx80) = oneshot::channel();
        let s80 = {
            // First start the redirecting from port 80 to port 443.
            let domain = domain.to_string();
            use std::str::FromStr;
            let redirect = warp::path::tail().map(move |path: warp::path::Tail| {
                println!("redirecting to https://{}/{}", domain, path.as_str());
                warp::redirect::redirect(
                    warp::http::Uri::from_str(&format!("https://{}/{}", &domain, path.as_str()))
                        .expect("problem with uri?"),
                )
            });
            tokio::spawn(async move {
                warp::serve(redirect)
                    .bind_with_graceful_shutdown(([0, 0, 0, 0], PORT_HTTP), async {
                        rx80.await.ok();
                    })
                    .1
                    .await
            })
        };
        let (tx, rx) = oneshot::channel();
        let s443 = {
            // Now start our actual site.
            let service = service.clone();
            let key_name = key_name.clone();
            let pem_name = pem_name.clone();
            tokio::spawn(async move {
                warp::serve(service)
                    .tls()
                    .cert_path(&pem_name)
                    .key_path(&key_name)
                    .bind_with_graceful_shutdown(([0, 0, 0, 0], PORT_HTTPS), async {
                        rx.await.ok();
                    })
                    .1
                    .await
            })
        };

        // Now wait until it is time to grab a new certificate.
        if let Some(time_to_renew) = time_to_expiration(&pem_name).and_then(|x| x.checked_sub(TMIN))
        {
            println!("Sleeping for {:?} before renewing", time_to_renew);
            tokio::time::delay_for(time_to_renew).await;
            println!("Now it is time to renew!");
            tx.send(()).unwrap();
            tx80.send(()).unwrap();
            try_join!(s80, s443).expect("server did not shutdown gracefully");
        } else if let Some(time_to_renew) = time_to_expiration(&pem_name) {
            // Presumably we already failed to renew, so let's
            // just keep using our current certificate as long
            // as we can!
            println!("Sleeping for {:?} before renewing", time_to_renew);
            tokio::time::delay_for(time_to_renew).await;
            println!("Now it is time to renew!");
            tx.send(()).unwrap();
            tx80.send(()).unwrap();
            try_join!(s80, s443).expect("server did not shutdown gracefully");
        } else {
            println!("Uh oh... looks like we already are at our limit?");
            println!("Waiting an hour before trying again...");
            tokio::time::delay_for(std::time::Duration::from_secs(60 * 60)).await;
        }
    }
}

fn time_to_expiration<P: AsRef<std::path::Path>>(p: P) -> Option<std::time::Duration> {
    let file = std::fs::File::open(p).ok()?;
    x509_parser::pem::Pem::read(std::io::BufReader::new(file))
        .ok()?
        .0
        .parse_x509()
        .ok()?
        .tbs_certificate
        .validity
        .time_to_expiration()
}
