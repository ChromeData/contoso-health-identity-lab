# Contoso Claims Viewer: the sample relying party for the AD FS -> Entra
# migration (lab/adfs/README.md). A real SAML 2.0 service provider
# (SimpleSAMLphp) that shows the claims the identity provider sent.
# Runs only on the operator's Mac, on https://localhost:8443.
FROM php:8.3-apache

# SimpleSAMLphp 2.4.10 "full" release. SHA-256 from the publisher's release
# notes (github.com/simplesamlphp/simplesamlphp/releases/tag/v2.4.10),
# re-checked locally 2026-11-07. A changed tarball fails the build.
ARG SSP_VERSION=2.4.10
ARG SSP_SHA256=6a0edb94195fb9bee395234a29d801c023c12a52dd610d7afe15c55020861ee5
RUN set -eux; \
    curl -fsSL -o /tmp/ssp.tgz "https://github.com/simplesamlphp/simplesamlphp/releases/download/v${SSP_VERSION}/simplesamlphp-${SSP_VERSION}-full.tar.gz"; \
    echo "${SSP_SHA256}  /tmp/ssp.tgz" | sha256sum -c -; \
    mkdir -p /var/simplesamlphp; \
    tar xzf /tmp/ssp.tgz -C /var/simplesamlphp --strip-components=1; \
    rm /tmp/ssp.tgz; \
    mkdir -p /var/simplesamlphp/log /var/simplesamlphp/tmp /var/simplesamlphp/cert; \
    # Per-image secrets (session salt, unused admin password). Local lab
    # container only; never published.
    openssl rand -hex 32 > /var/simplesamlphp/config/.salt; \
    openssl rand -hex 24 > /var/simplesamlphp/config/.adminpw; \
    # TLS for https://localhost:8443. AD FS accepts only https assertion
    # consumer URLs; Entra gets the same URL so the app does not change.
    openssl req -x509 -newkey rsa:2048 -nodes -days 90 -subj "/CN=localhost" \
      -addext "subjectAltName=DNS:localhost" \
      -keyout /etc/ssl/private/cv.key -out /etc/ssl/certs/cv.crt; \
    chown -R www-data:www-data /var/simplesamlphp/log /var/simplesamlphp/tmp; \
    a2enmod ssl rewrite headers

COPY config/config.php config/authsources.php /var/simplesamlphp/config/
COPY config/apache.conf /etc/apache2/sites-available/000-default.conf
COPY public/ /var/www/html/

EXPOSE 8443
