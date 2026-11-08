# =============================================================================
# Dockerfile - OrangeHRM 5.9, built natively for this Mac (arm64).
# -----------------------------------------------------------------------------
# WHY not the official image: orangehrm/orangehrm is published for amd64
# only. Under emulation in Colima its PHP workers crashed (Apache logged
# "Segmentation fault" and the sign-in page came back empty, 2026-11-07).
# This file repeats the official image's own build steps (its layer
# history) on the multi-arch PHP base, so it runs natively:
#  - the same PHP (8.3.31, Apache, prefork) and the same extensions
#    (gd, opcache, intl, pdo_mysql, zip, ldap);
#  - the same OrangeHRM release zip from SourceForge, checked against the
#    MD5 the official 5.9 image pins (OHRM_MD5), and against its SHA-256.
# Base pinned by digest (supply chain).
# =============================================================================
FROM php:8.3.31-apache@sha256:759e57453c1f4957dde87cbb33e25842eb91dd5ce7a06e93cdb4b93508bc182a

ENV OHRM_VERSION=5.9 \
    OHRM_MD5=380d85deba0f82174a7db346c9347b87 \
    OHRM_SHA256=f6e640f8b59e8d09f15edcd24ac3d42bb52dcc4839a7d83f964dd798bc793f79

RUN set -ex; \
  mv "$PHP_INI_DIR/php.ini-production" "$PHP_INI_DIR/php.ini"; \
  apt-get update; \
  apt-get install -y --no-install-recommends libfreetype6-dev libjpeg-dev libpng-dev libzip-dev libldap2-dev libicu-dev unzip; \
  cd /var/www && rm -rf html; \
  curl -fSL -o orangehrm.zip "https://sourceforge.net/projects/orangehrm/files/stable/${OHRM_VERSION}/orangehrm-${OHRM_VERSION}.zip"; \
  echo "${OHRM_MD5} orangehrm.zip" | md5sum -c -; \
  echo "${OHRM_SHA256} orangehrm.zip" | sha256sum -c -; \
  unzip -q orangehrm.zip "orangehrm-${OHRM_VERSION}/*"; \
  mv "orangehrm-${OHRM_VERSION}" html; rm -f orangehrm.zip; \
  chown www-data:www-data html; \
  chown -R www-data:www-data html/lib/confs html/src/cache html/src/log html/src/config; \
  chmod -R 775 html/lib/confs html/src/cache html/src/log html/src/config; \
  docker-php-ext-configure gd --with-freetype --with-jpeg; \
  docker-php-ext-configure ldap --with-libdir="lib/$(uname -m)-linux-gnu/"; \
  docker-php-ext-install -j "$(nproc)" gd opcache intl pdo_mysql zip ldap; \
  rm -rf /var/lib/apt/lists/*; \
  { echo 'opcache.memory_consumption=128'; echo 'opcache.interned_strings_buffer=8'; \
    echo 'opcache.max_accelerated_files=4000'; echo 'opcache.revalidate_freq=60'; \
    echo 'opcache.fast_shutdown=1'; echo 'opcache.enable_cli=1'; } > "$PHP_INI_DIR/conf.d/opcache-recommended.ini"; \
  echo 'ServerName localhost' > /etc/apache2/conf-enabled/servername.conf; \
  a2enmod rewrite

WORKDIR /var/www/html
